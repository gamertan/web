// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"database/sql"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/organizations"
)

func TestOpenCanRequireExplicitMigration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "explicit.db")
	store, err := OpenWithOptions(path, OpenOptions{Migrate: false})
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.RequireCurrentSchema(t.Context()); err == nil {
		t.Fatal("unmigrated database reported current")
	}
	if err = store.Migrate(t.Context()); err != nil {
		t.Fatal(err)
	}
	if err = store.RequireCurrentSchema(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestServiceRoundTripWithApplicationPolicy(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1000, 0).UTC()
	service, err := auth.New(store, auth.Options{Random: strings.NewReader(strings.Repeat("r", 512)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SeedPolicy(t.Context(), auth.PolicySeed{Roles: map[string]string{"reader": "Read the application"}, Permissions: map[string]string{"catalog.read": "Read catalog"}, RolePermissions: map[string][]string{"reader": {"catalog.read"}}}); err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(t.Context(), auth.CreateUser{Username: "reader.one", Email: "reader@example.test", DisplayName: "Reader", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.GrantRole(t.Context(), user.ID, "reader", now); err != nil {
		t.Fatal(err)
	}
	token, principal, err := service.Authenticate(t.Context(), "READER.ONE", "correct horse battery staple", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || !principal.Has("catalog.read") || len(principal.Roles) != 1 {
		t.Fatalf("principal=%+v", principal)
	}
	loaded, err := service.Session(t.Context(), token)
	if err != nil || !loaded.Has("catalog.read") {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err = service.RevokeSession(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Session(t.Context(), token); err == nil {
		t.Fatal("revoked session accepted")
	}
}

func TestRequiredPasswordChangeRotatesCredentialAndRevokesSessions(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(3000, 0).UTC()
	service, err := auth.New(store, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(t.Context(), auth.CreateUser{Username: "bootstrap", Email: "bootstrap@example.test", DisplayName: "Bootstrap Operator", Password: "temporary bootstrap credential", RequirePasswordChange: true})
	if err != nil || !user.PasswordChangeRequired {
		t.Fatalf("user=%+v err=%v", user, err)
	}
	token, principal, err := service.Authenticate(t.Context(), user.Username, "temporary bootstrap credential", time.Hour)
	if err != nil || !principal.User.PasswordChangeRequired {
		t.Fatalf("principal=%+v err=%v", principal, err)
	}
	if err = service.ChangePassword(t.Context(), user.ID, "wrong current credential", "new permanent credential"); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("wrong current credential err=%v", err)
	}
	if _, err = service.Session(t.Context(), token); err != nil {
		t.Fatalf("failed rotation revoked session: %v", err)
	}
	if err = service.ChangePassword(t.Context(), user.ID, "temporary bootstrap credential", "temporary bootstrap credential"); !errors.Is(err, auth.ErrPasswordUnchanged) {
		t.Fatalf("reused credential err=%v", err)
	}
	if err = service.ChangePassword(t.Context(), user.ID, "temporary bootstrap credential", "new permanent credential"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Session(t.Context(), token); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("old session survived rotation: %v", err)
	}
	if _, _, err = service.Authenticate(t.Context(), user.Username, "temporary bootstrap credential", time.Hour); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("temporary credential survived rotation: %v", err)
	}
	_, principal, err = service.Authenticate(t.Context(), user.Username, "new permanent credential", time.Hour)
	if err != nil || principal.User.PasswordChangeRequired {
		t.Fatalf("rotated principal=%+v err=%v", principal, err)
	}
}

func TestAdministrativePasswordResetIsAtomicAndAudited(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(4000, 0).UTC()
	service, err := auth.New(store, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(t.Context(), auth.CreateUser{Username: "recover.me", Email: "recover@example.test", DisplayName: "Recovery Test", Password: "original permanent credential"})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := service.Authenticate(t.Context(), user.Username, "original permanent credential", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	reset, err := service.ResetPassword(t.Context(), auth.AdministrativePasswordReset{Identifier: user.Email, TemporaryPassword: "one-time recovery credential"})
	if err != nil || !reset.PasswordChangeRequired {
		t.Fatalf("reset=%+v err=%v", reset, err)
	}
	if _, err = service.Session(t.Context(), token); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("session survived reset: %v", err)
	}
	if _, _, err = service.Authenticate(t.Context(), user.Username, "original permanent credential", time.Hour); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old credential survived reset: %v", err)
	}
	_, principal, err := service.Authenticate(t.Context(), user.Username, "one-time recovery credential", time.Hour)
	if err != nil || !principal.User.PasswordChangeRequired {
		t.Fatalf("recovery principal=%+v err=%v", principal, err)
	}
	var action, summary string
	var events int
	if err = store.db.QueryRow(`SELECT COUNT(*),action,summary FROM gwf_audit_events WHERE resource_id=?`, user.ID).Scan(&events, &action, &summary); err != nil {
		t.Fatal(err)
	}
	if events != 1 || action != "auth.password.reset" || strings.Contains(summary, "one-time recovery credential") || !strings.Contains(summary, "revoked all sessions") {
		t.Fatalf("events=%d action=%q summary=%q", events, action, summary)
	}
	if _, err = service.ResetPassword(t.Context(), auth.AdministrativePasswordReset{Identifier: user.Username, TemporaryPassword: "one-time recovery credential"}); !errors.Is(err, auth.ErrPasswordUnchanged) {
		t.Fatalf("same credential err=%v", err)
	}
}

func TestAdministrativePasswordResetRollsBackWhenAuditCannotCommit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(5000, 0).UTC()
	service, err := auth.New(store, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(t.Context(), auth.CreateUser{Username: "rollback.me", Email: "rollback@example.test", DisplayName: "Rollback Test", Password: "original permanent credential"})
	if err != nil {
		t.Fatal(err)
	}
	token, _, err := service.Authenticate(t.Context(), user.Username, "original permanent credential", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	user, currentHash, err := store.CredentialByUserID(t.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	newHash, err := auth.HashPassword("one-time recovery credential")
	if err != nil {
		t.Fatal(err)
	}
	audit := auth.AuditEvent{ID: "duplicate-audit-id", Action: "auth.password.reset", ResourceType: "user", ResourceID: user.ID, Summary: "A local administrator issued a one-time credential and revoked all sessions.", CreatedAt: now}
	if err = store.AppendAudit(t.Context(), audit); err != nil {
		t.Fatal(err)
	}
	if err = store.ResetPasswordAndRevokeSessions(t.Context(), user.ID, currentHash, newHash, now, audit); err == nil {
		t.Fatal("duplicate audit unexpectedly committed reset")
	}
	if _, err = service.Session(t.Context(), token); err != nil {
		t.Fatalf("rollback revoked session: %v", err)
	}
	_, principal, err := service.Authenticate(t.Context(), user.Username, "original permanent credential", time.Hour)
	if err != nil || principal.User.PasswordChangeRequired {
		t.Fatalf("original credential not restored: principal=%+v err=%v", principal, err)
	}
	if _, _, err = service.Authenticate(t.Context(), user.Username, "one-time recovery credential", time.Hour); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("uncommitted recovery credential accepted: %v", err)
	}
}

func TestMigrationAddsPasswordRequirementWithoutChangingExistingUsers(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.db")
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	_, err = database.Exec(`CREATE TABLE gwf_users (id TEXT PRIMARY KEY, username TEXT NOT NULL, username_normalized TEXT NOT NULL UNIQUE, email TEXT NOT NULL, email_normalized TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, status TEXT NOT NULL, created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login_at INTEGER)`)
	if err == nil {
		_, err = database.Exec(`INSERT INTO gwf_users(id,username,username_normalized,email,email_normalized,display_name,status,created_at,updated_at) VALUES('existing-user','existing','existing','existing@example.test','existing@example.test','Existing','active',1,1)`)
	}
	if closeErr := database.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		t.Fatal(err)
	}
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var required, migrations int
	if err = store.db.QueryRow(`SELECT password_change_required FROM gwf_users WHERE id='existing-user'`).Scan(&required); err != nil || required != 0 {
		t.Fatalf("required=%d err=%v", required, err)
	}
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM gamertan_web_migrations WHERE version=3`).Scan(&migrations); err != nil || migrations != 1 {
		t.Fatalf("migrations=%d err=%v", migrations, err)
	}
}

func TestSchemaIsNamespacedAndSeedsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM gwf_roles`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("roles=%d", count)
	}
	var legacy int
	err = store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`).Scan(&legacy)
	if err != nil {
		t.Fatal(err)
	}
	if legacy != 0 {
		t.Fatal("created unnamespaced users table")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestAdapterRejectsUnboundedPolicyAndInvalidAudit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.SeedPolicy(t.Context(), auth.PolicySeed{Roles: map[string]string{"BAD ROLE": "invalid"}}); err == nil {
		t.Fatal("invalid role accepted")
	}
	if err = store.AppendAudit(t.Context(), auth.AuditEvent{ID: "short"}); err == nil {
		t.Fatal("invalid audit event accepted")
	}
}

func TestOpenRejectsSymlinkDatabase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privilege-dependent on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "accounts.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink database accepted")
	}
}

func TestOrganizationTeamResourceAndScopedAccessRoundTrip(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(2000, 0).UTC()
	authService, err := auth.New(store, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "owner.one", Email: "owner@example.test", DisplayName: "Owner", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "member.one", Email: "member@example.test", DisplayName: "Member", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	organizationService, err := organizations.New(store, organizations.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	organization, err := organizationService.CreateOrganization(t.Context(), organizations.CreateOrganization{Slug: "observatory-test", Name: "Observatory Test", OwnerUserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	raw, _, err := organizationService.Invite(t.Context(), organization.ID, member.Email, owner.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if err = organizationService.AcceptInvitation(t.Context(), raw, member.ID); err != nil {
		t.Fatal(err)
	}
	team, err := organizationService.CreateTeam(t.Context(), organizations.CreateTeam{OrganizationID: organization.ID, Slug: "operators", Name: "Operators", ActorUserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	if err = organizationService.AddTeamMember(t.Context(), team.ID, member.ID, owner.ID); err != nil {
		t.Fatal(err)
	}
	project, err := organizationService.CreateProject(t.Context(), organizations.CreateProject{OrganizationID: organization.ID, Slug: "eql", Name: "EQL"})
	if err != nil {
		t.Fatal(err)
	}
	environment, err := organizationService.CreateEnvironment(t.Context(), organizations.CreateEnvironment{OrganizationID: organization.ID, ProjectID: project.ID, Slug: "production", Name: "Production"})
	if err != nil {
		t.Fatal(err)
	}
	application, err := organizationService.CreateApplicationService(t.Context(), organizations.CreateApplicationService{OrganizationID: organization.ID, ProjectID: project.ID, EnvironmentID: environment.ID, Slug: "web", Name: "Web"})
	if err != nil {
		t.Fatal(err)
	}
	policy := access.Policy{Roles: map[string]string{"viewer": "Read telemetry"}, Permissions: map[string]string{"telemetry.read": "Read telemetry", "telemetry.sensitive.read": "Read sensitive telemetry"}, Grants: map[string][]string{"viewer": {"telemetry.read"}}}
	accessService, err := access.New(store, policy, access.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err = accessService.Seed(t.Context()); err != nil {
		t.Fatal(err)
	}
	scope := access.Scope{OrganizationID: organization.ID, ProjectID: project.ID, EnvironmentID: environment.ID, ServiceID: application.ID}
	if _, err = accessService.Grant(t.Context(), access.Grant{SubjectKind: access.Team, SubjectID: team.ID, Role: "viewer", Scope: scope, GrantedBy: owner.ID}); err != nil {
		t.Fatal(err)
	}
	decision, err := accessService.Authorize(t.Context(), member.ID, scope, "telemetry.read")
	if err != nil || !decision.Allowed || decision.Source != "role" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	decision, err = accessService.Authorize(t.Context(), member.ID, scope, "telemetry.sensitive.read")
	if err != nil || decision.Allowed {
		t.Fatalf("sensitive decision=%+v err=%v", decision, err)
	}
	if _, err = accessService.ActivateBreakGlass(t.Context(), organization.ID, member.ID, "telemetry.sensitive.read", "Investigate the active production incident", "request-12345678", 15*time.Minute); err != nil {
		t.Fatal(err)
	}
	decision, err = accessService.Authorize(t.Context(), member.ID, scope, "telemetry.sensitive.read")
	if err != nil || !decision.Allowed || decision.Source != "break_glass" {
		t.Fatalf("break-glass decision=%+v err=%v", decision, err)
	}
	var audits int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM gwf_access_audit_events WHERE organization_id=?`, organization.ID).Scan(&audits); err != nil || audits != 6 {
		t.Fatalf("audits=%d err=%v", audits, err)
	}
	auditEvents, err := accessService.Audit(t.Context(), organization.ID, 10)
	if err != nil || len(auditEvents) != 6 {
		t.Fatalf("audit events=%+v err=%v", auditEvents, err)
	}
	foundBreakGlass := false
	for _, event := range auditEvents {
		foundBreakGlass = foundBreakGlass || event.Action == "break_glass.activate"
	}
	if !foundBreakGlass {
		t.Fatalf("break-glass audit missing: %+v", auditEvents)
	}
}

func TestInvitationAccessLifecycleAndLastOwnerProtection(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	authService, err := auth.New(store, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	owner, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "owner.lifecycle", Email: "owner-lifecycle@example.test", DisplayName: "Owner", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	member, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "member.lifecycle", Email: "member-lifecycle@example.test", DisplayName: "Member", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	organizationService, err := organizations.New(store, organizations.Options{Now: func() time.Time { return now }, OwnerRole: "organization.owner"})
	if err != nil {
		t.Fatal(err)
	}
	organization, err := organizationService.CreateOrganization(t.Context(), organizations.CreateOrganization{Slug: "lifecycle-test", Name: "Lifecycle Test", OwnerUserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	policy := access.Policy{Roles: map[string]string{"organization.owner": "Owner"}, Permissions: map[string]string{"telemetry.read": "Read"}, Grants: map[string][]string{"organization.owner": {"telemetry.read"}}}
	accessService, err := access.New(store, policy, access.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err = accessService.Seed(t.Context()); err != nil {
		t.Fatal(err)
	}
	if _, err = accessService.Grant(t.Context(), access.Grant{SubjectKind: access.User, SubjectID: owner.ID, Role: "organization.owner", Scope: access.Scope{OrganizationID: organization.ID}, GrantedBy: owner.ID}); err != nil {
		t.Fatal(err)
	}
	if err = organizationService.SetMembershipStatus(t.Context(), organization.ID, owner.ID, "suspended", owner.ID, "request-last-owner"); !errors.Is(err, organizations.ErrLastOwner) {
		t.Fatalf("last-owner suspension err=%v", err)
	}
	team, err := organizationService.CreateTeam(t.Context(), organizations.CreateTeam{OrganizationID: organization.ID, Slug: "operators", Name: "Operators", ActorUserID: owner.ID})
	if err != nil {
		t.Fatal(err)
	}
	raw, invitation, err := organizationService.InviteWithAccess(t.Context(), organizations.InviteWithAccess{OrganizationID: organization.ID, Email: member.Email, InvitedByUserID: owner.ID, DirectRole: "organization.owner", TeamIDs: []string{team.ID}, Lifetime: 7 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	if invitation.DirectRole != "organization.owner" || len(invitation.TeamIDs) != 1 {
		t.Fatalf("invitation=%+v", invitation)
	}
	if err = organizationService.AcceptInvitation(t.Context(), raw, member.ID); err != nil {
		t.Fatal(err)
	}
	decision, err := accessService.Authorize(t.Context(), member.ID, access.Scope{OrganizationID: organization.ID}, "telemetry.read")
	if err != nil || !decision.Allowed {
		t.Fatalf("member decision=%+v err=%v", decision, err)
	}
	teams, err := organizationService.Teams(t.Context(), organization.ID, member.ID)
	if err != nil || len(teams) != 1 || teams[0].ID != team.ID {
		t.Fatalf("member teams=%+v err=%v", teams, err)
	}
	if err = organizationService.SetMembershipStatus(t.Context(), organization.ID, owner.ID, "suspended", owner.ID, "request-suspend-owner"); err != nil {
		t.Fatal(err)
	}
	if err = organizationService.RemoveMembership(t.Context(), organization.ID, member.ID, member.ID, "request-last-member"); !errors.Is(err, organizations.ErrLastOwner) {
		t.Fatalf("sole active owner removal err=%v", err)
	}
	if _, err = organizationService.SetOrganizationStatus(t.Context(), organizations.SetOrganizationStatus{ID: organization.ID, Status: "archived", ActorUserID: member.ID, ExpectedRevision: organization.Revision, RequestID: "request-archive"}); err != nil {
		t.Fatal(err)
	}
	decision, err = accessService.Authorize(t.Context(), member.ID, access.Scope{OrganizationID: organization.ID}, "telemetry.read")
	if err != nil || decision.Allowed {
		t.Fatalf("archived organization decision=%+v err=%v", decision, err)
	}
}
