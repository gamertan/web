// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
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
	team, err := organizationService.CreateTeam(t.Context(), organizations.CreateTeam{OrganizationID: organization.ID, Slug: "operators", Name: "Operators"})
	if err != nil {
		t.Fatal(err)
	}
	if err = organizationService.AddTeamMember(t.Context(), team.ID, member.ID); err != nil {
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
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM gwf_access_audit_events WHERE organization_id=?`, organization.ID).Scan(&audits); err != nil || audits != 1 {
		t.Fatalf("audits=%d err=%v", audits, err)
	}
	auditEvents, err := accessService.Audit(t.Context(), organization.ID, 10)
	if err != nil || len(auditEvents) != 1 || auditEvents[0].Action != "break_glass.activate" {
		t.Fatalf("audit events=%+v err=%v", auditEvents, err)
	}
}
