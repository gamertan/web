// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"errors"
	"testing"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authwebauthn"
	"gamertan.com/web/bootstrap"
)

func TestInitialOwnerBootstrapCommitsEveryBoundary(t *testing.T) {
	store, err := Open(t.TempDir() + "/bootstrap.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	policy := access.Policy{Roles: map[string]string{"home.owner": "Own the home organization"}, Permissions: map[string]string{"home.manage": "Manage the home organization"}, Grants: map[string][]string{"home.owner": {"home.manage"}}}
	accessService, err := access.New(store, policy, access.Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = accessService.Seed(t.Context()); err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 9, 3, 19, 0, 0, 0, time.UTC)
	service, err := bootstrap.New(store, bootstrap.Options{OwnerRole: "home.owner", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	created, err := service.Start(t.Context(), bootstrap.Input{Username: "cole.owner", Email: "cole@example.test", DisplayName: "Cole Speelman", OrganizationSlug: "gamertan", OrganizationName: "Gamertan"})
	if err != nil {
		t.Fatal(err)
	}
	user, err := store.UserByID(t.Context(), created.User.ID)
	if err != nil || user.Email != "cole@example.test" {
		t.Fatalf("user=%+v err=%v", user, err)
	}
	organization, err := store.OrganizationByID(t.Context(), created.Organization.ID)
	if err != nil || organization.Personal || organization.Slug != "gamertan" {
		t.Fatalf("organization=%+v err=%v", organization, err)
	}
	memberships, err := store.MembershipsForUser(t.Context(), user.ID)
	if err != nil || len(memberships) != 1 || memberships[0].OrganizationID != organization.ID {
		t.Fatalf("memberships=%+v err=%v", memberships, err)
	}
	decision, err := accessService.Authorize(t.Context(), user.ID, access.Scope{OrganizationID: organization.ID}, "home.manage")
	if err != nil || !decision.Allowed || decision.Role != "home.owner" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	passkeyService := testBootstrapPasskeyService(t, store, now)
	begin, err := passkeyService.BeginEnrollment(t.Context(), created.EnrollmentToken, "Initial passkey")
	if err != nil || begin.CeremonyToken == "" {
		t.Fatalf("begin=%+v err=%v", begin, err)
	}
	if _, err = passkeyService.BeginEnrollment(t.Context(), created.EnrollmentToken, "Replay"); !errors.Is(err, authwebauthn.ErrEnrollmentNotFound) {
		t.Fatalf("enrollment replay err=%v", err)
	}
	var authAudits, accessAudits int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM gwf_audit_events WHERE resource_id=?`, user.ID).Scan(&authAudits); err != nil {
		t.Fatal(err)
	}
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM gwf_access_audit_events WHERE organization_id=?`, organization.ID).Scan(&accessAudits); err != nil {
		t.Fatal(err)
	}
	if authAudits != 1 || accessAudits != 2 {
		t.Fatalf("auth audits=%d access audits=%d", authAudits, accessAudits)
	}
}

func TestInitialOwnerBootstrapRollsBackWithoutSeededRole(t *testing.T) {
	store, err := Open(t.TempDir() + "/bootstrap.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 9, 3, 19, 0, 0, 0, time.UTC)
	service, err := bootstrap.New(store, bootstrap.Options{OwnerRole: "home.owner", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Start(t.Context(), bootstrap.Input{Username: "cole.owner", Email: "cole@example.test", DisplayName: "Cole Speelman", OrganizationSlug: "gamertan", OrganizationName: "Gamertan"}); err == nil {
		t.Fatal("bootstrap succeeded without seeded role")
	}
	for _, table := range []string{"gwf_users", "gwf_organizations", "gwf_organization_memberships", "gwf_access_bindings", "gwf_passkey_enrollment_tokens", "gwf_audit_events", "gwf_access_audit_events"} {
		var count int
		if queryErr := store.db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); queryErr != nil || count != 0 {
			t.Fatalf("table=%s count=%d err=%v", table, count, queryErr)
		}
	}
}

func testBootstrapPasskeyService(t *testing.T, store *Store, now time.Time) *authwebauthn.Service {
	t.Helper()
	authService, err := auth.New(store, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	service, err := authwebauthn.New(store, authService, authwebauthn.Config{RPID: "example.test", RPDisplayName: "Example", Origin: "https://example.test", Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	return service
}
