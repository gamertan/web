// SPDX-License-Identifier: MPL-2.0

package access

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestScopedRoleAndBreakGlass(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	repository := &repositoryStub{}
	policy := Policy{Roles: map[string]string{"viewer": "Read safe telemetry"}, Permissions: map[string]string{"telemetry.read": "Read telemetry", "telemetry.sensitive.read": "Read sensitive telemetry"}, Grants: map[string][]string{"viewer": {"telemetry.read"}}}
	service, err := New(repository, policy, Options{Random: strings.NewReader(strings.Repeat("r", 512)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	scope := Scope{OrganizationID: "org-12345678", ProjectID: "project-12345678"}
	binding, err := service.Grant(t.Context(), Grant{SubjectKind: User, SubjectID: "user-12345678", Role: "viewer", Scope: scope, GrantedBy: "user-87654321"})
	if err != nil {
		t.Fatal(err)
	}
	repository.bindings = []Binding{binding}
	decision, err := service.Authorize(t.Context(), "user-12345678", Scope{OrganizationID: scope.OrganizationID, ProjectID: scope.ProjectID, EnvironmentID: "env-12345678"}, "telemetry.read")
	if err != nil || !decision.Allowed || decision.Source != "role" {
		t.Fatalf("decision=%+v err=%v", decision, err)
	}
	decision, err = service.Authorize(t.Context(), "user-12345678", scope, "telemetry.sensitive.read")
	if err != nil || decision.Allowed {
		t.Fatalf("unexpected sensitive decision=%+v err=%v", decision, err)
	}
	grant, err := service.ActivateBreakGlass(t.Context(), scope.OrganizationID, "user-12345678", "telemetry.sensitive.read", "Investigate active incident", "request-12345678", 15*time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	repository.breakGlass = []BreakGlass{grant}
	decision, err = service.Authorize(t.Context(), "user-12345678", scope, "telemetry.sensitive.read")
	if err != nil || !decision.Allowed || decision.Source != "break_glass" {
		t.Fatalf("break-glass decision=%+v err=%v", decision, err)
	}
}

func TestScopeHierarchyAndLifetimeFailClosed(t *testing.T) {
	policy := Policy{Roles: map[string]string{"viewer": ""}, Permissions: map[string]string{"telemetry.read": ""}, Grants: map[string][]string{"viewer": {"telemetry.read"}}}
	service, err := New(&repositoryStub{}, policy, Options{Random: strings.NewReader(strings.Repeat("x", 256))})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Grant(t.Context(), Grant{SubjectKind: User, SubjectID: "user-12345678", Role: "viewer", Scope: Scope{OrganizationID: "org-12345678", EnvironmentID: "env-12345678"}, GrantedBy: "user-87654321"}); err == nil {
		t.Fatal("incomplete hierarchy accepted")
	}
	if _, err = service.ActivateBreakGlass(t.Context(), "org-12345678", "user-12345678", "telemetry.read", "reason", "", 2*time.Hour); err == nil {
		t.Fatal("unbounded break-glass lifetime accepted")
	}
}

type repositoryStub struct {
	bindings   []Binding
	breakGlass []BreakGlass
}

func (*repositoryStub) SeedAccessPolicy(context.Context, Policy) error          { return nil }
func (*repositoryStub) Grant(context.Context, Binding) error                    { return nil }
func (*repositoryStub) Revoke(context.Context, string, string, time.Time) error { return nil }
func (repository *repositoryStub) EffectiveBindings(context.Context, string, string) ([]Binding, error) {
	return repository.bindings, nil
}
func (repository *repositoryStub) CreateBreakGlass(_ context.Context, grant BreakGlass, _ AuditEvent) error {
	repository.breakGlass = []BreakGlass{grant}
	return nil
}
func (repository *repositoryStub) ActiveBreakGlass(context.Context, string, string, time.Time) ([]BreakGlass, error) {
	return repository.breakGlass, nil
}
func (*repositoryStub) AppendAccessAudit(context.Context, AuditEvent) error { return nil }
func (*repositoryStub) AccessAudit(context.Context, string, int) ([]AuditEvent, error) {
	return nil, nil
}
