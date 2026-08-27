// SPDX-License-Identifier: MPL-2.0

package organizations

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestCreateInviteAndAccept(t *testing.T) {
	now := time.Unix(1000, 0).UTC()
	repository := &repositoryStub{}
	service, err := New(repository, Options{Random: strings.NewReader(strings.Repeat("r", 512)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	organization, err := service.CreateOrganization(t.Context(), CreateOrganization{Slug: "quiet-systems", Name: "Quiet Systems", OwnerUserID: "user-12345678"})
	if err != nil || organization.ID == "" || repository.organization.ID != organization.ID {
		t.Fatalf("organization=%+v err=%v", organization, err)
	}
	raw, invitation, err := service.Invite(t.Context(), organization.ID, "MEMBER@example.test", "user-12345678", time.Hour)
	if err != nil || raw == "" || invitation.Email != "member@example.test" {
		t.Fatalf("invitation=%+v err=%v", invitation, err)
	}
	repository.invitation = invitation
	if err = service.AcceptInvitation(t.Context(), raw, "user-87654321"); err != nil {
		t.Fatal(err)
	}
	if repository.acceptedUser != "user-87654321" {
		t.Fatalf("accepted=%q", repository.acceptedUser)
	}
}

func TestInvitationFailsClosed(t *testing.T) {
	service, err := New(&repositoryStub{invitationErr: ErrInvitationNotFound}, Options{Random: strings.NewReader(strings.Repeat("x", 256))})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.AcceptInvitation(t.Context(), strings.Repeat("x", 43), "user-87654321"); !errors.Is(err, ErrInvitationNotFound) {
		t.Fatalf("err=%v", err)
	}
	if _, _, err = service.Invite(t.Context(), "bad", "person@example.test", "user-12345678", time.Hour); err == nil {
		t.Fatal("invalid organization accepted")
	}
}

type repositoryStub struct {
	organization  Organization
	invitation    Invitation
	invitationErr error
	acceptedUser  string
}

func (repository *repositoryStub) CreateOrganization(_ context.Context, organization Organization, _ Membership, _ AuditEvent) error {
	repository.organization = organization
	return nil
}
func (repository *repositoryStub) OrganizationByID(context.Context, string) (Organization, error) {
	return repository.organization, nil
}
func (*repositoryStub) UpdateOrganization(context.Context, Organization, int64, AuditEvent) error {
	return nil
}
func (*repositoryStub) CreateTeam(context.Context, Team, AuditEvent) error { return nil }
func (*repositoryStub) TeamByID(context.Context, string, string) (Team, error) {
	return Team{}, nil
}
func (*repositoryStub) UpdateTeam(context.Context, Team, int64, AuditEvent) error { return nil }
func (*repositoryStub) AddTeamMember(context.Context, TeamMembership, AuditEvent) error {
	return nil
}
func (*repositoryStub) RemoveTeamMember(context.Context, string, string, AuditEvent) error {
	return nil
}
func (*repositoryStub) SetMembershipStatus(context.Context, string, string, string, string, AuditEvent) error {
	return nil
}
func (*repositoryStub) RemoveMembership(context.Context, string, string, string, AuditEvent) error {
	return nil
}
func (*repositoryStub) CreateProject(context.Context, Project) error         { return nil }
func (*repositoryStub) CreateEnvironment(context.Context, Environment) error { return nil }
func (*repositoryStub) CreateApplicationService(context.Context, ApplicationService) error {
	return nil
}
func (repository *repositoryStub) CreateInvitation(_ context.Context, invitation Invitation, _ AuditEvent) error {
	repository.invitation = invitation
	return nil
}
func (repository *repositoryStub) InvitationByDigest(context.Context, [32]byte, time.Time) (Invitation, error) {
	if repository.invitationErr != nil {
		return Invitation{}, repository.invitationErr
	}
	return repository.invitation, nil
}
func (*repositoryStub) Invitations(context.Context, string, int) ([]Invitation, error) {
	return nil, nil
}
func (*repositoryStub) RevokeInvitation(context.Context, string, string, time.Time, AuditEvent) error {
	return nil
}
func (repository *repositoryStub) AcceptInvitation(_ context.Context, _ [32]byte, userID string, _ time.Time, _ AuditEvent) error {
	repository.acceptedUser = userID
	return nil
}
func (*repositoryStub) MembershipsForUser(context.Context, string) ([]Membership, error) {
	return nil, nil
}
func (*repositoryStub) TeamsForUser(context.Context, string, string) ([]Team, error) { return nil, nil }
