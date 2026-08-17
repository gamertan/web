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

func (repository *repositoryStub) CreateOrganization(_ context.Context, organization Organization, _ Membership) error {
	repository.organization = organization
	return nil
}
func (*repositoryStub) CreateTeam(context.Context, Team) error               { return nil }
func (*repositoryStub) AddTeamMember(context.Context, TeamMembership) error  { return nil }
func (*repositoryStub) CreateProject(context.Context, Project) error         { return nil }
func (*repositoryStub) CreateEnvironment(context.Context, Environment) error { return nil }
func (*repositoryStub) CreateApplicationService(context.Context, ApplicationService) error {
	return nil
}
func (repository *repositoryStub) CreateInvitation(_ context.Context, invitation Invitation) error {
	repository.invitation = invitation
	return nil
}
func (repository *repositoryStub) InvitationByDigest(context.Context, [32]byte, time.Time) (Invitation, error) {
	if repository.invitationErr != nil {
		return Invitation{}, repository.invitationErr
	}
	return repository.invitation, nil
}
func (repository *repositoryStub) AcceptInvitation(_ context.Context, _ [32]byte, userID string, _ time.Time) error {
	repository.acceptedUser = userID
	return nil
}
func (*repositoryStub) MembershipsForUser(context.Context, string) ([]Membership, error) {
	return nil, nil
}
func (*repositoryStub) TeamsForUser(context.Context, string, string) ([]Team, error) { return nil, nil }
