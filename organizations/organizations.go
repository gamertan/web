// SPDX-License-Identifier: MPL-2.0

// Package organizations defines storage-neutral organizations, teams,
// memberships, and single-use invitations.
package organizations

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"regexp"
	"strings"
	"time"
)

var (
	ErrInvitationNotFound = errors.New("organizations: invitation not found")
	ErrMembershipNotFound = errors.New("organizations: membership not found")
	slugPattern           = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	idPattern             = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
)

type Organization struct {
	ID        string
	Slug      string
	Name      string
	Personal  bool
	CreatedAt time.Time
}

type Membership struct {
	OrganizationID string
	UserID         string
	Status         string
	JoinedAt       time.Time
}

type Team struct {
	ID, OrganizationID, Slug, Name string
	CreatedAt                      time.Time
}

type TeamMembership struct {
	TeamID, UserID string
	JoinedAt       time.Time
}

type Project struct {
	ID, OrganizationID, Slug, Name string
	CreatedAt                      time.Time
}

type Environment struct {
	ID, OrganizationID, ProjectID, Slug, Name string
	CreatedAt                                 time.Time
}

type ApplicationService struct {
	ID, OrganizationID, ProjectID, EnvironmentID, Slug, Name string
	CreatedAt                                                time.Time
}

type Invitation struct {
	Digest                       [32]byte
	OrganizationID               string
	Email, InvitedByUserID       string
	CreatedAt, ExpiresAt, UsedAt time.Time
}

type Repository interface {
	CreateOrganization(context.Context, Organization, Membership) error
	CreateTeam(context.Context, Team) error
	AddTeamMember(context.Context, TeamMembership) error
	CreateProject(context.Context, Project) error
	CreateEnvironment(context.Context, Environment) error
	CreateApplicationService(context.Context, ApplicationService) error
	CreateInvitation(context.Context, Invitation) error
	InvitationByDigest(context.Context, [32]byte, time.Time) (Invitation, error)
	AcceptInvitation(context.Context, [32]byte, string, time.Time) error
	MembershipsForUser(context.Context, string) ([]Membership, error)
	TeamsForUser(context.Context, string, string) ([]Team, error)
}

type Options struct {
	Random io.Reader
	Now    func() time.Time
}

type Service struct {
	repository Repository
	random     io.Reader
	now        func() time.Time
}

func New(repository Repository, options Options) (*Service, error) {
	if repository == nil {
		return nil, errors.New("organizations: repository is required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{repository: repository, random: options.Random, now: options.Now}, nil
}

type CreateOrganization struct {
	Slug, Name, OwnerUserID string
	Personal                bool
}

func (service *Service) CreateOrganization(ctx context.Context, input CreateOrganization) (Organization, error) {
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	input.Name = strings.TrimSpace(input.Name)
	if !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) || !idPattern.MatchString(input.OwnerUserID) {
		return Organization{}, errors.New("organizations: invalid organization")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return Organization{}, err
	}
	now := service.now().UTC()
	organization := Organization{ID: id, Slug: input.Slug, Name: input.Name, Personal: input.Personal, CreatedAt: now}
	owner := Membership{OrganizationID: id, UserID: input.OwnerUserID, Status: "active", JoinedAt: now}
	if err = service.repository.CreateOrganization(ctx, organization, owner); err != nil {
		return Organization{}, err
	}
	return organization, nil
}

func (service *Service) CreatePersonalOrganization(ctx context.Context, userID, displayName string) (Organization, error) {
	value := make([]byte, 6)
	if _, err := io.ReadFull(service.random, value); err != nil {
		return Organization{}, fmt.Errorf("organizations: secure randomness unavailable: %w", err)
	}
	suffix := hex.EncodeToString(value)
	return service.CreateOrganization(ctx, CreateOrganization{Slug: "personal-" + strings.ToLower(suffix), Name: strings.TrimSpace(displayName) + " — Personal", OwnerUserID: userID, Personal: true})
}

type CreateTeam struct{ OrganizationID, Slug, Name string }

func (service *Service) CreateTeam(ctx context.Context, input CreateTeam) (Team, error) {
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	input.Name = strings.TrimSpace(input.Name)
	if !idPattern.MatchString(input.OrganizationID) || !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) {
		return Team{}, errors.New("organizations: invalid team")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return Team{}, err
	}
	team := Team{ID: id, OrganizationID: input.OrganizationID, Slug: input.Slug, Name: input.Name, CreatedAt: service.now().UTC()}
	if err = service.repository.CreateTeam(ctx, team); err != nil {
		return Team{}, err
	}
	return team, nil
}

func (service *Service) AddTeamMember(ctx context.Context, teamID, userID string) error {
	if !idPattern.MatchString(teamID) || !idPattern.MatchString(userID) {
		return errors.New("organizations: invalid team membership")
	}
	return service.repository.AddTeamMember(ctx, TeamMembership{TeamID: teamID, UserID: userID, JoinedAt: service.now().UTC()})
}

type CreateProject struct{ OrganizationID, Slug, Name string }

func (service *Service) CreateProject(ctx context.Context, input CreateProject) (Project, error) {
	input.Slug, input.Name = strings.ToLower(strings.TrimSpace(input.Slug)), strings.TrimSpace(input.Name)
	if !idPattern.MatchString(input.OrganizationID) || !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) {
		return Project{}, errors.New("organizations: invalid project")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return Project{}, err
	}
	project := Project{ID: id, OrganizationID: input.OrganizationID, Slug: input.Slug, Name: input.Name, CreatedAt: service.now().UTC()}
	if err = service.repository.CreateProject(ctx, project); err != nil {
		return Project{}, err
	}
	return project, nil
}

type CreateEnvironment struct{ OrganizationID, ProjectID, Slug, Name string }

func (service *Service) CreateEnvironment(ctx context.Context, input CreateEnvironment) (Environment, error) {
	input.Slug, input.Name = strings.ToLower(strings.TrimSpace(input.Slug)), strings.TrimSpace(input.Name)
	if !idPattern.MatchString(input.OrganizationID) || !idPattern.MatchString(input.ProjectID) || !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) {
		return Environment{}, errors.New("organizations: invalid environment")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return Environment{}, err
	}
	environment := Environment{ID: id, OrganizationID: input.OrganizationID, ProjectID: input.ProjectID, Slug: input.Slug, Name: input.Name, CreatedAt: service.now().UTC()}
	if err = service.repository.CreateEnvironment(ctx, environment); err != nil {
		return Environment{}, err
	}
	return environment, nil
}

type CreateApplicationService struct{ OrganizationID, ProjectID, EnvironmentID, Slug, Name string }

func (service *Service) CreateApplicationService(ctx context.Context, input CreateApplicationService) (ApplicationService, error) {
	input.Slug, input.Name = strings.ToLower(strings.TrimSpace(input.Slug)), strings.TrimSpace(input.Name)
	if !idPattern.MatchString(input.OrganizationID) || !idPattern.MatchString(input.ProjectID) || !idPattern.MatchString(input.EnvironmentID) || !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) {
		return ApplicationService{}, errors.New("organizations: invalid application service")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return ApplicationService{}, err
	}
	application := ApplicationService{ID: id, OrganizationID: input.OrganizationID, ProjectID: input.ProjectID, EnvironmentID: input.EnvironmentID, Slug: input.Slug, Name: input.Name, CreatedAt: service.now().UTC()}
	if err = service.repository.CreateApplicationService(ctx, application); err != nil {
		return ApplicationService{}, err
	}
	return application, nil
}

func (service *Service) Invite(ctx context.Context, organizationID, email, invitedBy string, lifetime time.Duration) (string, Invitation, error) {
	email = strings.ToLower(strings.TrimSpace(email))
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(invitedBy) || !bounded(email, 320) || !strings.Contains(email, "@") || lifetime < 5*time.Minute || lifetime > 30*24*time.Hour {
		return "", Invitation{}, errors.New("organizations: invalid invitation")
	}
	raw, err := token(service.random, 32)
	if err != nil {
		return "", Invitation{}, err
	}
	now := service.now().UTC()
	invitation := Invitation{Digest: sha256.Sum256([]byte(raw)), OrganizationID: organizationID, Email: email, InvitedByUserID: invitedBy, CreatedAt: now, ExpiresAt: now.Add(lifetime)}
	if err = service.repository.CreateInvitation(ctx, invitation); err != nil {
		return "", Invitation{}, err
	}
	return raw, invitation, nil
}

func (service *Service) AcceptInvitation(ctx context.Context, rawToken, userID string) error {
	if len(rawToken) < 32 || len(rawToken) > 128 || !idPattern.MatchString(userID) {
		return ErrInvitationNotFound
	}
	digest := sha256.Sum256([]byte(rawToken))
	now := service.now().UTC()
	if _, err := service.repository.InvitationByDigest(ctx, digest, now); err != nil {
		return err
	}
	return service.repository.AcceptInvitation(ctx, digest, userID, now)
}

func (service *Service) Memberships(ctx context.Context, userID string) ([]Membership, error) {
	if !idPattern.MatchString(userID) {
		return nil, errors.New("organizations: invalid user")
	}
	return service.repository.MembershipsForUser(ctx, userID)
}

func (service *Service) Teams(ctx context.Context, organizationID, userID string) ([]Team, error) {
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(userID) {
		return nil, errors.New("organizations: invalid team query")
	}
	return service.repository.TeamsForUser(ctx, organizationID, userID)
}

func (service *Service) Repository() Repository { return service.repository }

func token(random io.Reader, size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("organizations: secure randomness unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func bounded(value string, limit int) bool {
	return value != "" && len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n")
}
