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
	ErrInvitationNotFound   = errors.New("organizations: invitation not found")
	ErrMembershipNotFound   = errors.New("organizations: membership not found")
	ErrOrganizationNotFound = errors.New("organizations: organization not found")
	ErrTeamNotFound         = errors.New("organizations: team not found")
	ErrRevisionConflict     = errors.New("organizations: revision conflict")
	ErrPersonalOrganization = errors.New("organizations: personal organization lifecycle is fixed")
	ErrLastOwner            = errors.New("organizations: the last active direct owner must be preserved")
	slugPattern             = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	idPattern               = regexp.MustCompile(`^[A-Za-z0-9_-]{8,128}$`)
)

type Organization struct {
	ID                   string
	Slug                 string
	Name                 string
	Status               string
	Personal             bool
	Revision             int64
	CreatedAt, UpdatedAt time.Time
}

type Membership struct {
	OrganizationID string
	UserID         string
	Status         string
	JoinedAt       time.Time
}

type Team struct {
	ID, OrganizationID, Slug, Name, Status string
	Revision                               int64
	CreatedAt, UpdatedAt                   time.Time
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
	ID                                      string
	Digest                                  [32]byte
	OrganizationID                          string
	Email, InvitedByUserID                  string
	DirectRole                              string
	TeamIDs                                 []string
	CreatedAt, ExpiresAt, UsedAt, RevokedAt time.Time
}

type AuditEvent struct {
	ID, OrganizationID, ActorUserID, Action, ResourceType, ResourceID, RequestID, Summary string
	CreatedAt                                                                             time.Time
}

type Repository interface {
	CreateOrganization(context.Context, Organization, Membership, AuditEvent) error
	OrganizationByID(context.Context, string) (Organization, error)
	UpdateOrganization(context.Context, Organization, int64, AuditEvent) error
	CreateTeam(context.Context, Team, AuditEvent) error
	TeamByID(context.Context, string, string) (Team, error)
	UpdateTeam(context.Context, Team, int64, AuditEvent) error
	AddTeamMember(context.Context, TeamMembership, AuditEvent) error
	RemoveTeamMember(context.Context, string, string, AuditEvent) error
	SetMembershipStatus(context.Context, string, string, string, string, AuditEvent) error
	RemoveMembership(context.Context, string, string, string, AuditEvent) error
	CreateProject(context.Context, Project) error
	CreateEnvironment(context.Context, Environment) error
	CreateApplicationService(context.Context, ApplicationService) error
	CreateInvitation(context.Context, Invitation, AuditEvent) error
	InvitationByDigest(context.Context, [32]byte, time.Time) (Invitation, error)
	Invitations(context.Context, string, int) ([]Invitation, error)
	RevokeInvitation(context.Context, string, string, time.Time, AuditEvent) error
	AcceptInvitation(context.Context, [32]byte, string, time.Time, AuditEvent) error
	MembershipsForUser(context.Context, string) ([]Membership, error)
	TeamsForUser(context.Context, string, string) ([]Team, error)
}

type Options struct {
	Random    io.Reader
	Now       func() time.Time
	OwnerRole string
}

type Service struct {
	repository Repository
	random     io.Reader
	now        func() time.Time
	ownerRole  string
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
	if options.OwnerRole != "" && !safeNamePattern.MatchString(options.OwnerRole) {
		return nil, errors.New("organizations: owner role is invalid")
	}
	return &Service{repository: repository, random: options.Random, now: options.Now, ownerRole: options.OwnerRole}, nil
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
	organization := Organization{ID: id, Slug: input.Slug, Name: input.Name, Status: "active", Personal: input.Personal, Revision: 1, CreatedAt: now, UpdatedAt: now}
	owner := Membership{OrganizationID: id, UserID: input.OwnerUserID, Status: "active", JoinedAt: now}
	audit, err := service.audit(input.OwnerUserID, id, "organization.create", "organization", id, "Organization created")
	if err != nil {
		return Organization{}, err
	}
	if err = service.repository.CreateOrganization(ctx, organization, owner, audit); err != nil {
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

type CreateTeam struct{ OrganizationID, Slug, Name, ActorUserID string }

func (service *Service) CreateTeam(ctx context.Context, input CreateTeam) (Team, error) {
	input.Slug = strings.ToLower(strings.TrimSpace(input.Slug))
	input.Name = strings.TrimSpace(input.Name)
	if !idPattern.MatchString(input.OrganizationID) || !idPattern.MatchString(input.ActorUserID) || !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) {
		return Team{}, errors.New("organizations: invalid team")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return Team{}, err
	}
	now := service.now().UTC()
	team := Team{ID: id, OrganizationID: input.OrganizationID, Slug: input.Slug, Name: input.Name, Status: "active", Revision: 1, CreatedAt: now, UpdatedAt: now}
	audit, err := service.audit(input.ActorUserID, input.OrganizationID, "team.create", "team", id, "Team created")
	if err != nil {
		return Team{}, err
	}
	if err = service.repository.CreateTeam(ctx, team, audit); err != nil {
		return Team{}, err
	}
	return team, nil
}

func (service *Service) AddTeamMember(ctx context.Context, teamID, userID, actorUserID string) error {
	if !idPattern.MatchString(teamID) || !idPattern.MatchString(userID) || !idPattern.MatchString(actorUserID) {
		return errors.New("organizations: invalid team membership")
	}
	team, err := service.repository.TeamByID(ctx, "", teamID)
	if err != nil {
		return err
	}
	audit, err := service.audit(actorUserID, team.OrganizationID, "team.member.add", "team", teamID, "Team member added")
	if err != nil {
		return err
	}
	return service.repository.AddTeamMember(ctx, TeamMembership{TeamID: teamID, UserID: userID, JoinedAt: service.now().UTC()}, audit)
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
	return service.InviteWithAccess(ctx, InviteWithAccess{OrganizationID: organizationID, Email: email, InvitedByUserID: invitedBy, Lifetime: lifetime})
}

type InviteWithAccess struct {
	OrganizationID, Email, InvitedByUserID, DirectRole string
	TeamIDs                                            []string
	Lifetime                                           time.Duration
}

func (service *Service) InviteWithAccess(ctx context.Context, input InviteWithAccess) (string, Invitation, error) {
	organizationID, email, invitedBy, lifetime := input.OrganizationID, input.Email, input.InvitedByUserID, input.Lifetime
	email = strings.ToLower(strings.TrimSpace(email))
	input.DirectRole = strings.TrimSpace(input.DirectRole)
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(invitedBy) || !bounded(email, 320) || !strings.Contains(email, "@") || lifetime < 5*time.Minute || lifetime > 30*24*time.Hour || input.DirectRole != "" && !safeNamePattern.MatchString(input.DirectRole) || !validIDs(input.TeamIDs, 16) {
		return "", Invitation{}, errors.New("organizations: invalid invitation")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return "", Invitation{}, err
	}
	raw, err := token(service.random, 32)
	if err != nil {
		return "", Invitation{}, err
	}
	now := service.now().UTC()
	invitation := Invitation{ID: id, Digest: sha256.Sum256([]byte(raw)), OrganizationID: organizationID, Email: email, InvitedByUserID: invitedBy, DirectRole: input.DirectRole, TeamIDs: append([]string(nil), input.TeamIDs...), CreatedAt: now, ExpiresAt: now.Add(lifetime)}
	audit, err := service.audit(invitedBy, organizationID, "invitation.create", "invitation", id, "Organization invitation created")
	if err != nil {
		return "", Invitation{}, err
	}
	if err = service.repository.CreateInvitation(ctx, invitation, audit); err != nil {
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
	invitation, err := service.repository.InvitationByDigest(ctx, digest, now)
	if err != nil {
		return err
	}
	audit, err := service.audit(userID, invitation.OrganizationID, "invitation.accept", "invitation", invitation.ID, "Organization invitation accepted")
	if err != nil {
		return err
	}
	return service.repository.AcceptInvitation(ctx, digest, userID, now, audit)
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

type UpdateOrganization struct {
	ID, Slug, Name, ActorUserID, RequestID string
	ExpectedRevision                       int64
}

func (service *Service) UpdateOrganization(ctx context.Context, input UpdateOrganization) (Organization, error) {
	input.Slug, input.Name = strings.ToLower(strings.TrimSpace(input.Slug)), strings.TrimSpace(input.Name)
	if !idPattern.MatchString(input.ID) || !idPattern.MatchString(input.ActorUserID) || !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) || input.ExpectedRevision < 1 || !boundedOptional(input.RequestID, 128) {
		return Organization{}, errors.New("organizations: invalid organization update")
	}
	value, err := service.repository.OrganizationByID(ctx, input.ID)
	if err != nil {
		return Organization{}, err
	}
	value.Slug, value.Name, value.Revision, value.UpdatedAt = input.Slug, input.Name, input.ExpectedRevision+1, service.now().UTC()
	audit, err := service.auditWithRequest(input.ActorUserID, value.ID, "organization.update", "organization", value.ID, input.RequestID, "Organization details updated")
	if err != nil {
		return Organization{}, err
	}
	if err = service.repository.UpdateOrganization(ctx, value, input.ExpectedRevision, audit); err != nil {
		return Organization{}, err
	}
	return value, nil
}

type SetOrganizationStatus struct {
	ID, Status, ActorUserID, RequestID string
	ExpectedRevision                   int64
}

func (service *Service) SetOrganizationStatus(ctx context.Context, input SetOrganizationStatus) (Organization, error) {
	if !idPattern.MatchString(input.ID) || !idPattern.MatchString(input.ActorUserID) || (input.Status != "active" && input.Status != "archived") || input.ExpectedRevision < 1 || !boundedOptional(input.RequestID, 128) {
		return Organization{}, errors.New("organizations: invalid organization status")
	}
	value, err := service.repository.OrganizationByID(ctx, input.ID)
	if err != nil {
		return Organization{}, err
	}
	if value.Personal {
		return Organization{}, ErrPersonalOrganization
	}
	value.Status, value.Revision, value.UpdatedAt = input.Status, input.ExpectedRevision+1, service.now().UTC()
	action := "organization.archive"
	summary := "Organization archived"
	if input.Status == "active" {
		action, summary = "organization.reactivate", "Organization reactivated"
	}
	audit, err := service.auditWithRequest(input.ActorUserID, value.ID, action, "organization", value.ID, input.RequestID, summary)
	if err != nil {
		return Organization{}, err
	}
	if err = service.repository.UpdateOrganization(ctx, value, input.ExpectedRevision, audit); err != nil {
		return Organization{}, err
	}
	return value, nil
}

type UpdateTeam struct {
	OrganizationID, ID, Slug, Name, Status, ActorUserID, RequestID string
	ExpectedRevision                                               int64
}

func (service *Service) UpdateTeam(ctx context.Context, input UpdateTeam) (Team, error) {
	input.Slug, input.Name = strings.ToLower(strings.TrimSpace(input.Slug)), strings.TrimSpace(input.Name)
	if !idPattern.MatchString(input.OrganizationID) || !idPattern.MatchString(input.ID) || !idPattern.MatchString(input.ActorUserID) || !slugPattern.MatchString(input.Slug) || !bounded(input.Name, 128) || (input.Status != "active" && input.Status != "archived") || input.ExpectedRevision < 1 || !boundedOptional(input.RequestID, 128) {
		return Team{}, errors.New("organizations: invalid team update")
	}
	value, err := service.repository.TeamByID(ctx, input.OrganizationID, input.ID)
	if err != nil {
		return Team{}, err
	}
	priorStatus := value.Status
	value.Slug, value.Name, value.Status, value.Revision, value.UpdatedAt = input.Slug, input.Name, input.Status, input.ExpectedRevision+1, service.now().UTC()
	action, summary := "team.update", "Team details updated"
	if input.Status != priorStatus {
		action, summary = "team.archive", "Team archived"
		if input.Status == "active" {
			action, summary = "team.reactivate", "Team reactivated"
		}
	}
	audit, err := service.auditWithRequest(input.ActorUserID, value.OrganizationID, action, "team", value.ID, input.RequestID, summary)
	if err != nil {
		return Team{}, err
	}
	if err = service.repository.UpdateTeam(ctx, value, input.ExpectedRevision, audit); err != nil {
		return Team{}, err
	}
	return value, nil
}

func (service *Service) RemoveTeamMember(ctx context.Context, organizationID, teamID, userID, actorUserID, requestID string) error {
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(teamID) || !idPattern.MatchString(userID) || !idPattern.MatchString(actorUserID) || !boundedOptional(requestID, 128) {
		return errors.New("organizations: invalid team membership removal")
	}
	audit, err := service.auditWithRequest(actorUserID, organizationID, "team.member.remove", "team", teamID, requestID, "Team member removed")
	if err != nil {
		return err
	}
	return service.repository.RemoveTeamMember(ctx, teamID, userID, audit)
}

func (service *Service) SetMembershipStatus(ctx context.Context, organizationID, userID, status, actorUserID, requestID string) error {
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(userID) || !idPattern.MatchString(actorUserID) || (status != "active" && status != "suspended") || !boundedOptional(requestID, 128) {
		return errors.New("organizations: invalid membership status")
	}
	if status != "active" && service.ownerRole == "" {
		return errors.New("organizations: owner role is required for membership lifecycle changes")
	}
	audit, err := service.auditWithRequest(actorUserID, organizationID, "membership."+status, "membership", userID, requestID, "Organization membership set to "+status)
	if err != nil {
		return err
	}
	return service.repository.SetMembershipStatus(ctx, organizationID, userID, status, service.ownerRole, audit)
}

func (service *Service) RemoveMembership(ctx context.Context, organizationID, userID, actorUserID, requestID string) error {
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(userID) || !idPattern.MatchString(actorUserID) || !boundedOptional(requestID, 128) {
		return errors.New("organizations: invalid membership removal")
	}
	if service.ownerRole == "" {
		return errors.New("organizations: owner role is required for membership lifecycle changes")
	}
	audit, err := service.auditWithRequest(actorUserID, organizationID, "membership.remove", "membership", userID, requestID, "Organization membership removed")
	if err != nil {
		return err
	}
	return service.repository.RemoveMembership(ctx, organizationID, userID, service.ownerRole, audit)
}

func (service *Service) Invitations(ctx context.Context, organizationID string, limit int) ([]Invitation, error) {
	if !idPattern.MatchString(organizationID) || limit < 1 || limit > 1000 {
		return nil, errors.New("organizations: invalid invitation query")
	}
	return service.repository.Invitations(ctx, organizationID, limit)
}

func (service *Service) RevokeInvitation(ctx context.Context, organizationID, invitationID, actorUserID, requestID string) error {
	if !idPattern.MatchString(organizationID) || !idPattern.MatchString(invitationID) || !idPattern.MatchString(actorUserID) || !boundedOptional(requestID, 128) {
		return errors.New("organizations: invalid invitation revocation")
	}
	now := service.now().UTC()
	audit, err := service.auditWithRequest(actorUserID, organizationID, "invitation.revoke", "invitation", invitationID, requestID, "Organization invitation revoked")
	if err != nil {
		return err
	}
	return service.repository.RevokeInvitation(ctx, organizationID, invitationID, now, audit)
}

func (service *Service) Repository() Repository { return service.repository }

func (service *Service) audit(actor, organizationID, action, resourceType, resourceID, summary string) (AuditEvent, error) {
	return service.auditWithRequest(actor, organizationID, action, resourceType, resourceID, "", summary)
}

func (service *Service) auditWithRequest(actor, organizationID, action, resourceType, resourceID, requestID, summary string) (AuditEvent, error) {
	if !idPattern.MatchString(actor) || !idPattern.MatchString(organizationID) || !bounded(action, 128) || !bounded(resourceType, 128) || !bounded(resourceID, 128) || !boundedOptional(requestID, 128) || !bounded(summary, 512) {
		return AuditEvent{}, errors.New("organizations: invalid audit event")
	}
	id, err := token(service.random, 18)
	if err != nil {
		return AuditEvent{}, err
	}
	return AuditEvent{ID: id, OrganizationID: organizationID, ActorUserID: actor, Action: action, ResourceType: resourceType, ResourceID: resourceID, RequestID: requestID, Summary: summary, CreatedAt: service.now().UTC()}, nil
}

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

func boundedOptional(value string, limit int) bool {
	return len(value) <= limit && !strings.ContainsAny(value, "\x00\r\n")
}

func validIDs(values []string, limit int) bool {
	if len(values) > limit {
		return false
	}
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if !idPattern.MatchString(value) {
			return false
		}
		if _, exists := seen[value]; exists {
			return false
		}
		seen[value] = struct{}{}
	}
	return true
}

var safeNamePattern = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,127}$`)
