// SPDX-License-Identifier: MPL-2.0

// Package bootstrap creates the first application owner and non-personal
// organization as one storage transaction. It is intended for a root-local
// operator command, not for public registration or a network administration
// endpoint.
package bootstrap

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authwebauthn"
	"gamertan.com/web/organizations"
)

const defaultEnrollmentLifetime = 15 * time.Minute

var (
	identifierPattern = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)
	slugPattern       = regexp.MustCompile(`^[a-z0-9][a-z0-9-]{1,62}$`)
	rolePattern       = regexp.MustCompile(`^[a-z][a-z0-9._-]{1,127}$`)
)

// Input is the reviewed, non-secret identity and organization metadata from a
// local operator command.
type Input struct {
	Username         string
	Email            string
	DisplayName      string
	OrganizationSlug string
	OrganizationName string
}

// Setup is the complete secret-free state a repository must commit atomically.
// Enrollment contains only a digest; the raw token remains in the Result.
type Setup struct {
	User              auth.User
	Enrollment        authwebauthn.EnrollmentToken
	Organization      organizations.Organization
	Membership        organizations.Membership
	OwnerBinding      access.Binding
	AuthAudit         auth.AuditEvent
	OrganizationAudit organizations.AuditEvent
	AccessAudit       access.AuditEvent
}

// Result contains the created public records and the one-time enrollment
// secret. Applications must deliver EnrollmentToken through a private channel
// and must never log it.
type Result struct {
	User            auth.User
	Organization    organizations.Organization
	EnrollmentToken string
	ExpiresAt       time.Time
}

// Repository owns the single transaction spanning identity, enrollment,
// organization membership, owner access, and their audit events.
type Repository interface {
	CreateInitialOwner(context.Context, Setup) error
}

type Options struct {
	OwnerRole          string
	EnrollmentLifetime time.Duration
	Random             io.Reader
	Now                func() time.Time
}

type Service struct {
	repository         Repository
	ownerRole          string
	enrollmentLifetime time.Duration
	random             io.Reader
	now                func() time.Time
}

func New(repository Repository, options Options) (*Service, error) {
	if repository == nil {
		return nil, errors.New("bootstrap: repository is required")
	}
	if !rolePattern.MatchString(options.OwnerRole) {
		return nil, errors.New("bootstrap: owner role is invalid")
	}
	if options.EnrollmentLifetime == 0 {
		options.EnrollmentLifetime = defaultEnrollmentLifetime
	}
	if options.EnrollmentLifetime < time.Minute || options.EnrollmentLifetime > time.Hour {
		return nil, errors.New("bootstrap: enrollment lifetime is invalid")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	return &Service{repository: repository, ownerRole: options.OwnerRole, enrollmentLifetime: options.EnrollmentLifetime, random: options.Random, now: options.Now}, nil
}

// Start atomically creates one active passkey-only owner, one active
// non-personal organization, direct owner access, and a single-use enrollment
// token. It does not create a session or expose a network bootstrap surface.
func (service *Service) Start(ctx context.Context, input Input) (Result, error) {
	input.Username = strings.TrimSpace(input.Username)
	input.Email = strings.ToLower(strings.TrimSpace(input.Email))
	input.DisplayName = strings.TrimSpace(input.DisplayName)
	input.OrganizationSlug = strings.ToLower(strings.TrimSpace(input.OrganizationSlug))
	input.OrganizationName = strings.TrimSpace(input.OrganizationName)
	if !identifierPattern.MatchString(input.Username) || !canonicalEmail(input.Email) || !bounded(input.DisplayName, 128) || !slugPattern.MatchString(input.OrganizationSlug) || !bounded(input.OrganizationName, 128) {
		return Result{}, errors.New("bootstrap: invalid owner or organization")
	}
	values, err := service.randomValues(7)
	if err != nil {
		return Result{}, err
	}
	now := service.now().UTC()
	userID, organizationID, bindingID := values[0], values[1], values[2]
	rawToken := values[3]
	user := auth.User{ID: userID, Username: input.Username, Email: input.Email, DisplayName: input.DisplayName, Status: "active", CreatedAt: now, UpdatedAt: now}
	organization := organizations.Organization{ID: organizationID, Slug: input.OrganizationSlug, Name: input.OrganizationName, Status: "active", Revision: 1, CreatedAt: now, UpdatedAt: now}
	enrollment := authwebauthn.EnrollmentToken{Digest: sha256.Sum256([]byte(rawToken)), UserID: userID, CreatedAt: now, ExpiresAt: now.Add(service.enrollmentLifetime)}
	membership := organizations.Membership{OrganizationID: organizationID, UserID: userID, Status: "active", JoinedAt: now}
	binding := access.Binding{ID: bindingID, SubjectKind: access.User, SubjectID: userID, Role: service.ownerRole, Scope: access.Scope{OrganizationID: organizationID}, GrantedBy: userID, GrantedAt: now}
	setup := Setup{
		User:              user,
		Enrollment:        enrollment,
		Organization:      organization,
		Membership:        membership,
		OwnerBinding:      binding,
		AuthAudit:         auth.AuditEvent{ID: values[4], ActorUserID: userID, Action: "auth.passkey.bootstrap", ResourceType: "user", ResourceID: userID, Summary: "A local operator created the initial passkey-only owner and one-time enrollment token.", CreatedAt: now},
		OrganizationAudit: organizations.AuditEvent{ID: values[5], OrganizationID: organizationID, ActorUserID: userID, Action: "organization.bootstrap", ResourceType: "organization", ResourceID: organizationID, Summary: "A local operator created the initial organization.", CreatedAt: now},
		AccessAudit:       access.AuditEvent{ID: values[6], OrganizationID: organizationID, ActorUserID: userID, Action: "access.binding.grant", ResourceType: "binding", ResourceID: bindingID, Summary: "The initial owner received direct organization access.", CreatedAt: now},
	}
	if err = service.repository.CreateInitialOwner(ctx, setup); err != nil {
		return Result{}, err
	}
	return Result{User: user, Organization: organization, EnrollmentToken: rawToken, ExpiresAt: enrollment.ExpiresAt}, nil
}

func (service *Service) randomValues(count int) ([]string, error) {
	values := make([]string, count)
	for index := range values {
		bytes := make([]byte, 24)
		if _, err := io.ReadFull(service.random, bytes); err != nil {
			return nil, fmt.Errorf("bootstrap: secure randomness unavailable: %w", err)
		}
		values[index] = base64.RawURLEncoding.EncodeToString(bytes)
	}
	return values, nil
}

func canonicalEmail(value string) bool {
	if value == "" || len(value) > 320 || strings.ContainsAny(value, "\x00\r\n") {
		return false
	}
	address, err := mail.ParseAddress(value)
	return err == nil && address.Name == "" && address.Address == value
}

func bounded(value string, maximum int) bool {
	return value != "" && len(value) <= maximum && !strings.ContainsAny(value, "\x00\r\n")
}
