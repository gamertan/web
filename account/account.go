// SPDX-License-Identifier: MPL-2.0

// Package account orchestrates atomic account registration. Email is the
// canonical sign-in identifier; username remains the stable public/profile
// identity. Applications may finish with password-only base access or include
// an initial passkey when their onboarding policy requires one.
package account

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/mail"
	"regexp"
	"strings"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/auth"
	"gamertan.com/web/authrecovery"
	"gamertan.com/web/authwebauthn"
	"gamertan.com/web/organizations"
)

var (
	ErrRegistrationNotFound = errors.New("account: registration not found")
	ErrPasskeysUnavailable  = errors.New("account: passkeys are unavailable")
	usernamePattern         = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)
)

type Registration struct {
	Digest               [32]byte
	User                 auth.User
	CreatedAt, ExpiresAt time.Time
}

type RegistrationCompletion struct {
	Credential        *authwebauthn.Credential
	RecoveryDigests   [][32]byte
	Organization      organizations.Organization
	Membership        organizations.Membership
	OwnerBinding      access.Binding
	AuthAudit         auth.AuditEvent
	OrganizationAudit organizations.AuditEvent
	AccessAudit       access.AuditEvent
	CompletedAt       time.Time
}

type Repository interface {
	CreateRegistration(context.Context, Registration, string, auth.AuditEvent) error
	Registration(context.Context, [32]byte, time.Time) (Registration, error)
	CompleteRegistration(context.Context, [32]byte, RegistrationCompletion) error
}

type Passkeys interface {
	BeginAccountRegistration(context.Context, string, string, []byte) (authwebauthn.BeginResult, error)
	FinishAccountRegistration(context.Context, string, []byte, []byte, authwebauthn.RegistrationCommit) (authwebauthn.Credential, error)
}

type Sessions interface {
	IssueSession(context.Context, string, time.Duration) (string, auth.Principal, error)
}

type Options struct {
	Random          io.Reader
	Now             func() time.Time
	RegistrationTTL time.Duration
	SessionLifetime time.Duration
	RecoveryCodes   int
	OwnerRole       string
}

type Service struct {
	repository Repository
	passkeys   Passkeys
	sessions   Sessions
	random     io.Reader
	now        func() time.Time
	draftTTL   time.Duration
	sessionTTL time.Duration
	codeCount  int
	ownerRole  string
}

func New(repository Repository, passkeys Passkeys, sessions Sessions, options Options) (*Service, error) {
	if repository == nil || sessions == nil {
		return nil, errors.New("account: repository and sessions are required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.RegistrationTTL == 0 {
		options.RegistrationTTL = 15 * time.Minute
	}
	if options.SessionLifetime == 0 {
		options.SessionLifetime = 12 * time.Hour
	}
	if options.RecoveryCodes == 0 {
		options.RecoveryCodes = authrecovery.DefaultCodeCount
	}
	if options.OwnerRole == "" {
		options.OwnerRole = "owner"
	}
	if options.RegistrationTTL < 5*time.Minute || options.RegistrationTTL > time.Hour || options.SessionLifetime < 5*time.Minute || options.SessionLifetime > 30*24*time.Hour || options.RecoveryCodes < 5 || options.RecoveryCodes > 20 || !roleName(options.OwnerRole) {
		return nil, errors.New("account: invalid registration policy")
	}
	return &Service{repository: repository, passkeys: passkeys, sessions: sessions, random: options.Random, now: options.Now, draftTTL: options.RegistrationTTL, sessionTTL: options.SessionLifetime, codeCount: options.RecoveryCodes, ownerRole: options.OwnerRole}, nil
}

type StartInput struct {
	Email, Username, DisplayName, Password string
}

type StartResult struct {
	RegistrationToken string
	User              auth.User
	ExpiresAt         time.Time
}

// Start validates and stores a bounded pending registration. The returned
// secret is displayed only to the same browser flow and binds every following
// ceremony to this draft.
func (service *Service) Start(ctx context.Context, input StartInput) (StartResult, error) {
	email, err := canonicalEmail(input.Email)
	if err != nil {
		return StartResult{}, err
	}
	username := strings.TrimSpace(input.Username)
	displayName := strings.TrimSpace(input.DisplayName)
	if !usernamePattern.MatchString(username) || displayName == "" || len(displayName) > 128 || strings.ContainsAny(displayName, "\x00\r\n") {
		return StartResult{}, errors.New("account: invalid profile")
	}
	passwordHash, err := auth.HashPasswordWithRandom(input.Password, service.random)
	if err != nil {
		return StartResult{}, err
	}
	userID, err := service.token(18)
	if err != nil {
		return StartResult{}, err
	}
	rawToken, err := service.token(32)
	if err != nil {
		return StartResult{}, err
	}
	now := service.now().UTC()
	user := auth.User{ID: userID, Username: username, Email: email, DisplayName: displayName, Status: "active", RegistrationPending: true, CreatedAt: now, UpdatedAt: now}
	registration := Registration{Digest: sha256.Sum256([]byte(rawToken)), User: user, CreatedAt: now, ExpiresAt: now.Add(service.draftTTL)}
	audit, err := service.authAudit(user.ID, "auth.account.registration.start", "A public account registration was started.")
	if err != nil {
		return StartResult{}, err
	}
	if err = service.repository.CreateRegistration(ctx, registration, passwordHash, audit); err != nil {
		return StartResult{}, err
	}
	return StartResult{RegistrationToken: rawToken, User: user, ExpiresAt: registration.ExpiresAt}, nil
}

func (service *Service) BeginPasskey(ctx context.Context, registrationToken, label string) (authwebauthn.BeginResult, error) {
	if service.passkeys == nil {
		return authwebauthn.BeginResult{}, ErrPasskeysUnavailable
	}
	registration, err := service.registration(ctx, registrationToken)
	if err != nil {
		return authwebauthn.BeginResult{}, err
	}
	return service.passkeys.BeginAccountRegistration(ctx, registration.User.ID, label, []byte(registrationToken))
}

type FinishResult struct {
	User              auth.User
	Organization      organizations.Organization
	RecoveryCodes     []string
	SessionToken      string
	Principal         auth.Principal
	PasskeyCredential authwebauthn.Credential
}

// FinishPassword activates a base account without requiring WebAuthn. The
// application can require an operation-bound passkey assertion later for
// sensitive permissions.
func (service *Service) FinishPassword(ctx context.Context, registrationToken string) (FinishResult, error) {
	registration, err := service.registration(ctx, registrationToken)
	if err != nil {
		return FinishResult{}, err
	}
	codes, recoveryDigests, err := authrecovery.GenerateCodeSet(service.random, service.codeCount)
	if err != nil {
		return FinishResult{}, err
	}
	completion, err := service.completion(registration, recoveryDigests)
	if err != nil {
		return FinishResult{}, err
	}
	completion.AuthAudit, err = service.authAudit(registration.User.ID, "auth.account.registration.complete", "The password-authenticated account registration was completed.")
	if err != nil {
		return FinishResult{}, err
	}
	if err = service.repository.CompleteRegistration(ctx, registration.Digest, completion); err != nil {
		return FinishResult{}, err
	}
	return service.finishSession(ctx, registration, completion, codes, authwebauthn.Credential{})
}

// FinishWithPasskey completes the same atomic account transaction while also
// storing a verified initial passkey.
func (service *Service) FinishWithPasskey(ctx context.Context, registrationToken, ceremonyToken string, response []byte) (FinishResult, error) {
	if service.passkeys == nil {
		return FinishResult{}, ErrPasskeysUnavailable
	}
	registration, err := service.registration(ctx, registrationToken)
	if err != nil {
		return FinishResult{}, err
	}
	codes, recoveryDigests, err := authrecovery.GenerateCodeSet(service.random, service.codeCount)
	if err != nil {
		return FinishResult{}, err
	}
	completion, err := service.completion(registration, recoveryDigests)
	if err != nil {
		return FinishResult{}, err
	}
	credential, err := service.passkeys.FinishAccountRegistration(ctx, ceremonyToken, []byte(registrationToken), response, func(commitCtx context.Context, verified authwebauthn.Credential, passkeyAudit auth.AuditEvent) error {
		completion.Credential = &verified
		completion.AuthAudit = passkeyAudit
		return service.repository.CompleteRegistration(commitCtx, registration.Digest, completion)
	})
	if err != nil {
		return FinishResult{}, err
	}
	return service.finishSession(ctx, registration, completion, codes, credential)
}

func (service *Service) finishSession(ctx context.Context, registration Registration, completion RegistrationCompletion, codes []string, credential authwebauthn.Credential) (FinishResult, error) {
	user := registration.User
	user.RegistrationPending = false
	user.UpdatedAt = completion.CompletedAt
	result := FinishResult{User: user, Organization: completion.Organization, RecoveryCodes: codes, PasskeyCredential: credential}
	sessionToken, principal, err := service.sessions.IssueSession(ctx, user.ID, service.sessionTTL)
	if err != nil {
		// Registration is already durable. Preserve the one-time recovery codes
		// in the returned result so an application can display them while asking
		// the user to sign in again.
		return result, fmt.Errorf("account: registration completed but session issuance failed: %w", err)
	}
	result.SessionToken, result.Principal = sessionToken, principal
	return result, nil
}

func (service *Service) completion(registration Registration, recoveryDigests [][32]byte) (RegistrationCompletion, error) {
	organizationID, err := service.token(18)
	if err != nil {
		return RegistrationCompletion{}, err
	}
	bindingID, err := service.token(18)
	if err != nil {
		return RegistrationCompletion{}, err
	}
	slugBytes := make([]byte, 6)
	if _, err = io.ReadFull(service.random, slugBytes); err != nil {
		return RegistrationCompletion{}, fmt.Errorf("account: secure randomness unavailable: %w", err)
	}
	now := service.now().UTC()
	organization := organizations.Organization{ID: organizationID, Slug: "personal-" + hex.EncodeToString(slugBytes), Name: registration.User.DisplayName + " — Personal", Status: "active", Personal: true, Revision: 1, CreatedAt: now, UpdatedAt: now}
	membership := organizations.Membership{OrganizationID: organizationID, UserID: registration.User.ID, Status: "active", JoinedAt: now}
	binding := access.Binding{ID: bindingID, SubjectKind: access.User, SubjectID: registration.User.ID, Role: service.ownerRole, Scope: access.Scope{OrganizationID: organizationID}, GrantedBy: registration.User.ID, GrantedAt: now}
	organizationAuditID, err := service.token(18)
	if err != nil {
		return RegistrationCompletion{}, err
	}
	accessAuditID, err := service.token(18)
	if err != nil {
		return RegistrationCompletion{}, err
	}
	return RegistrationCompletion{
		RecoveryDigests:   recoveryDigests,
		Organization:      organization,
		Membership:        membership,
		OwnerBinding:      binding,
		OrganizationAudit: organizations.AuditEvent{ID: organizationAuditID, OrganizationID: organizationID, ActorUserID: registration.User.ID, Action: "organization.personal.create", ResourceType: "organization", ResourceID: organizationID, Summary: "Personal organization created during account registration.", CreatedAt: now},
		AccessAudit:       access.AuditEvent{ID: accessAuditID, OrganizationID: organizationID, ActorUserID: registration.User.ID, Action: "access.owner.grant", ResourceType: "user", ResourceID: registration.User.ID, Summary: "Initial personal-organization owner access granted.", CreatedAt: now},
		CompletedAt:       now,
	}, nil
}

func (service *Service) registration(ctx context.Context, raw string) (Registration, error) {
	if len(raw) < 32 || len(raw) > 128 {
		return Registration{}, ErrRegistrationNotFound
	}
	if _, err := base64.RawURLEncoding.DecodeString(raw); err != nil {
		return Registration{}, ErrRegistrationNotFound
	}
	return service.repository.Registration(ctx, sha256.Sum256([]byte(raw)), service.now().UTC())
}

func (service *Service) authAudit(userID, action, summary string) (auth.AuditEvent, error) {
	id, err := service.token(18)
	if err != nil {
		return auth.AuditEvent{}, err
	}
	return auth.AuditEvent{ID: id, ActorUserID: userID, Action: action, ResourceType: "user", ResourceID: userID, Summary: summary, CreatedAt: service.now().UTC()}, nil
}

func (service *Service) token(size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(service.random, value); err != nil {
		return "", fmt.Errorf("account: secure randomness unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func canonicalEmail(value string) (string, error) {
	value = strings.ToLower(strings.TrimSpace(value))
	parsed, err := mail.ParseAddress(value)
	if err != nil || parsed.Address != value || len(value) > 320 || strings.ContainsAny(value, "\x00\r\n") {
		return "", errors.New("account: a valid email address is required")
	}
	return value, nil
}

func roleName(value string) bool {
	if len(value) < 2 || len(value) > 128 || value[0] < 'a' || value[0] > 'z' {
		return false
	}
	for _, character := range value[1:] {
		if character < 'a' || character > 'z' && (character < '0' || character > '9') && character != '.' && character != '_' && character != '-' {
			return false
		}
	}
	return true
}
