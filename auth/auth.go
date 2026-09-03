// SPDX-License-Identifier: MPL-2.0

// Package auth defines storage-neutral users, credentials, opaque sessions,
// permissions, and audit events. Applications retain authorization policy.
package auth

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sort"
	"strings"
	"time"
)

var (
	ErrInvalidCredentials = errors.New("auth: invalid credentials")
	ErrInactiveUser       = errors.New("auth: account is not active")
	ErrPasswordUnchanged  = errors.New("auth: new password must differ from the current password")
	ErrSessionNotFound    = errors.New("auth: session not found")
	ErrUserNotFound       = errors.New("auth: user not found")
	identifierPattern     = regexp.MustCompile(`^[A-Za-z0-9][A-Za-z0-9_.-]{2,63}$`)
)

type User struct {
	ID, Username, Email, DisplayName, Status string
	CreatedAt, UpdatedAt                     time.Time
	PasswordChangeRequired                   bool
	// RegistrationPending keeps a partially completed public registration
	// ineligible for authentication until its credentials, personal scope, and
	// recovery material have been committed atomically.
	RegistrationPending bool
}

func (user User) Active() bool { return user.Status == "active" && !user.RegistrationPending }

type Principal struct {
	User        User
	Roles       []string
	Permissions map[string]bool
}

func (principal Principal) Has(permission string) bool { return principal.Permissions[permission] }

type Session struct {
	Digest                           [32]byte
	UserID                           string
	CreatedAt, ExpiresAt, LastSeenAt time.Time
}

type AuditEvent struct {
	ID, ActorUserID, Action, ResourceType, ResourceID, RequestID, Summary string
	CreatedAt                                                             time.Time
}

type PolicySeed struct {
	Roles           map[string]string
	Permissions     map[string]string
	RolePermissions map[string][]string
}

type Repository interface {
	CreateUser(context.Context, User, string) error
	CredentialByIdentifier(context.Context, string) (User, string, error)
	CredentialByUserID(context.Context, string) (User, string, error)
	ReplacePasswordAndRevokeSessions(context.Context, string, string, string, time.Time) error
	ResetPasswordAndRevokeSessions(context.Context, string, string, string, time.Time, AuditEvent) error
	UpdateLastLogin(context.Context, string, time.Time) error
	CreateSession(context.Context, Session) error
	PrincipalBySession(context.Context, [32]byte, time.Time) (Principal, Session, error)
	TouchSession(context.Context, [32]byte, time.Time) error
	DeleteSession(context.Context, [32]byte) error
	RevokeUserSessions(context.Context, string) error
	SeedPolicy(context.Context, PolicySeed) error
	GrantRole(context.Context, string, string, time.Time) error
	AppendAudit(context.Context, AuditEvent) error
}

type Service struct {
	repository    Repository
	random        io.Reader
	now           func() time.Time
	touchInterval time.Duration
}

type Options struct {
	Random        io.Reader
	Now           func() time.Time
	TouchInterval time.Duration
}

func New(repository Repository, options Options) (*Service, error) {
	if repository == nil {
		return nil, errors.New("auth: repository is required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.TouchInterval == 0 {
		options.TouchInterval = 5 * time.Minute
	}
	if options.TouchInterval < time.Minute || options.TouchInterval > time.Hour {
		return nil, errors.New("auth: invalid session touch interval")
	}
	return &Service{repository: repository, random: options.Random, now: options.Now, touchInterval: options.TouchInterval}, nil
}

type CreateUser struct {
	Username, Email, DisplayName, Password string
	RequirePasswordChange                  bool
}

// AdministrativePasswordReset describes a locally authorized recovery. The
// application is responsible for delivering TemporaryPassword through a
// private, one-time channel; the value must never be logged or audited.
type AdministrativePasswordReset struct {
	Identifier, TemporaryPassword string
}

func (service *Service) CreateUser(ctx context.Context, input CreateUser) (User, error) {
	username := strings.TrimSpace(input.Username)
	email := strings.TrimSpace(input.Email)
	displayName := strings.TrimSpace(input.DisplayName)
	if !identifierPattern.MatchString(username) || email == "" || len(email) > 320 || !strings.Contains(email, "@") || displayName == "" || len(displayName) > 128 {
		return User{}, errors.New("auth: invalid user")
	}
	hash, err := HashPasswordWithRandom(input.Password, service.random)
	if err != nil {
		return User{}, err
	}
	id, err := randomToken(service.random, 18)
	if err != nil {
		return User{}, err
	}
	now := service.now().UTC()
	user := User{ID: id, Username: username, Email: email, DisplayName: displayName, Status: "active", CreatedAt: now, UpdatedAt: now, PasswordChangeRequired: input.RequirePasswordChange}
	if err = service.repository.CreateUser(ctx, user, hash); err != nil {
		return User{}, err
	}
	return user, nil
}

// GenerateTemporaryPassword returns 256 bits of URL-safe cryptographic
// entropy suitable for an application-managed one-time bootstrap credential.
func GenerateTemporaryPassword(random io.Reader) (string, error) {
	if random == nil {
		random = rand.Reader
	}
	return randomToken(random, 32)
}

// ChangePassword verifies the current credential, rejects reuse, replaces the
// Argon2id hash, clears the password-change requirement, and revokes every
// existing session through one repository operation.
func (service *Service) ChangePassword(ctx context.Context, userID, currentPassword, newPassword string) error {
	user, currentHash, err := service.repository.CredentialByUserID(ctx, strings.TrimSpace(userID))
	if errors.Is(err, ErrUserNotFound) {
		_ = VerifyPassword(dummyPasswordHash, currentPassword)
		return ErrInvalidCredentials
	}
	if err != nil {
		_ = VerifyPassword(dummyPasswordHash, currentPassword)
		return fmt.Errorf("auth: load credentials: %w", err)
	}
	if !VerifyPassword(currentHash, currentPassword) {
		return ErrInvalidCredentials
	}
	if !user.Active() {
		return ErrInactiveUser
	}
	if currentPassword == newPassword {
		return ErrPasswordUnchanged
	}
	newHash, err := HashPasswordWithRandom(newPassword, service.random)
	if err != nil {
		return err
	}
	if err = service.repository.ReplacePasswordAndRevokeSessions(ctx, user.ID, currentHash, newHash, service.now().UTC()); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return ErrInvalidCredentials
		}
		return fmt.Errorf("auth: replace password: %w", err)
	}
	return nil
}

// ResetPassword replaces an active user's credential without requiring the
// current password. It is intended only for a locally authorized
// administrative recovery command. The repository atomically requires another
// password change, revokes all sessions, and appends a secret-free audit event.
func (service *Service) ResetPassword(ctx context.Context, input AdministrativePasswordReset) (User, error) {
	identifier := strings.TrimSpace(input.Identifier)
	user, currentHash, err := service.repository.CredentialByIdentifier(ctx, identifier)
	if errors.Is(err, ErrUserNotFound) {
		return User{}, ErrUserNotFound
	}
	if err != nil {
		return User{}, fmt.Errorf("auth: load credentials for administrative reset: %w", err)
	}
	if !user.Active() {
		return User{}, ErrInactiveUser
	}
	if VerifyPassword(currentHash, input.TemporaryPassword) {
		return User{}, ErrPasswordUnchanged
	}
	newHash, err := HashPasswordWithRandom(input.TemporaryPassword, service.random)
	if err != nil {
		return User{}, err
	}
	auditID, err := randomToken(service.random, 18)
	if err != nil {
		return User{}, err
	}
	now := service.now().UTC()
	audit := AuditEvent{
		ID:           auditID,
		Action:       "auth.password.reset",
		ResourceType: "user",
		ResourceID:   user.ID,
		Summary:      "A local administrator issued a one-time credential and revoked all sessions.",
		CreatedAt:    now,
	}
	if err = service.repository.ResetPasswordAndRevokeSessions(ctx, user.ID, currentHash, newHash, now, audit); err != nil {
		if errors.Is(err, ErrInvalidCredentials) {
			return User{}, ErrInvalidCredentials
		}
		return User{}, fmt.Errorf("auth: reset password: %w", err)
	}
	user.PasswordChangeRequired = true
	user.UpdatedAt = now
	return user, nil
}

// VerifyPassword verifies the password credential for an active account
// without creating a session. Applications use it as the first step of a
// bounded multi-factor ceremony and must not treat success as an authenticated
// browser session on its own.
func (service *Service) VerifyPassword(ctx context.Context, identifier, password string) (User, error) {
	user, hash, err := service.repository.CredentialByIdentifier(ctx, strings.TrimSpace(identifier))
	if errors.Is(err, ErrUserNotFound) {
		_ = VerifyPassword(dummyPasswordHash, password)
		return User{}, ErrInvalidCredentials
	}
	if err != nil {
		_ = VerifyPassword(dummyPasswordHash, password)
		return User{}, fmt.Errorf("auth: load credentials: %w", err)
	}
	if !VerifyPassword(hash, password) {
		return User{}, ErrInvalidCredentials
	}
	if !user.Active() {
		return User{}, ErrInactiveUser
	}
	return user, nil
}

func (service *Service) Authenticate(ctx context.Context, identifier, password string, lifetime time.Duration) (string, Principal, error) {
	if lifetime < 5*time.Minute || lifetime > 30*24*time.Hour {
		return "", Principal{}, errors.New("auth: invalid session lifetime")
	}
	user, err := service.VerifyPassword(ctx, identifier, password)
	if err != nil {
		return "", Principal{}, err
	}
	return service.IssueSession(ctx, user.ID, lifetime)
}

// IssueSession creates an opaque session for an already authenticated user.
// Authentication mechanisms such as passkeys call this only after completing
// their credential verification. The repository remains authoritative for the
// account's current status and permissions.
func (service *Service) IssueSession(ctx context.Context, userID string, lifetime time.Duration) (string, Principal, error) {
	if lifetime < 5*time.Minute || lifetime > 30*24*time.Hour {
		return "", Principal{}, errors.New("auth: invalid session lifetime")
	}
	userID = strings.TrimSpace(userID)
	if !opaqueID(userID) {
		return "", Principal{}, errors.New("auth: invalid user id")
	}
	token, err := randomToken(service.random, 32)
	if err != nil {
		return "", Principal{}, err
	}
	now := service.now().UTC()
	digest := sha256.Sum256([]byte(token))
	if err = service.repository.CreateSession(ctx, Session{Digest: digest, UserID: userID, CreatedAt: now, ExpiresAt: now.Add(lifetime), LastSeenAt: now}); err != nil {
		return "", Principal{}, err
	}
	_ = service.repository.UpdateLastLogin(ctx, userID, now)
	principal, _, err := service.repository.PrincipalBySession(ctx, digest, now)
	if err != nil {
		_ = service.repository.DeleteSession(ctx, digest)
		return "", Principal{}, err
	}
	if !principal.User.Active() {
		_ = service.repository.DeleteSession(ctx, digest)
		return "", Principal{}, ErrInactiveUser
	}
	return token, principal, nil
}

func (service *Service) Session(ctx context.Context, token string) (Principal, error) {
	if len(token) < 32 || len(token) > 128 {
		return Principal{}, ErrSessionNotFound
	}
	digest := sha256.Sum256([]byte(token))
	now := service.now().UTC()
	principal, session, err := service.repository.PrincipalBySession(ctx, digest, now)
	if errors.Is(err, ErrSessionNotFound) {
		return Principal{}, ErrSessionNotFound
	}
	if err != nil {
		return Principal{}, fmt.Errorf("auth: load session: %w", err)
	}
	if !principal.User.Active() {
		_ = service.repository.DeleteSession(ctx, digest)
		return Principal{}, ErrInactiveUser
	}
	if now.Sub(session.LastSeenAt) >= service.touchInterval {
		_ = service.repository.TouchSession(ctx, digest, now)
	}
	principal.Roles = sortedUnique(principal.Roles)
	if principal.Permissions == nil {
		principal.Permissions = map[string]bool{}
	}
	return principal, nil
}

func (service *Service) RevokeSession(ctx context.Context, token string) error {
	if len(token) < 32 || len(token) > 128 {
		return ErrSessionNotFound
	}
	digest := sha256.Sum256([]byte(token))
	return service.repository.DeleteSession(ctx, digest)
}
func (service *Service) RevokeUserSessions(ctx context.Context, userID string) error {
	return service.repository.RevokeUserSessions(ctx, userID)
}
func (service *Service) Repository() Repository { return service.repository }

func randomToken(random io.Reader, bytes int) (string, error) {
	value := make([]byte, bytes)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", fmt.Errorf("auth: secure randomness unavailable: %w", err)
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}

func opaqueID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func sortedUnique(values []string) []string {
	set := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value != "" {
			set[value] = struct{}{}
		}
	}
	result := make([]string, 0, len(set))
	for value := range set {
		result = append(result, value)
	}
	sort.Strings(result)
	return result
}
