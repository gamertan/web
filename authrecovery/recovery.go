// SPDX-License-Identifier: MPL-2.0

// Package authrecovery provides printable one-time recovery codes and bounded
// recovery grants for password-plus-passkey accounts.
package authrecovery

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base32"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"strings"
	"time"

	"gamertan.com/web/auth"
)

const DefaultCodeCount = 10

var (
	ErrCodeNotFound  = errors.New("authrecovery: recovery code not found")
	ErrGrantNotFound = errors.New("authrecovery: recovery grant not found")
)

type Grant struct {
	Digest    [32]byte
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Repository interface {
	ReplaceRecoveryCodes(context.Context, string, [][32]byte, time.Time, auth.AuditEvent) error
	ConsumeRecoveryCodeAndCreateGrant(context.Context, string, [32]byte, Grant, auth.AuditEvent) error
	TakeRecoveryGrant(context.Context, [32]byte, time.Time) (auth.User, error)
}

type PasswordVerifier interface {
	VerifyPassword(context.Context, string, string) (auth.User, error)
}

type Options struct {
	Random        io.Reader
	Now           func() time.Time
	CodeCount     int
	GrantLifetime time.Duration
}

type Service struct {
	repository Repository
	passwords  PasswordVerifier
	random     io.Reader
	now        func() time.Time
	count      int
	grantTTL   time.Duration
}

func New(repository Repository, passwords PasswordVerifier, options Options) (*Service, error) {
	if repository == nil || passwords == nil {
		return nil, errors.New("authrecovery: repository and password verifier are required")
	}
	if options.Random == nil {
		options.Random = rand.Reader
	}
	if options.Now == nil {
		options.Now = time.Now
	}
	if options.CodeCount == 0 {
		options.CodeCount = DefaultCodeCount
	}
	if options.GrantLifetime == 0 {
		options.GrantLifetime = 10 * time.Minute
	}
	if options.CodeCount < 5 || options.CodeCount > 20 || options.GrantLifetime < 2*time.Minute || options.GrantLifetime > 30*time.Minute {
		return nil, errors.New("authrecovery: invalid recovery policy")
	}
	return &Service{repository: repository, passwords: passwords, random: options.Random, now: options.Now, count: options.CodeCount, grantTTL: options.GrantLifetime}, nil
}

// ReplaceCodes creates a complete new recovery-code set. Codes are returned
// once; only domain-separated digests are persisted.
func (service *Service) ReplaceCodes(ctx context.Context, userID, actorUserID string) ([]string, error) {
	codes, digests, err := GenerateCodeSet(service.random, service.count)
	if err != nil {
		return nil, err
	}
	now := service.now().UTC()
	auditID, err := token(service.random, 18)
	if err != nil {
		return nil, err
	}
	audit := auth.AuditEvent{ID: auditID, ActorUserID: actorUserID, Action: "auth.recovery-codes.replace", ResourceType: "user", ResourceID: userID, Summary: "The account recovery-code set was replaced.", CreatedAt: now}
	if err = service.repository.ReplaceRecoveryCodes(ctx, userID, digests, now, audit); err != nil {
		return nil, err
	}
	return codes, nil
}

// Begin verifies the password, atomically consumes one code, revokes sessions,
// and returns a short-lived grant. Applications bind the grant to the passkey
// replacement ceremony and do not issue a normal session from it.
func (service *Service) Begin(ctx context.Context, identifier, password, code string) (auth.User, string, error) {
	user, err := service.passwords.VerifyPassword(ctx, identifier, password)
	if err != nil {
		return auth.User{}, "", err
	}
	digest, err := DigestCode(code)
	if err != nil {
		return auth.User{}, "", auth.ErrInvalidCredentials
	}
	rawGrant, err := token(service.random, 32)
	if err != nil {
		return auth.User{}, "", err
	}
	now := service.now().UTC()
	grant := Grant{Digest: sha256.Sum256([]byte(rawGrant)), UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(service.grantTTL)}
	auditID, err := token(service.random, 18)
	if err != nil {
		return auth.User{}, "", err
	}
	audit := auth.AuditEvent{ID: auditID, ActorUserID: user.ID, Action: "auth.recovery.begin", ResourceType: "user", ResourceID: user.ID, Summary: "A recovery code was consumed and existing sessions were revoked.", CreatedAt: now}
	if err = service.repository.ConsumeRecoveryCodeAndCreateGrant(ctx, user.ID, digest, grant, audit); err != nil {
		if errors.Is(err, ErrCodeNotFound) {
			return auth.User{}, "", auth.ErrInvalidCredentials
		}
		return auth.User{}, "", err
	}
	return user, rawGrant, nil
}

func (service *Service) TakeGrant(ctx context.Context, raw string) (auth.User, error) {
	if len(raw) < 32 || len(raw) > 128 {
		return auth.User{}, ErrGrantNotFound
	}
	return service.repository.TakeRecoveryGrant(ctx, sha256.Sum256([]byte(raw)), service.now().UTC())
}

func GenerateCodeSet(random io.Reader, count int) ([]string, [][32]byte, error) {
	if random == nil || count < 1 || count > 20 {
		return nil, nil, errors.New("authrecovery: invalid code-set request")
	}
	codes := make([]string, 0, count)
	digests := make([][32]byte, 0, count)
	seen := make(map[[32]byte]struct{}, count)
	for len(codes) < count {
		value := make([]byte, 16)
		if _, err := io.ReadFull(random, value); err != nil {
			return nil, nil, fmt.Errorf("authrecovery: secure randomness unavailable: %w", err)
		}
		encoded := base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(value)
		code := strings.Join([]string{encoded[0:5], encoded[5:10], encoded[10:15], encoded[15:20], encoded[20:26]}, "-")
		digest, _ := DigestCode(code)
		if _, duplicate := seen[digest]; duplicate {
			continue
		}
		seen[digest] = struct{}{}
		codes = append(codes, code)
		digests = append(digests, digest)
	}
	return codes, digests, nil
}

func DigestCode(code string) ([32]byte, error) {
	normalized := strings.ToUpper(strings.ReplaceAll(strings.ReplaceAll(strings.TrimSpace(code), "-", ""), " ", ""))
	decoded, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(normalized)
	if err != nil || len(decoded) != 16 {
		return [32]byte{}, ErrCodeNotFound
	}
	return sha256.Sum256(append([]byte("gamertan-web-recovery-code-v1\x00"), decoded...)), nil
}

func token(random io.Reader, size int) (string, error) {
	value := make([]byte, size)
	if _, err := io.ReadFull(random, value); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(value), nil
}
