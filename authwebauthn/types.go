// SPDX-License-Identifier: MPL-2.0

// Package authwebauthn provides storage-neutral, passkey-only WebAuthn
// ceremonies. It owns relying-party policy, bounded single-use ceremony state,
// credential lifecycle, and recovery tokens while delegating protocol parsing
// and signature verification to a pinned WebAuthn implementation.
package authwebauthn

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"time"

	"gamertan.com/web/auth"
)

var (
	ErrCeremonyNotFound      = errors.New("authwebauthn: ceremony not found")
	ErrCredentialNotFound    = errors.New("authwebauthn: credential not found")
	ErrEnrollmentNotFound    = errors.New("authwebauthn: enrollment token not found")
	ErrCredentialFloor       = errors.New("authwebauthn: the required credential floor cannot be crossed")
	ErrLastCredential        = errors.New("authwebauthn: the last credential cannot be removed remotely")
	ErrOperationBinding      = errors.New("authwebauthn: operation binding does not match")
	ErrPasskeyReadiness      = errors.New("authwebauthn: at least two passkeys are required")
	ErrUnsupportedCredential = errors.New("authwebauthn: credential algorithm is unsupported")
)

const (
	CeremonyRegistration = "registration"
	CeremonyLogin        = "login"
	CeremonyApproval     = "approval"
)

type Credential struct {
	ID         []byte
	UserID     string
	Label      string
	Data       json.RawMessage
	CreatedAt  time.Time
	LastUsedAt time.Time
}

// CredentialSummary is the non-secret credential metadata applications may
// show to an authenticated account owner. It intentionally excludes the
// stored public-key document and user identifier.
type CredentialSummary struct {
	ID         []byte
	Label      string
	CreatedAt  time.Time
	LastUsedAt time.Time
}

type EnrollmentToken struct {
	Digest    [32]byte
	UserID    string
	CreatedAt time.Time
	ExpiresAt time.Time
}

type Ceremony struct {
	Digest        [32]byte
	Kind          string
	UserID        string
	Label         string
	SessionData   json.RawMessage
	BindingDigest [32]byte
	CreatedAt     time.Time
	ExpiresAt     time.Time
}

type BeginResult struct {
	CeremonyToken string          `json:"ceremony_token"`
	PublicKey     json.RawMessage `json:"public_key"`
	ExpiresAt     time.Time       `json:"expires_at"`
}

type Authentication struct {
	SessionToken string
	Principal    auth.Principal
	CredentialID []byte
	CloneWarning bool
}

type Approval struct {
	User          auth.User
	CredentialID  []byte
	BindingDigest [32]byte
	CloneWarning  bool
	ApprovedAt    time.Time
}

// Repository persists passkey-specific state. Implementations must consume
// enrollment tokens and ceremonies atomically and must perform recovery and
// credential removal invariants in transactions.
type Repository interface {
	CreatePasskeyUser(context.Context, auth.User, EnrollmentToken, auth.AuditEvent) error
	UserByID(context.Context, string) (auth.User, error)
	UserByIdentifier(context.Context, string) (auth.User, error)
	UserByCredentialID(context.Context, []byte) (auth.User, error)
	CredentialsByUserID(context.Context, string) ([]Credential, error)
	SaveCredential(context.Context, Credential, auth.AuditEvent) error
	UpdateCredential(context.Context, Credential) error
	DeleteCredential(context.Context, string, []byte, int, auth.AuditEvent) error
	CredentialCount(context.Context, string) (int, error)
	CreateCeremony(context.Context, Ceremony) error
	TakeCeremony(context.Context, [32]byte, time.Time) (Ceremony, error)
	ConsumeEnrollmentToken(context.Context, [32]byte, time.Time) (auth.User, error)
	RecoverUser(context.Context, string, EnrollmentToken, auth.AuditEvent) (auth.User, error)
}

func BindingDigest(value []byte) [32]byte { return sha256.Sum256(value) }
