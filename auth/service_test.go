// SPDX-License-Identifier: MPL-2.0

package auth

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestSessionDistinguishesMissingFromUnavailableStorage(t *testing.T) {
	service, err := New(repositoryStub{sessionErr: ErrSessionNotFound}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Session(t.Context(), strings.Repeat("x", 43)); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("missing err=%v", err)
	}

	storageErr := errors.New("storage offline")
	service, err = New(repositoryStub{sessionErr: storageErr}, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.Session(t.Context(), strings.Repeat("x", 43)); !errors.Is(err, storageErr) || errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("storage err=%v", err)
	}
}

func TestRevokeSessionRejectsInvalidTokenBeforeStorage(t *testing.T) {
	repository := &recordingRepository{}
	service, err := New(repository, Options{})
	if err != nil {
		t.Fatal(err)
	}
	if err = service.RevokeSession(t.Context(), "short"); !errors.Is(err, ErrSessionNotFound) {
		t.Fatalf("err=%v", err)
	}
	if repository.deleted {
		t.Fatal("storage called for invalid token")
	}
}

type recordingRepository struct {
	repositoryStub
	deleted bool
}

func (repository *recordingRepository) DeleteSession(context.Context, [32]byte) error {
	repository.deleted = true
	return nil
}

type repositoryStub struct{ sessionErr error }

func (repositoryStub) CreateUser(context.Context, User, string) error { return nil }
func (repositoryStub) CredentialByIdentifier(context.Context, string) (User, string, error) {
	return User{}, "", ErrUserNotFound
}
func (repositoryStub) CredentialByUserID(context.Context, string) (User, string, error) {
	return User{}, "", ErrUserNotFound
}
func (repositoryStub) ReplacePasswordAndRevokeSessions(context.Context, string, string, string, time.Time) error {
	return nil
}
func (repositoryStub) ResetPasswordAndRevokeSessions(context.Context, string, string, string, time.Time, AuditEvent) error {
	return nil
}
func (repositoryStub) UpdateLastLogin(context.Context, string, time.Time) error { return nil }
func (repositoryStub) CreateSession(context.Context, Session) error             { return nil }
func (repository repositoryStub) PrincipalBySession(context.Context, [32]byte, time.Time) (Principal, Session, error) {
	return Principal{}, Session{}, repository.sessionErr
}
func (repositoryStub) TouchSession(context.Context, [32]byte, time.Time) error { return nil }
func (repositoryStub) DeleteSession(context.Context, [32]byte) error           { return nil }
func (repositoryStub) RevokeUserSessions(context.Context, string) error        { return nil }
func (repositoryStub) SeedPolicy(context.Context, PolicySeed) error            { return nil }
func (repositoryStub) GrantRole(context.Context, string, string, time.Time) error {
	return nil
}
func (repositoryStub) AppendAudit(context.Context, AuditEvent) error { return nil }
