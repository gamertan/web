// SPDX-License-Identifier: MPL-2.0

package authrecovery_test

import (
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/auth"
	"gamertan.com/web/authrecovery"
	"gamertan.com/web/authsqlite"
)

func TestRecoveryCodeIsSingleUseAndRevokesSessions(t *testing.T) {
	now := time.Date(2026, 9, 3, 12, 0, 0, 0, time.UTC)
	store, err := authsqlite.Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	random := &counterReader{}
	authService, err := auth.New(store, auth.Options{Random: random, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	user, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "recover.person", Email: "recover@example.test", DisplayName: "Recover Person", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	recovery, err := authrecovery.New(store, authService, authrecovery.Options{Random: random, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	codes, err := recovery.ReplaceCodes(t.Context(), user.ID, user.ID)
	if err != nil || len(codes) != authrecovery.DefaultCodeCount {
		t.Fatalf("codes=%d err=%v", len(codes), err)
	}
	session, _, err := authService.IssueSession(t.Context(), user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	loaded, grant, err := recovery.Begin(t.Context(), strings.ToUpper(user.Email), "correct horse battery staple", strings.ToLower(codes[0]))
	if err != nil || loaded.ID != user.ID || grant == "" {
		t.Fatalf("loaded=%+v grant=%q err=%v", loaded, grant, err)
	}
	if _, err = authService.Session(t.Context(), session); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("session survived recovery: %v", err)
	}
	if _, _, err = recovery.Begin(t.Context(), user.Email, "correct horse battery staple", codes[0]); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("code replay err=%v", err)
	}
	loaded, err = recovery.TakeGrant(t.Context(), grant)
	if err != nil || loaded.ID != user.ID {
		t.Fatalf("grant user=%+v err=%v", loaded, err)
	}
	if _, err = recovery.TakeGrant(t.Context(), grant); !errors.Is(err, authrecovery.ErrGrantNotFound) {
		t.Fatalf("grant replay err=%v", err)
	}
}

type counterReader struct{ value byte }

func (reader *counterReader) Read(target []byte) (int, error) {
	for index := range target {
		reader.value++
		target[index] = reader.value
	}
	return len(target), nil
}
