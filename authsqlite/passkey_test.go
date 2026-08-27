// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"bytes"
	"encoding/json"
	"errors"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	wa "gamertan.com/web/internal/webauthnvendored/webauthn"

	"gamertan.com/web/auth"
	"gamertan.com/web/authwebauthn"
)

func TestPasskeyCredentialDeletionPreservesConfiguredFloor(t *testing.T) {
	store, err := Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	user := auth.User{ID: "passkey-user-id", Username: "passkey.user", Email: "passkey@example.test", DisplayName: "Passkey User", Status: "active", CreatedAt: now, UpdatedAt: now}
	enrollment := authwebauthn.EnrollmentToken{Digest: [32]byte{1}, UserID: user.ID, CreatedAt: now, ExpiresAt: now.Add(time.Minute)}
	if err = store.CreatePasskeyUser(t.Context(), user, enrollment, testAudit("bootstrap-audit", "auth.passkey.bootstrap", user.ID, now)); err != nil {
		t.Fatal(err)
	}
	ids := [][]byte{bytes.Repeat([]byte{1}, 32), bytes.Repeat([]byte{2}, 32), bytes.Repeat([]byte{3}, 32)}
	for index, id := range ids {
		encoded, marshalErr := json.Marshal(wa.Credential{ID: id, PublicKey: []byte{1, 2, 3}})
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		credential := authwebauthn.Credential{ID: id, UserID: user.ID, Label: "Credential", Data: encoded, CreatedAt: now}
		if err = store.SaveCredential(t.Context(), credential, testAudit("add-audit-"+string(rune('a'+index)), "auth.passkey.add", user.ID, now)); err != nil {
			t.Fatal(err)
		}
	}
	if err = store.DeleteCredential(t.Context(), user.ID, ids[0], 2, testAudit("delete-audit", "auth.passkey.remove", user.ID, now)); err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteCredential(t.Context(), user.ID, ids[1], 2, testAudit("delete-floor", "auth.passkey.remove", user.ID, now)); !errors.Is(err, authwebauthn.ErrCredentialFloor) {
		t.Fatalf("credential floor err=%v", err)
	}
	if err = store.DeleteCredential(t.Context(), user.ID, ids[1], 1, testAudit("delete-second", "auth.passkey.remove", user.ID, now)); err != nil {
		t.Fatal(err)
	}
	if err = store.DeleteCredential(t.Context(), user.ID, ids[2], 1, testAudit("delete-last", "auth.passkey.remove", user.ID, now)); !errors.Is(err, authwebauthn.ErrLastCredential) {
		t.Fatalf("last credential err=%v", err)
	}
}

func TestPasskeyCeremonyIsConsumedExactlyOnceConcurrently(t *testing.T) {
	store, err := Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	digest := [32]byte{1, 2, 3}
	if err = store.CreateCeremony(t.Context(), authwebauthn.Ceremony{Digest: digest, Kind: authwebauthn.CeremonyLogin, SessionData: []byte(`{"challenge":"example"}`), CreatedAt: now, ExpiresAt: now.Add(time.Minute)}); err != nil {
		t.Fatal(err)
	}
	var successes atomic.Int32
	unexpected := make(chan error, 16)
	var group sync.WaitGroup
	for range 16 {
		group.Add(1)
		go func() {
			defer group.Done()
			_, takeErr := store.TakeCeremony(t.Context(), digest, now)
			if takeErr == nil {
				successes.Add(1)
				return
			}
			if !errors.Is(takeErr, authwebauthn.ErrCeremonyNotFound) {
				unexpected <- takeErr
			}
		}()
	}
	group.Wait()
	close(unexpected)
	for value := range unexpected {
		t.Fatalf("unexpected concurrent error: %v", value)
	}
	if successes.Load() != 1 {
		t.Fatalf("successful consumes=%d", successes.Load())
	}
}

func TestPasskeyMigrationAtomicallyRetiresPasswordAndSessions(t *testing.T) {
	store, err := Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	authService, err := auth.New(store, auth.Options{Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	user, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "migrate.me", Email: "migrate@example.test", DisplayName: "Migration Test", Password: "legacy password credential"})
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := authService.IssueSession(t.Context(), user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	id := bytes.Repeat([]byte{7}, 32)
	encoded, err := json.Marshal(wa.Credential{ID: id, PublicKey: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	credential := authwebauthn.Credential{ID: id, UserID: user.ID, Label: "Primary passkey", Data: encoded, CreatedAt: now}
	audit := auth.AuditEvent{ID: "migration-audit", ActorUserID: user.ID, Action: "auth.passkey.migrate", ResourceType: "passkey", ResourceID: "credential", Summary: "migration", CreatedAt: now}
	if err = store.SaveCredentialAndRetirePassword(t.Context(), credential, audit); err != nil {
		t.Fatal(err)
	}
	if exists, existsErr := store.PasswordCredentialExists(t.Context(), user.ID); existsErr != nil || exists {
		t.Fatalf("password exists=%v err=%v", exists, existsErr)
	}
	if _, _, err = authService.Authenticate(t.Context(), user.Username, "legacy password credential", time.Hour); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("legacy password still authenticates: %v", err)
	}
	if _, err = authService.Session(t.Context(), session); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("session survived migration: %v", err)
	}
	credentials, err := store.CredentialsByUserID(t.Context(), user.ID)
	if err != nil || len(credentials) != 1 || !bytes.Equal(credentials[0].ID, id) {
		t.Fatalf("credentials=%+v err=%v", credentials, err)
	}
	if err = store.SaveCredentialAndRetirePassword(t.Context(), credential, audit); !errors.Is(err, authwebauthn.ErrPasswordNotAvailable) {
		t.Fatalf("migration replay err=%v", err)
	}
}

func testAudit(id, action, resourceID string, now time.Time) auth.AuditEvent {
	return auth.AuditEvent{ID: id, Action: action, ResourceType: "user", ResourceID: resourceID, Summary: "test", CreatedAt: now}
}
