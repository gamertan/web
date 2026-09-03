// SPDX-License-Identifier: MPL-2.0

package authrecovery_test

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/auth"
	"gamertan.com/web/authrecovery"
	"gamertan.com/web/authsqlite"
	"gamertan.com/web/authwebauthn"
	wa "gamertan.com/web/internal/webauthnvendored/webauthn"
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

func TestPasskeyRecoveryAtomicallyReplacesCodesWithoutIssuingSession(t *testing.T) {
	now := time.Date(2026, 9, 3, 13, 0, 0, 0, time.UTC)
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
	user, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "recover.passkey", Email: "recover-passkey@example.test", DisplayName: "Recover Passkey", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	existingID := bytes.Repeat([]byte{7}, 32)
	existingJSON, err := json.Marshal(wa.Credential{ID: existingID, PublicKey: []byte{1, 2, 3}})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SaveCredential(t.Context(), authwebauthn.Credential{ID: existingID, UserID: user.ID, Label: "Existing passkey", Data: existingJSON, CreatedAt: now}, auth.AuditEvent{ID: "existing-passkey-audit", ActorUserID: user.ID, Action: "auth.passkey.add", ResourceType: "passkey", ResourceID: base64.RawURLEncoding.EncodeToString(existingID), Summary: "Existing passkey fixture.", CreatedAt: now}); err != nil {
		t.Fatal(err)
	}
	passkeys := &passkeyRecoveryStub{now: now, credentialID: existingID}
	recovery, err := authrecovery.New(store, authService, authrecovery.Options{Random: random, Now: func() time.Time { return now }, Passkeys: passkeys})
	if err != nil {
		t.Fatal(err)
	}
	oldCodes, err := recovery.ReplaceCodes(t.Context(), user.ID, user.ID)
	if err != nil {
		t.Fatal(err)
	}
	_, grant, err := recovery.Begin(t.Context(), user.Email, "correct horse battery staple", oldCodes[0])
	if err != nil {
		t.Fatal(err)
	}
	begin, err := recovery.BeginPasskey(t.Context(), grant, "Replacement passkey")
	if err != nil || begin.CeremonyToken == "" || passkeys.userID != user.ID || passkeys.beginBinding != grant {
		t.Fatalf("begin=%+v passkeys=%+v err=%v", begin, passkeys, err)
	}
	if _, err = recovery.FinishPasskey(t.Context(), grant, begin.CeremonyToken, []byte(`{"fixture":true}`)); err == nil {
		t.Fatal("duplicate credential unexpectedly committed")
	}
	if _, err = recovery.BeginPasskey(t.Context(), grant, "Retry replacement"); err != nil {
		t.Fatalf("failed completion consumed recovery grant: %v", err)
	}
	lateSession, _, err := authService.IssueSession(t.Context(), user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	passkeys.credentialID = bytes.Repeat([]byte{8}, 32)
	result, err := recovery.FinishPasskey(t.Context(), grant, "retry-ceremony-token", []byte(`{"fixture":true}`))
	if err != nil || len(result.RecoveryCodes) != authrecovery.DefaultCodeCount || !bytes.Equal(result.Credential.ID, passkeys.credentialID) {
		t.Fatalf("result=%+v err=%v", result, err)
	}
	if passkeys.finishBinding != grant {
		t.Fatal("finish ceremony was not bound to the restricted recovery grant")
	}
	if _, err = recovery.TakeGrant(t.Context(), grant); !errors.Is(err, authrecovery.ErrGrantNotFound) {
		t.Fatalf("completed grant replay err=%v", err)
	}
	if _, err = authService.Session(t.Context(), lateSession); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("session created during recovery survived completion: %v", err)
	}
	if _, _, err = recovery.Begin(t.Context(), user.Email, "correct horse battery staple", oldCodes[1]); !errors.Is(err, auth.ErrInvalidCredentials) {
		t.Fatalf("old recovery-code set survived completion: %v", err)
	}
	if _, newGrant, beginErr := recovery.Begin(t.Context(), user.Email, "correct horse battery staple", result.RecoveryCodes[0]); beginErr != nil || newGrant == "" {
		t.Fatalf("new recovery code unavailable: grant=%q err=%v", newGrant, beginErr)
	}
	credentials, err := store.CredentialsByUserID(t.Context(), user.ID)
	if err != nil || len(credentials) != 2 {
		t.Fatalf("credentials=%+v err=%v", credentials, err)
	}
}

type passkeyRecoveryStub struct {
	now           time.Time
	userID        string
	credentialID  []byte
	beginBinding  string
	finishBinding string
}

func (stub *passkeyRecoveryStub) BeginRecoveryRegistration(_ context.Context, userID, _ string, binding []byte) (authwebauthn.BeginResult, error) {
	stub.userID = userID
	stub.beginBinding = string(binding)
	return authwebauthn.BeginResult{CeremonyToken: "recovery-ceremony-token", PublicKey: json.RawMessage(`{"challenge":"fixture"}`), ExpiresAt: stub.now.Add(5 * time.Minute)}, nil
}

func (stub *passkeyRecoveryStub) FinishRecoveryRegistration(ctx context.Context, _ string, binding, _ []byte, commit authwebauthn.RegistrationCommit) (authwebauthn.Credential, error) {
	stub.finishBinding = string(binding)
	encoded, err := json.Marshal(wa.Credential{ID: stub.credentialID, PublicKey: []byte{1, 2, 3}})
	if err != nil {
		return authwebauthn.Credential{}, err
	}
	credential := authwebauthn.Credential{ID: append([]byte(nil), stub.credentialID...), UserID: stub.userID, Label: "Replacement passkey", Data: encoded, CreatedAt: stub.now}
	audit := auth.AuditEvent{ID: "recovery-passkey-audit", ActorUserID: stub.userID, Action: "auth.recovery.passkey", ResourceType: "passkey", ResourceID: base64.RawURLEncoding.EncodeToString(stub.credentialID), Summary: "A replacement passkey was enrolled during account recovery.", CreatedAt: stub.now}
	if err = commit(ctx, credential, audit); err != nil {
		return authwebauthn.Credential{}, err
	}
	return credential, nil
}

type counterReader struct{ value byte }

func (reader *counterReader) Read(target []byte) (int, error) {
	for index := range target {
		reader.value++
		target[index] = reader.value
	}
	return len(target), nil
}
