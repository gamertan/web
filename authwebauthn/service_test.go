// SPDX-License-Identifier: MPL-2.0

package authwebauthn_test

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"io"
	"testing"
	"time"

	"gamertan.com/web/internal/webauthnvendored/protocol"
	"gamertan.com/web/internal/webauthnvendored/protocol/webauthncose"
	wa "gamertan.com/web/internal/webauthnvendored/webauthn"

	"gamertan.com/web/auth"
	"gamertan.com/web/authsqlite"
	"gamertan.com/web/authwebauthn"
)

func TestBootstrapEnrollmentAndApprovalPolicy(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store, authService, service := newService(t, &now, &counterReader{})
	defer store.Close()

	user, enrollmentToken, err := service.Bootstrap(t.Context(), authwebauthn.BootstrapInput{Username: "operator.one", Email: "operator@example.test", DisplayName: "Operator One"})
	if err != nil {
		t.Fatal(err)
	}
	if enrollmentToken == "" || user.PasswordChangeRequired {
		t.Fatalf("unexpected bootstrap user=%+v token=%q", user, enrollmentToken)
	}

	begin, err := service.BeginEnrollment(t.Context(), enrollmentToken, "Primary passkey")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.BeginEnrollment(t.Context(), enrollmentToken, "Replay"); !errors.Is(err, authwebauthn.ErrEnrollmentNotFound) {
		t.Fatalf("replayed enrollment err=%v", err)
	}
	var options protocol.PublicKeyCredentialCreationOptions
	if err = json.Unmarshal(begin.PublicKey, &options); err != nil {
		t.Fatal(err)
	}
	if options.RelyingParty.ID != "tend.gamertan.com" || options.AuthenticatorSelection.UserVerification != protocol.VerificationRequired || options.AuthenticatorSelection.ResidentKey != protocol.ResidentKeyRequirementRequired || options.Attestation != protocol.PreferNoAttestation {
		t.Fatalf("unexpected registration policy: %+v", options)
	}
	if len(options.Parameters) != 1 || options.Parameters[0].Algorithm != webauthncose.AlgES256 {
		t.Fatalf("unexpected algorithms: %+v", options.Parameters)
	}
	if !begin.ExpiresAt.Equal(now.Add(5 * time.Minute)) {
		t.Fatalf("registration expiry=%v", begin.ExpiresAt)
	}
	if _, err = service.FinishRegistrationForUser(t.Context(), begin.CeremonyToken, "another-user", []byte(`{}`)); !errors.Is(err, authwebauthn.ErrOperationBinding) {
		t.Fatalf("cross-account registration completion err=%v", err)
	}
	if _, err = service.FinishRegistrationForUser(t.Context(), begin.CeremonyToken, user.ID, []byte(`{}`)); !errors.Is(err, authwebauthn.ErrCeremonyNotFound) {
		t.Fatalf("mismatched completion did not consume ceremony: %v", err)
	}

	if err = service.RequireReady(t.Context(), user.ID); !errors.Is(err, authwebauthn.ErrPasskeyReadiness) {
		t.Fatalf("readiness without credentials err=%v", err)
	}
	for index := range 2 {
		credential := wa.Credential{ID: bytes.Repeat([]byte{byte(index + 1)}, 32), PublicKey: []byte{1, 2, 3}}
		encoded, marshalErr := json.Marshal(credential)
		if marshalErr != nil {
			t.Fatal(marshalErr)
		}
		audit := auth.AuditEvent{ID: "audit-passkey-" + string(rune('a'+index)), ActorUserID: user.ID, Action: "auth.passkey.add", ResourceType: "passkey", ResourceID: "fixture", Summary: "fixture", CreatedAt: now}
		if err = store.SaveCredential(t.Context(), authwebauthn.Credential{ID: credential.ID, UserID: user.ID, Label: "Fixture", Data: encoded, CreatedAt: now}, audit); err != nil {
			t.Fatal(err)
		}
	}
	if err = service.RequireReady(t.Context(), user.ID); err != nil {
		t.Fatal(err)
	}
	summaries, err := service.CredentialSummaries(t.Context(), user.ID)
	if err != nil {
		t.Fatal(err)
	}
	if len(summaries) != 2 || summaries[0].Label != "Fixture" || len(summaries[0].ID) != 32 {
		t.Fatalf("unexpected summaries: %+v", summaries)
	}
	summaries[0].ID[0] = 99
	refreshed, err := service.CredentialSummaries(t.Context(), user.ID)
	if err != nil || refreshed[0].ID[0] == 99 {
		t.Fatalf("credential summary did not defensively copy the identifier: summaries=%+v err=%v", refreshed, err)
	}
	if _, err = service.BeginCredentialRemoval(t.Context(), user.ID, refreshed[0].ID); !errors.Is(err, authwebauthn.ErrCredentialFloor) {
		t.Fatalf("credential removal below operational floor err=%v", err)
	}
	if _, err = service.BeginCredentialRemoval(t.Context(), user.ID, bytes.Repeat([]byte{9}, 32)); !errors.Is(err, authwebauthn.ErrCredentialNotFound) {
		t.Fatalf("unknown credential removal err=%v", err)
	}

	binding := bytes.Repeat([]byte("approved operation "), 3)
	approvalBegin, err := service.BeginApproval(t.Context(), user.ID, binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.FinishApproval(t.Context(), approvalBegin.CeremonyToken, append([]byte(nil), binding[:len(binding)-1]...), []byte(`{}`)); !errors.Is(err, authwebauthn.ErrOperationBinding) {
		t.Fatalf("tampered binding err=%v", err)
	}
	if _, err = service.FinishApproval(t.Context(), approvalBegin.CeremonyToken, binding, []byte(`{}`)); !errors.Is(err, authwebauthn.ErrCeremonyNotFound) {
		t.Fatalf("replayed approval err=%v", err)
	}

	login, err := service.BeginLogin(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	now = now.Add(3 * time.Minute)
	if _, err = service.FinishLogin(t.Context(), login.CeremonyToken, []byte(`{}`)); !errors.Is(err, authwebauthn.ErrCeremonyNotFound) {
		t.Fatalf("expired login err=%v", err)
	}

	_ = authService
}

func TestRecoveryRevokesSessionsAndIssuesSingleUseEnrollment(t *testing.T) {
	now := time.Date(2026, 8, 19, 12, 0, 0, 0, time.UTC)
	store, authService, service := newService(t, &now, &counterReader{})
	defer store.Close()
	user, _, err := service.Bootstrap(t.Context(), authwebauthn.BootstrapInput{Username: "recover.me", Email: "recover@example.test", DisplayName: "Recover Me"})
	if err != nil {
		t.Fatal(err)
	}
	session, _, err := authService.IssueSession(t.Context(), user.ID, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	_, token, err := service.Recover(t.Context(), "recover.me", "all authenticators unavailable")
	if err != nil {
		t.Fatal(err)
	}
	if _, err = authService.Session(t.Context(), session); !errors.Is(err, auth.ErrSessionNotFound) {
		t.Fatalf("session survived recovery: %v", err)
	}
	if _, err = service.BeginEnrollment(t.Context(), token, "Recovered passkey"); err != nil {
		t.Fatal(err)
	}
	if _, err = service.BeginEnrollment(t.Context(), token, "Replay"); !errors.Is(err, authwebauthn.ErrEnrollmentNotFound) {
		t.Fatalf("recovery token replay err=%v", err)
	}
}

func TestRecoveryRegistrationIsBoundAndConsumesMismatchedCeremony(t *testing.T) {
	now := time.Date(2026, 9, 3, 13, 0, 0, 0, time.UTC)
	store, authService, service := newService(t, &now, &counterReader{})
	defer store.Close()
	user, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "recover.bound", Email: "recover-bound@example.test", DisplayName: "Recover Bound", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	binding := bytes.Repeat([]byte("restricted recovery grant "), 2)
	begin, err := service.BeginRecoveryRegistration(t.Context(), user.ID, "Replacement passkey", binding)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = service.FinishRecoveryRegistration(t.Context(), begin.CeremonyToken, append([]byte(nil), binding[:len(binding)-1]...), []byte(`{}`), func(context.Context, authwebauthn.Credential, auth.AuditEvent) error { return nil }); !errors.Is(err, authwebauthn.ErrOperationBinding) {
		t.Fatalf("tampered recovery binding err=%v", err)
	}
	if _, err = service.FinishRecoveryRegistration(t.Context(), begin.CeremonyToken, binding, []byte(`{}`), func(context.Context, authwebauthn.Credential, auth.AuditEvent) error { return nil }); !errors.Is(err, authwebauthn.ErrCeremonyNotFound) {
		t.Fatalf("mismatched completion did not consume recovery ceremony: %v", err)
	}
	if _, err = service.BeginRecoveryRegistration(t.Context(), user.ID, "Replacement passkey", []byte("short")); !errors.Is(err, authwebauthn.ErrOperationBinding) {
		t.Fatalf("short recovery binding err=%v", err)
	}
}

func TestPasswordMigrationCeremonyIsBoundAndUnavailableAfterRetirement(t *testing.T) {
	now := time.Date(2026, 8, 27, 12, 0, 0, 0, time.UTC)
	store, err := authsqlite.Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authService, err := auth.New(store, auth.Options{Random: &counterReader{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	user, err := authService.CreateUser(t.Context(), auth.CreateUser{Username: "legacy.user", Email: "legacy@example.test", DisplayName: "Legacy User", Password: "legacy migration password"})
	if err != nil {
		t.Fatal(err)
	}
	service, err := authwebauthn.New(store, authService, authwebauthn.Config{RPID: "observatory.test", RPDisplayName: "Observatory", Origin: "https://observatory.test", RequiredCredentialCount: 1, Random: &counterReader{}, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	begin, err := service.BeginPasswordMigration(t.Context(), user.ID, "Primary passkey")
	if err != nil {
		t.Fatal(err)
	}
	digest := sha256.Sum256([]byte(begin.CeremonyToken))
	ceremony, err := store.TakeCeremony(t.Context(), digest, now)
	if err != nil {
		t.Fatal(err)
	}
	if ceremony.Kind != authwebauthn.CeremonyRegistration || ceremony.BindingDigest == ([32]byte{}) || ceremony.UserID != user.ID {
		t.Fatalf("unexpected migration ceremony: %+v", ceremony)
	}
	credential := wa.Credential{ID: bytes.Repeat([]byte{9}, 32), PublicKey: []byte{1, 2, 3}}
	encoded, err := json.Marshal(credential)
	if err != nil {
		t.Fatal(err)
	}
	audit := auth.AuditEvent{ID: "migration-direct", ActorUserID: user.ID, Action: "auth.passkey.migrate", ResourceType: "passkey", ResourceID: "credential", Summary: "migration", CreatedAt: now}
	if err = store.SaveCredentialAndRetirePassword(t.Context(), authwebauthn.Credential{ID: credential.ID, UserID: user.ID, Label: "Primary", Data: encoded, CreatedAt: now}, audit); err != nil {
		t.Fatal(err)
	}
	if _, err = service.BeginPasswordMigration(t.Context(), user.ID, "Replay"); !errors.Is(err, authwebauthn.ErrPasswordNotAvailable) {
		t.Fatalf("retired password migration err=%v", err)
	}
}

func TestConfigurationAndEntropyFailures(t *testing.T) {
	store, err := authsqlite.Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	authService, err := auth.New(store, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	for _, config := range []authwebauthn.Config{
		{RPID: "tend.gamertan.com", RPDisplayName: "Tend", Origin: "http://tend.gamertan.com"},
		{RPID: "tend.gamertan.com", RPDisplayName: "Tend", Origin: "https://other.gamertan.com"},
		{RPID: "tend.gamertan.com", RPDisplayName: "Tend", Origin: "https://tend.gamertan.com/path"},
	} {
		if _, err = authwebauthn.New(store, authService, config); err == nil {
			t.Fatalf("accepted config=%+v", config)
		}
	}
	service, err := authwebauthn.New(store, authService, authwebauthn.Config{RPID: "tend.gamertan.com", RPDisplayName: "Tend", Origin: "https://tend.gamertan.com", Random: failingReader{}})
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err = service.Bootstrap(t.Context(), authwebauthn.BootstrapInput{Username: "entropy.fail", Email: "entropy@example.test", DisplayName: "Entropy"}); err == nil || !errors.Is(err, io.ErrUnexpectedEOF) {
		t.Fatalf("entropy failure err=%v", err)
	}
}

func newService(t *testing.T, now *time.Time, random io.Reader) (*authsqlite.Store, *auth.Service, *authwebauthn.Service) {
	t.Helper()
	store, err := authsqlite.Open(t.TempDir() + "/auth.db")
	if err != nil {
		t.Fatal(err)
	}
	authService, err := auth.New(store, auth.Options{Random: random, Now: func() time.Time { return *now }})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	service, err := authwebauthn.New(store, authService, authwebauthn.Config{RPID: "tend.gamertan.com", RPDisplayName: "Tend", Origin: "https://tend.gamertan.com", Random: random, Now: func() time.Time { return *now }})
	if err != nil {
		store.Close()
		t.Fatal(err)
	}
	return store, authService, service
}

type failingReader struct{}

func (failingReader) Read([]byte) (int, error) { return 0, io.ErrUnexpectedEOF }

type counterReader struct{ next byte }

func (reader *counterReader) Read(value []byte) (int, error) {
	for index := range value {
		reader.next++
		value[index] = reader.next
	}
	return len(value), nil
}
