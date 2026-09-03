// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/account"
	"gamertan.com/web/auth"
	"gamertan.com/web/authwebauthn"
)

func TestAccountRegistrationCommitsEveryRequiredArtifact(t *testing.T) {
	store, authService, accountService, passkeys := accountFixture(t, true)
	started, err := accountService.Start(t.Context(), account.StartInput{Email: "PERSON@example.test", Username: "person.one", DisplayName: "Person One", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if started.User.Email != "person@example.test" || !started.User.RegistrationPending {
		t.Fatalf("pending user=%+v", started.User)
	}
	if _, err = authService.VerifyPassword(t.Context(), started.User.Email, "correct horse battery staple"); !errors.Is(err, auth.ErrInactiveUser) {
		t.Fatalf("pending password verification err=%v", err)
	}
	if _, err = accountService.BeginPasskey(t.Context(), started.RegistrationToken, "Primary passkey"); err != nil {
		t.Fatal(err)
	}
	finished, err := accountService.FinishWithPasskey(t.Context(), started.RegistrationToken, "ceremony-token", []byte(`{"id":"fixture"}`))
	if err != nil {
		t.Fatal(err)
	}
	if finished.User.RegistrationPending || finished.User.ID != started.User.ID || len(finished.RecoveryCodes) != 10 || finished.SessionToken == "" || !finished.Organization.Personal {
		t.Fatalf("finish=%+v code-count=%d", finished, len(finished.RecoveryCodes))
	}
	if passkeys.userID != started.User.ID || passkeys.binding != started.RegistrationToken {
		t.Fatalf("passkey binding user=%q binding=%q", passkeys.userID, passkeys.binding)
	}
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_passkey_credentials WHERE user_id=?`, started.User.ID, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_recovery_codes WHERE user_id=?`, started.User.ID, 10)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_organizations WHERE personal_owner_user_id=?`, started.User.ID, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_access_bindings WHERE subject_id=? AND role_name='owner'`, started.User.ID, 1)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_account_registrations WHERE user_id=?`, started.User.ID, 0)
	if _, err = authService.VerifyPassword(t.Context(), started.User.Email, "correct horse battery staple"); err != nil {
		t.Fatalf("completed password verification: %v", err)
	}
}

func TestPasswordAccountCanFinishWithoutPasskey(t *testing.T) {
	store, authService, accountService, _ := accountFixture(t, true)
	started, err := accountService.Start(t.Context(), account.StartInput{Email: "reader@example.test", Username: "reader.one", DisplayName: "Reader One", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	finished, err := accountService.FinishPassword(t.Context(), started.RegistrationToken)
	if err != nil {
		t.Fatal(err)
	}
	if finished.SessionToken == "" || len(finished.RecoveryCodes) != 10 || len(finished.PasskeyCredential.ID) != 0 {
		t.Fatalf("password finish=%+v code-count=%d", finished, len(finished.RecoveryCodes))
	}
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_passkey_credentials WHERE user_id=?`, started.User.ID, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_recovery_codes WHERE user_id=?`, started.User.ID, 10)
	if _, err = authService.VerifyPassword(t.Context(), "reader@example.test", "correct horse battery staple"); err != nil {
		t.Fatalf("password account not active: %v", err)
	}
}

func TestAccountRegistrationRollsBackWhenOwnerPolicyIsMissing(t *testing.T) {
	store, authService, accountService, _ := accountFixture(t, false)
	started, err := accountService.Start(t.Context(), account.StartInput{Email: "rollback@example.test", Username: "rollback.one", DisplayName: "Rollback One", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err = accountService.BeginPasskey(t.Context(), started.RegistrationToken, "Primary passkey"); err != nil {
		t.Fatal(err)
	}
	if _, err = accountService.FinishWithPasskey(t.Context(), started.RegistrationToken, "ceremony-token", []byte(`{"id":"fixture"}`)); err == nil {
		t.Fatal("completion unexpectedly succeeded without seeded owner role")
	}
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_passkey_credentials WHERE user_id=?`, started.User.ID, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_recovery_codes WHERE user_id=?`, started.User.ID, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_organizations WHERE personal_owner_user_id=?`, started.User.ID, 0)
	assertCount(t, store, `SELECT COUNT(*) FROM gwf_account_registrations WHERE user_id=?`, started.User.ID, 1)
	if _, err = authService.VerifyPassword(t.Context(), started.User.Email, "correct horse battery staple"); !errors.Is(err, auth.ErrInactiveUser) {
		t.Fatalf("rolled-back account became usable: %v", err)
	}
}

func accountFixture(t *testing.T, seedOwner bool) (*Store, *auth.Service, *account.Service, *accountPasskeys) {
	t.Helper()
	store, err := Open(filepath.Join(t.TempDir(), "identity.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if seedOwner {
		err = store.SeedAccessPolicy(t.Context(), access.Policy{
			Roles:       map[string]string{"owner": "Personal organization owner"},
			Permissions: map[string]string{"account.view": "View the account"},
			Grants:      map[string][]string{"owner": {"account.view"}},
		})
		if err != nil {
			t.Fatal(err)
		}
	}
	authService, err := auth.New(store, auth.Options{})
	if err != nil {
		t.Fatal(err)
	}
	passkeys := &accountPasskeys{now: time.Now().UTC()}
	accountService, err := account.New(store, passkeys, authService, account.Options{})
	if err != nil {
		t.Fatal(err)
	}
	return store, authService, accountService, passkeys
}

type accountPasskeys struct {
	userID, binding string
	now             time.Time
}

func (passkeys *accountPasskeys) BeginAccountRegistration(_ context.Context, userID, _ string, binding []byte) (authwebauthn.BeginResult, error) {
	passkeys.userID = userID
	passkeys.binding = string(binding)
	return authwebauthn.BeginResult{CeremonyToken: "ceremony-token", PublicKey: []byte(`{}`), ExpiresAt: passkeys.now.Add(5 * time.Minute)}, nil
}

func (passkeys *accountPasskeys) FinishAccountRegistration(ctx context.Context, ceremonyToken string, binding, _ []byte, commit authwebauthn.RegistrationCommit) (authwebauthn.Credential, error) {
	if ceremonyToken != "ceremony-token" || string(binding) != passkeys.binding {
		return authwebauthn.Credential{}, authwebauthn.ErrOperationBinding
	}
	credential := authwebauthn.Credential{ID: []byte("fixture-credential-id"), UserID: passkeys.userID, Label: "Primary passkey", Data: []byte(`{"id":"fixture-credential-id"}`), CreatedAt: passkeys.now}
	audit := auth.AuditEvent{ID: "passkey-audit-id", ActorUserID: passkeys.userID, Action: "auth.account.passkey", ResourceType: "passkey", ResourceID: "fixture-credential-id", Summary: "The initial account passkey was enrolled.", CreatedAt: passkeys.now}
	if err := commit(ctx, credential, audit); err != nil {
		return authwebauthn.Credential{}, err
	}
	return credential, nil
}

func assertCount(t *testing.T, store *Store, query, id string, want int) {
	t.Helper()
	var got int
	if err := store.db.QueryRow(query, id).Scan(&got); err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Fatalf("count for %q = %d, want %d", query, got, want)
	}
}
