// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/base64"
	"errors"
	"time"

	"gamertan.com/web/auth"
	"gamertan.com/web/authrecovery"
)

func (store *Store) ReplaceRecoveryCodes(ctx context.Context, userID string, digests [][32]byte, createdAt time.Time, audit auth.AuditEvent) error {
	if !opaqueID(userID) || len(digests) < 5 || len(digests) > 20 || createdAt.IsZero() || !validAuditEvent(audit) || audit.ResourceID != userID {
		return errors.New("authsqlite: invalid recovery-code set")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, digest := range digests {
		if zeroDigest(digest) {
			return errors.New("authsqlite: invalid recovery-code digest")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_recovery_codes(user_id,code_hash,created_at) VALUES(?,?,?)`, userID, digest[:], createdAt.Unix()); err != nil {
			return err
		}
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) RecoveryGrant(ctx context.Context, digest [32]byte, now time.Time) (auth.User, error) {
	if zeroDigest(digest) || now.IsZero() {
		return auth.User{}, authrecovery.ErrGrantNotFound
	}
	user, err := scanPasskeyUser(store.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.email,u.display_name,u.status,u.password_change_required,u.registration_pending,u.created_at,u.updated_at FROM gwf_recovery_grants g JOIN gwf_users u ON u.id=g.user_id WHERE g.token_hash=? AND g.expires_at>?`, digest[:], now.Unix()))
	if errors.Is(err, auth.ErrUserNotFound) {
		return auth.User{}, authrecovery.ErrGrantNotFound
	}
	return user, err
}

func (store *Store) CompletePasskeyRecovery(ctx context.Context, completion authrecovery.PasskeyCompletion) error {
	credential := completion.Credential
	credentialResource := base64.RawURLEncoding.EncodeToString(credential.ID)
	if zeroDigest(completion.GrantDigest) || !validCredential(credential, true) || len(completion.RecoveryDigests) < 5 || len(completion.RecoveryDigests) > 20 || completion.CompletedAt.IsZero() || !validAuditEvent(completion.PasskeyAudit) || !validAuditEvent(completion.RecoveryAudit) || completion.PasskeyAudit.ActorUserID != credential.UserID || completion.PasskeyAudit.Action != "auth.recovery.passkey" || completion.PasskeyAudit.ResourceType != "passkey" || completion.PasskeyAudit.ResourceID != credentialResource || completion.RecoveryAudit.ActorUserID != credential.UserID || completion.RecoveryAudit.Action != "auth.recovery.complete" || completion.RecoveryAudit.ResourceType != "user" || completion.RecoveryAudit.ResourceID != credential.UserID {
		return errors.New("authsqlite: invalid passkey recovery completion")
	}
	seen := make(map[[32]byte]struct{}, len(completion.RecoveryDigests))
	for _, digest := range completion.RecoveryDigests {
		if zeroDigest(digest) {
			return errors.New("authsqlite: invalid recovery-code digest")
		}
		if _, exists := seen[digest]; exists {
			return errors.New("authsqlite: duplicate recovery-code digest")
		}
		seen[digest] = struct{}{}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var userID string
	err = tx.QueryRowContext(ctx, `DELETE FROM gwf_recovery_grants WHERE token_hash=? AND expires_at>? RETURNING user_id`, completion.GrantDigest[:], completion.CompletedAt.Unix()).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return authrecovery.ErrGrantNotFound
	}
	if err != nil {
		return err
	}
	if userID != credential.UserID {
		return errors.New("authsqlite: passkey recovery identity mismatch")
	}
	var active, pending int
	if err = tx.QueryRowContext(ctx, `SELECT status='active',registration_pending FROM gwf_users WHERE id=?`, userID).Scan(&active, &pending); err != nil || active != 1 || pending != 0 {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return auth.ErrInactiveUser
	}
	existing, err := tx.QueryContext(ctx, `SELECT credential_id FROM gwf_passkey_credentials WHERE user_id=?`, userID)
	if err != nil {
		return err
	}
	for existing.Next() {
		var id []byte
		if err = existing.Scan(&id); err != nil {
			existing.Close()
			return err
		}
		if bytes.Equal(id, credential.ID) {
			existing.Close()
			return errors.New("authsqlite: passkey credential already exists")
		}
	}
	if err = existing.Close(); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_passkey_credentials(credential_id,user_id,label,credential_json,created_at,last_used_at) VALUES(?,?,?,?,?,NULL)`, credential.ID, userID, credential.Label, []byte(credential.Data), credential.CreatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_recovery_codes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, digest := range completion.RecoveryDigests {
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_recovery_codes(user_id,code_hash,created_at,used_at) VALUES(?,?,?,NULL)`, userID, digest[:], completion.CompletedAt.Unix()); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_auth_sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_passkey_ceremonies WHERE user_id=?`, userID); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, completion.PasskeyAudit); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, completion.RecoveryAudit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) ConsumeRecoveryCodeAndCreateGrant(ctx context.Context, userID string, codeDigest [32]byte, grant authrecovery.Grant, audit auth.AuditEvent) error {
	if !opaqueID(userID) || zeroDigest(codeDigest) || grant.UserID != userID || zeroDigest(grant.Digest) || grant.CreatedAt.IsZero() || !grant.ExpiresAt.After(grant.CreatedAt) || grant.ExpiresAt.Sub(grant.CreatedAt) > 30*time.Minute || !validAuditEvent(audit) || audit.ResourceID != userID {
		return errors.New("authsqlite: invalid recovery attempt")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE gwf_recovery_codes SET used_at=? WHERE user_id=? AND code_hash=? AND used_at IS NULL`, grant.CreatedAt.Unix(), userID, codeDigest[:])
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil || changed != 1 {
		return authrecovery.ErrCodeNotFound
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_auth_sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_recovery_grants WHERE user_id=?`, userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_recovery_grants(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)`, grant.Digest[:], userID, grant.CreatedAt.Unix(), grant.ExpiresAt.Unix()); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) TakeRecoveryGrant(ctx context.Context, digest [32]byte, now time.Time) (auth.User, error) {
	if zeroDigest(digest) || now.IsZero() {
		return auth.User{}, authrecovery.ErrGrantNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, err
	}
	defer tx.Rollback()
	var userID string
	if err = tx.QueryRowContext(ctx, `SELECT user_id FROM gwf_recovery_grants WHERE token_hash=? AND expires_at>?`, digest[:], now.Unix()).Scan(&userID); errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, authrecovery.ErrGrantNotFound
	} else if err != nil {
		return auth.User{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_recovery_grants WHERE token_hash=?`, digest[:]); err != nil {
		return auth.User{}, err
	}
	user, err := scanPasskeyUser(tx.QueryRowContext(ctx, `SELECT id,username,email,display_name,status,password_change_required,registration_pending,created_at,updated_at FROM gwf_users WHERE id=?`, userID))
	if err != nil {
		return auth.User{}, err
	}
	if err = tx.Commit(); err != nil {
		return auth.User{}, err
	}
	return user, nil
}
