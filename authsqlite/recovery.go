// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"database/sql"
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
