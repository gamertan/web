// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"gamertan.com/web/auth"
	"gamertan.com/web/authwebauthn"
)

const (
	maxPasskeysPerUser      = 16
	maxCredentialBytes      = 64 << 10
	maxCeremonySessionBytes = 64 << 10
)

func (store *Store) CreatePasskeyUser(ctx context.Context, user auth.User, enrollment authwebauthn.EnrollmentToken, audit auth.AuditEvent) error {
	if !validPasskeyUser(user) || !validEnrollment(enrollment) || enrollment.UserID != user.ID || !validAuditEvent(audit) {
		return errors.New("authsqlite: invalid passkey bootstrap")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_users(id,username,username_normalized,email,email_normalized,display_name,status,password_change_required,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, user.ID, user.Username, normalize(user.Username), user.Email, normalize(user.Email), user.DisplayName, user.Status, 0, user.CreatedAt.Unix(), user.UpdatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_passkey_enrollment_tokens(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)`, enrollment.Digest[:], enrollment.UserID, enrollment.CreatedAt.Unix(), enrollment.ExpiresAt.Unix()); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) UserByID(ctx context.Context, userID string) (auth.User, error) {
	if !opaqueID(userID) {
		return auth.User{}, auth.ErrUserNotFound
	}
	return scanPasskeyUser(store.db.QueryRowContext(ctx, `SELECT id,username,email,display_name,status,password_change_required,created_at,updated_at FROM gwf_users WHERE id=?`, userID))
}

func (store *Store) UserByIdentifier(ctx context.Context, identifier string) (auth.User, error) {
	identifier = strings.TrimSpace(identifier)
	if !text(identifier, 320, false) {
		return auth.User{}, auth.ErrUserNotFound
	}
	return scanPasskeyUser(store.db.QueryRowContext(ctx, `SELECT id,username,email,display_name,status,password_change_required,created_at,updated_at FROM gwf_users WHERE username_normalized=? OR email_normalized=?`, normalize(identifier), normalize(identifier)))
}

func (store *Store) UserByCredentialID(ctx context.Context, credentialID []byte) (auth.User, error) {
	if !boundedCredentialID(credentialID) {
		return auth.User{}, authwebauthn.ErrCredentialNotFound
	}
	user, err := scanPasskeyUser(store.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.email,u.display_name,u.status,u.password_change_required,u.created_at,u.updated_at FROM gwf_users u JOIN gwf_passkey_credentials c ON c.user_id=u.id WHERE c.credential_id=?`, credentialID))
	if errors.Is(err, auth.ErrUserNotFound) {
		return auth.User{}, authwebauthn.ErrCredentialNotFound
	}
	return user, err
}

func (store *Store) CredentialsByUserID(ctx context.Context, userID string) ([]authwebauthn.Credential, error) {
	if !opaqueID(userID) {
		return nil, auth.ErrUserNotFound
	}
	rows, err := store.db.QueryContext(ctx, `SELECT credential_id,label,credential_json,created_at,COALESCE(last_used_at,0) FROM gwf_passkey_credentials WHERE user_id=? ORDER BY created_at,credential_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	credentials := make([]authwebauthn.Credential, 0)
	for rows.Next() {
		var credential authwebauthn.Credential
		var created, used int64
		if err = rows.Scan(&credential.ID, &credential.Label, &credential.Data, &created, &used); err != nil {
			return nil, err
		}
		credential.UserID = userID
		credential.CreatedAt = time.Unix(created, 0).UTC()
		if used != 0 {
			credential.LastUsedAt = time.Unix(used, 0).UTC()
		}
		credentials = append(credentials, credential)
	}
	return credentials, rows.Err()
}

func (store *Store) PasswordCredentialExists(ctx context.Context, userID string) (bool, error) {
	if !opaqueID(userID) {
		return false, auth.ErrUserNotFound
	}
	var count int
	if err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_password_credentials WHERE user_id=?`, userID).Scan(&count); err != nil {
		return false, err
	}
	return count == 1, nil
}

func (store *Store) SaveCredential(ctx context.Context, credential authwebauthn.Credential, audit auth.AuditEvent) error {
	if !validCredential(credential, true) || !validAuditEvent(audit) {
		return errors.New("authsqlite: invalid passkey credential")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_passkey_credentials WHERE user_id=?`, credential.UserID).Scan(&count); err != nil {
		return err
	}
	if count >= maxPasskeysPerUser {
		return errors.New("authsqlite: passkey credential limit reached")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_passkey_credentials(credential_id,user_id,label,credential_json,created_at,last_used_at) VALUES(?,?,?,?,?,NULL)`, credential.ID, credential.UserID, credential.Label, []byte(credential.Data), credential.CreatedAt.Unix()); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) SaveCredentialAndRetirePassword(ctx context.Context, credential authwebauthn.Credential, audit auth.AuditEvent) error {
	if !validCredential(credential, true) || !validAuditEvent(audit) || audit.ActorUserID != credential.UserID || audit.Action != "auth.passkey.migrate" {
		return errors.New("authsqlite: invalid passkey migration")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var credentialCount, passwordCount int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_passkey_credentials WHERE user_id=?`, credential.UserID).Scan(&credentialCount); err != nil {
		return err
	}
	if credentialCount >= maxPasskeysPerUser {
		return errors.New("authsqlite: passkey credential limit reached")
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_password_credentials WHERE user_id=?`, credential.UserID).Scan(&passwordCount); err != nil {
		return err
	}
	if passwordCount != 1 {
		return authwebauthn.ErrPasswordNotAvailable
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_passkey_credentials(credential_id,user_id,label,credential_json,created_at,last_used_at) VALUES(?,?,?,?,?,NULL)`, credential.ID, credential.UserID, credential.Label, []byte(credential.Data), credential.CreatedAt.Unix()); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM gwf_password_credentials WHERE user_id=?`, credential.UserID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return authwebauthn.ErrPasswordNotAvailable
	}
	if _, err = tx.ExecContext(ctx, `UPDATE gwf_users SET password_change_required=0,updated_at=? WHERE id=?`, credential.CreatedAt.Unix(), credential.UserID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_auth_sessions WHERE user_id=?`, credential.UserID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_passkey_ceremonies WHERE user_id=?`, credential.UserID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_passkey_enrollment_tokens WHERE user_id=?`, credential.UserID); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) UpdateCredential(ctx context.Context, credential authwebauthn.Credential) error {
	if !validCredential(credential, false) || credential.LastUsedAt.IsZero() {
		return errors.New("authsqlite: invalid passkey credential update")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE gwf_passkey_credentials SET credential_json=?,last_used_at=? WHERE credential_id=? AND user_id=?`, []byte(credential.Data), credential.LastUsedAt.Unix(), credential.ID, credential.UserID)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return authwebauthn.ErrCredentialNotFound
	}
	return nil
}

func (store *Store) DeleteCredential(ctx context.Context, userID string, credentialID []byte, minimumRemaining int, audit auth.AuditEvent) error {
	if !opaqueID(userID) || !boundedCredentialID(credentialID) || minimumRemaining < 1 || minimumRemaining > maxPasskeysPerUser || !validAuditEvent(audit) {
		return errors.New("authsqlite: invalid passkey credential deletion")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var count int
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_passkey_credentials WHERE user_id=?`, userID).Scan(&count); err != nil {
		return err
	}
	if count <= minimumRemaining {
		if minimumRemaining == 1 {
			return authwebauthn.ErrLastCredential
		}
		return authwebauthn.ErrCredentialFloor
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM gwf_passkey_credentials WHERE user_id=? AND credential_id=?`, userID, credentialID)
	if err != nil {
		return err
	}
	if changed, rowsErr := result.RowsAffected(); rowsErr != nil || changed != 1 {
		if rowsErr != nil {
			return rowsErr
		}
		return authwebauthn.ErrCredentialNotFound
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) CredentialCount(ctx context.Context, userID string) (int, error) {
	if !opaqueID(userID) {
		return 0, auth.ErrUserNotFound
	}
	var count int
	err := store.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_passkey_credentials WHERE user_id=?`, userID).Scan(&count)
	return count, err
}

func (store *Store) CreateCeremony(ctx context.Context, ceremony authwebauthn.Ceremony) error {
	if !validCeremony(ceremony) {
		return errors.New("authsqlite: invalid passkey ceremony")
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO gwf_passkey_ceremonies(token_hash,kind,user_id,label,session_json,binding_hash,created_at,expires_at) VALUES(?,?,NULLIF(?,''),?,?,?,?,?)`, ceremony.Digest[:], ceremony.Kind, ceremony.UserID, ceremony.Label, []byte(ceremony.SessionData), ceremony.BindingDigest[:], ceremony.CreatedAt.Unix(), ceremony.ExpiresAt.Unix())
	return err
}

func (store *Store) TakeCeremony(ctx context.Context, digest [32]byte, now time.Time) (authwebauthn.Ceremony, error) {
	if zeroDigest(digest) || now.IsZero() {
		return authwebauthn.Ceremony{}, authwebauthn.ErrCeremonyNotFound
	}
	var ceremony authwebauthn.Ceremony
	var userID sql.NullString
	var binding []byte
	var created, expires int64
	err := store.db.QueryRowContext(ctx, `DELETE FROM gwf_passkey_ceremonies WHERE token_hash=? RETURNING kind,user_id,label,session_json,binding_hash,created_at,expires_at`, digest[:]).Scan(&ceremony.Kind, &userID, &ceremony.Label, &ceremony.SessionData, &binding, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return authwebauthn.Ceremony{}, authwebauthn.ErrCeremonyNotFound
	}
	if err != nil {
		return authwebauthn.Ceremony{}, err
	}
	ceremony.Digest = digest
	ceremony.UserID = userID.String
	copy(ceremony.BindingDigest[:], binding)
	ceremony.CreatedAt, ceremony.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
	if len(binding) != sha256Size || !now.Before(ceremony.ExpiresAt) {
		return authwebauthn.Ceremony{}, authwebauthn.ErrCeremonyNotFound
	}
	return ceremony, nil
}

func (store *Store) ConsumeEnrollmentToken(ctx context.Context, digest [32]byte, now time.Time) (auth.User, error) {
	if zeroDigest(digest) || now.IsZero() {
		return auth.User{}, authwebauthn.ErrEnrollmentNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, err
	}
	defer tx.Rollback()
	var userID string
	err = tx.QueryRowContext(ctx, `DELETE FROM gwf_passkey_enrollment_tokens WHERE token_hash=? AND expires_at>? RETURNING user_id`, digest[:], now.Unix()).Scan(&userID)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, authwebauthn.ErrEnrollmentNotFound
	}
	if err != nil {
		return auth.User{}, err
	}
	user, err := scanPasskeyUser(tx.QueryRowContext(ctx, `SELECT id,username,email,display_name,status,password_change_required,created_at,updated_at FROM gwf_users WHERE id=?`, userID))
	if err != nil {
		return auth.User{}, err
	}
	if err = tx.Commit(); err != nil {
		return auth.User{}, err
	}
	return user, nil
}

func (store *Store) RecoverUser(ctx context.Context, identifier string, enrollment authwebauthn.EnrollmentToken, audit auth.AuditEvent) (auth.User, error) {
	if !text(strings.TrimSpace(identifier), 320, false) || !validEnrollment(enrollment) || !validAuditEvent(audit) {
		return auth.User{}, errors.New("authsqlite: invalid passkey recovery")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return auth.User{}, err
	}
	defer tx.Rollback()
	user, err := scanPasskeyUser(tx.QueryRowContext(ctx, `SELECT id,username,email,display_name,status,password_change_required,created_at,updated_at FROM gwf_users WHERE username_normalized=? OR email_normalized=?`, normalize(identifier), normalize(identifier)))
	if err != nil {
		return auth.User{}, err
	}
	if enrollment.UserID != user.ID || audit.ResourceID != user.ID {
		return auth.User{}, errors.New("authsqlite: passkey recovery identity mismatch")
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_auth_sessions WHERE user_id=?`, user.ID); err != nil {
		return auth.User{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_passkey_ceremonies WHERE user_id=?`, user.ID); err != nil {
		return auth.User{}, err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_passkey_enrollment_tokens WHERE user_id=?`, user.ID); err != nil {
		return auth.User{}, err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_passkey_enrollment_tokens(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)`, enrollment.Digest[:], user.ID, enrollment.CreatedAt.Unix(), enrollment.ExpiresAt.Unix()); err != nil {
		return auth.User{}, err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return auth.User{}, err
	}
	if err = tx.Commit(); err != nil {
		return auth.User{}, err
	}
	return user, nil
}

type rowScanner interface{ Scan(...any) error }

func scanPasskeyUser(row rowScanner) (auth.User, error) {
	var user auth.User
	var passwordChangeRequired int
	var created, updated int64
	if err := row.Scan(&user.ID, &user.Username, &user.Email, &user.DisplayName, &user.Status, &passwordChangeRequired, &created, &updated); err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return auth.User{}, auth.ErrUserNotFound
		}
		return auth.User{}, err
	}
	user.PasswordChangeRequired = passwordChangeRequired == 1
	user.CreatedAt, user.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return user, nil
}

func validPasskeyUser(user auth.User) bool {
	return opaqueID(user.ID) && text(user.Username, 64, false) && text(user.Email, 320, false) && text(user.DisplayName, 128, false) && user.Status == "active" && !user.CreatedAt.IsZero() && !user.UpdatedAt.IsZero()
}

func validEnrollment(token authwebauthn.EnrollmentToken) bool {
	return !zeroDigest(token.Digest) && opaqueID(token.UserID) && !token.CreatedAt.IsZero() && token.ExpiresAt.After(token.CreatedAt)
}

func boundedCredentialID(value []byte) bool { return len(value) >= 16 && len(value) <= 1024 }

func validCredential(credential authwebauthn.Credential, requireLabel bool) bool {
	return boundedCredentialID(credential.ID) && opaqueID(credential.UserID) && (!requireLabel || text(credential.Label, 80, false)) && len(credential.Data) > 0 && len(credential.Data) <= maxCredentialBytes && json.Valid(credential.Data) && (!requireLabel || !credential.CreatedAt.IsZero())
}

func validCeremony(ceremony authwebauthn.Ceremony) bool {
	validKind := ceremony.Kind == authwebauthn.CeremonyRegistration || ceremony.Kind == authwebauthn.CeremonyLogin || ceremony.Kind == authwebauthn.CeremonyApproval
	validUser := ceremony.Kind == authwebauthn.CeremonyLogin && ceremony.UserID == "" || opaqueID(ceremony.UserID)
	registrationKind := ceremony.Kind == authwebauthn.CeremonyRegistration
	validLabel := registrationKind && text(ceremony.Label, 80, false) || !registrationKind && ceremony.Label == ""
	zeroBinding := zeroDigest(ceremony.BindingDigest)
	validBinding := ceremony.Kind == authwebauthn.CeremonyApproval && !zeroBinding || ceremony.Kind == authwebauthn.CeremonyRegistration || ceremony.Kind == authwebauthn.CeremonyLogin && zeroBinding
	return !zeroDigest(ceremony.Digest) && validKind && validUser && validLabel && validBinding && len(ceremony.SessionData) > 0 && len(ceremony.SessionData) <= maxCeremonySessionBytes && json.Valid(ceremony.SessionData) && !ceremony.CreatedAt.IsZero() && ceremony.ExpiresAt.After(ceremony.CreatedAt)
}

const sha256Size = 32
