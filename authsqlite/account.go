// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gamertan.com/web/access"
	"gamertan.com/web/account"
	"gamertan.com/web/auth"
)

func (store *Store) CreateRegistration(ctx context.Context, registration account.Registration, passwordHash string, audit auth.AuditEvent) error {
	user := registration.User
	if zeroDigest(registration.Digest) || !validPendingUser(user) || !registration.CreatedAt.Equal(user.CreatedAt) || !registration.ExpiresAt.After(registration.CreatedAt) || registration.ExpiresAt.Sub(registration.CreatedAt) > time.Hour || !text(passwordHash, 1024, false) || !validAuditEvent(audit) || audit.ActorUserID != user.ID || audit.ResourceID != user.ID {
		return errors.New("authsqlite: invalid account registration")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	// A bounded abandoned registration must not reserve its email or username
	// forever. Deleting the pending user cascades every private draft artifact.
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_users WHERE registration_pending=1 AND id IN (SELECT user_id FROM gwf_account_registrations WHERE expires_at<=?)`, registration.CreatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_users(id,username,username_normalized,email,email_normalized,display_name,status,password_change_required,registration_pending,created_at,updated_at) VALUES(?,?,?,?,?,?,?,0,1,?,?)`, user.ID, user.Username, normalize(user.Username), user.Email, normalize(user.Email), user.DisplayName, user.Status, user.CreatedAt.Unix(), user.UpdatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_password_credentials(user_id,password_hash,changed_at) VALUES(?,?,?)`, user.ID, passwordHash, user.CreatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_account_registrations(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)`, registration.Digest[:], user.ID, registration.CreatedAt.Unix(), registration.ExpiresAt.Unix()); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) Registration(ctx context.Context, digest [32]byte, now time.Time) (account.Registration, error) {
	if zeroDigest(digest) || now.IsZero() {
		return account.Registration{}, account.ErrRegistrationNotFound
	}
	var registration account.Registration
	var passwordChangeRequired, pending int
	var created, updated, draftCreated, expires int64
	err := store.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.email,u.display_name,u.status,u.password_change_required,u.registration_pending,u.created_at,u.updated_at,r.created_at,r.expires_at FROM gwf_account_registrations r JOIN gwf_users u ON u.id=r.user_id WHERE r.token_hash=? AND r.expires_at>? AND u.registration_pending=1`, digest[:], now.Unix()).Scan(&registration.User.ID, &registration.User.Username, &registration.User.Email, &registration.User.DisplayName, &registration.User.Status, &passwordChangeRequired, &pending, &created, &updated, &draftCreated, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return account.Registration{}, account.ErrRegistrationNotFound
	}
	if err != nil {
		return account.Registration{}, err
	}
	registration.Digest = digest
	registration.User.PasswordChangeRequired = passwordChangeRequired == 1
	registration.User.RegistrationPending = pending == 1
	registration.User.CreatedAt = time.Unix(created, 0).UTC()
	registration.User.UpdatedAt = time.Unix(updated, 0).UTC()
	registration.CreatedAt = time.Unix(draftCreated, 0).UTC()
	registration.ExpiresAt = time.Unix(expires, 0).UTC()
	return registration, nil
}

func (store *Store) CompleteRegistration(ctx context.Context, digest [32]byte, completion account.RegistrationCompletion) error {
	userID := completion.Membership.UserID
	validOptionalCredential := completion.Credential == nil || validCredential(*completion.Credential, true) && completion.Credential.UserID == userID
	if zeroDigest(digest) || !validOptionalCredential || len(completion.RecoveryDigests) < 5 || len(completion.RecoveryDigests) > 20 || !validOrganization(completion.Organization) || !completion.Organization.Personal || completion.Membership.OrganizationID != completion.Organization.ID || !opaqueID(userID) || completion.Membership.Status != "active" || completion.Membership.JoinedAt.IsZero() || !validOwnerBinding(completion.OwnerBinding, completion.Organization.ID, userID) || !validAuditEvent(completion.AuthAudit) || completion.AuthAudit.ActorUserID != userID || !validOrganizationAudit(completion.OrganizationAudit, completion.Organization.ID) || !validAccessAudit(completion.AccessAudit) || completion.AccessAudit.OrganizationID != completion.Organization.ID || completion.CompletedAt.IsZero() {
		return errors.New("authsqlite: invalid account registration completion")
	}
	seen := make(map[[32]byte]struct{}, len(completion.RecoveryDigests))
	for _, recoveryDigest := range completion.RecoveryDigests {
		if zeroDigest(recoveryDigest) {
			return errors.New("authsqlite: invalid recovery code digest")
		}
		if _, exists := seen[recoveryDigest]; exists {
			return errors.New("authsqlite: duplicate recovery code digest")
		}
		seen[recoveryDigest] = struct{}{}
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var registeredUserID string
	err = tx.QueryRowContext(ctx, `DELETE FROM gwf_account_registrations WHERE token_hash=? AND expires_at>? RETURNING user_id`, digest[:], completion.CompletedAt.Unix()).Scan(&registeredUserID)
	if errors.Is(err, sql.ErrNoRows) {
		return account.ErrRegistrationNotFound
	}
	if err != nil {
		return err
	}
	if registeredUserID != userID {
		return account.ErrRegistrationNotFound
	}
	var pending int
	if err = tx.QueryRowContext(ctx, `SELECT registration_pending FROM gwf_users WHERE id=? AND status='active'`, userID).Scan(&pending); err != nil || pending != 1 {
		if err != nil && !errors.Is(err, sql.ErrNoRows) {
			return err
		}
		return account.ErrRegistrationNotFound
	}
	if completion.Credential != nil {
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_passkey_credentials(credential_id,user_id,label,credential_json,created_at,last_used_at) VALUES(?,?,?,?,?,NULL)`, completion.Credential.ID, userID, completion.Credential.Label, []byte(completion.Credential.Data), completion.Credential.CreatedAt.Unix()); err != nil {
			return err
		}
	}
	for _, recoveryDigest := range completion.RecoveryDigests {
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_recovery_codes(user_id,code_hash,created_at,used_at) VALUES(?,?,?,NULL)`, userID, recoveryDigest[:], completion.CompletedAt.Unix()); err != nil {
			return err
		}
	}
	organization := completion.Organization
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organizations(id,slug,name,personal,personal_owner_user_id,created_at,status,revision,updated_at) VALUES(?,?,?,1,?,?,?,?,?)`, organization.ID, organization.Slug, organization.Name, userID, organization.CreatedAt.Unix(), organization.Status, organization.Revision, organization.UpdatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organization_memberships(organization_id,user_id,status,joined_at) VALUES(?,?,?,?)`, completion.Membership.OrganizationID, userID, completion.Membership.Status, completion.Membership.JoinedAt.Unix()); err != nil {
		return err
	}
	binding := completion.OwnerBinding
	result, err := tx.ExecContext(ctx, `INSERT INTO gwf_access_bindings(id,organization_id,subject_kind,subject_id,role_name,project_id,environment_id,service_id,granted_by_user_id,granted_at) SELECT ?,?,'user',?,?,NULL,NULL,NULL,?,? FROM gwf_access_roles WHERE name=?`, binding.ID, organization.ID, userID, binding.Role, userID, binding.GrantedAt.Unix(), binding.Role)
	if err != nil {
		return err
	}
	if changed, rowsErr := result.RowsAffected(); rowsErr != nil || changed != 1 {
		if rowsErr != nil {
			return rowsErr
		}
		return errors.New("authsqlite: account owner role has not been seeded")
	}
	if _, err = tx.ExecContext(ctx, `UPDATE gwf_users SET registration_pending=0,updated_at=? WHERE id=? AND registration_pending=1`, completion.CompletedAt.Unix(), userID); err != nil {
		return err
	}
	if err = appendAudit(ctx, tx, completion.AuthAudit); err != nil {
		return err
	}
	if err = appendOrganizationAudit(ctx, tx, completion.OrganizationAudit); err != nil {
		return err
	}
	if err = appendAccessAudit(ctx, tx, completion.AccessAudit); err != nil {
		return err
	}
	return tx.Commit()
}

func validPendingUser(user auth.User) bool {
	return opaqueID(user.ID) && text(user.Username, 64, false) && text(user.Email, 320, false) && text(user.DisplayName, 128, false) && user.Status == "active" && user.RegistrationPending && !user.PasswordChangeRequired && !user.CreatedAt.IsZero() && !user.UpdatedAt.IsZero()
}

func validOwnerBinding(binding access.Binding, organizationID, userID string) bool {
	return opaqueID(binding.ID) && binding.SubjectKind == access.User && binding.SubjectID == userID && safeName(binding.Role) && binding.Scope.OrganizationID == organizationID && binding.Scope.ProjectID == "" && binding.Scope.EnvironmentID == "" && binding.Scope.ServiceID == "" && binding.GrantedBy == userID && !binding.GrantedAt.IsZero()
}

var _ account.Repository = (*Store)(nil)
