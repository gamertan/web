// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"errors"

	"gamertan.com/web/bootstrap"
)

// CreateInitialOwner commits the root-local bootstrap across identity,
// enrollment, organization, membership, owner access, and all audit records.
func (store *Store) CreateInitialOwner(ctx context.Context, setup bootstrap.Setup) error {
	user := setup.User
	organization := setup.Organization
	membership := setup.Membership
	binding := setup.OwnerBinding
	if !validPasskeyUser(user) || !validEnrollment(setup.Enrollment) || setup.Enrollment.UserID != user.ID ||
		!validOrganization(organization) || organization.Personal || organization.Status != "active" || organization.Revision != 1 ||
		membership.OrganizationID != organization.ID || membership.UserID != user.ID || membership.Status != "active" || membership.JoinedAt.IsZero() ||
		!validOwnerBinding(binding, organization.ID, user.ID) ||
		!validAuditEvent(setup.AuthAudit) || setup.AuthAudit.ActorUserID != user.ID || setup.AuthAudit.Action != "auth.passkey.bootstrap" || setup.AuthAudit.ResourceType != "user" || setup.AuthAudit.ResourceID != user.ID ||
		!validOrganizationAudit(setup.OrganizationAudit, organization.ID) || setup.OrganizationAudit.ActorUserID != user.ID || setup.OrganizationAudit.Action != "organization.bootstrap" || setup.OrganizationAudit.ResourceType != "organization" || setup.OrganizationAudit.ResourceID != organization.ID ||
		!validAccessAudit(setup.AccessAudit) || setup.AccessAudit.OrganizationID != organization.ID || setup.AccessAudit.ActorUserID != user.ID || setup.AccessAudit.Action != "access.binding.grant" || setup.AccessAudit.ResourceType != "binding" || setup.AccessAudit.ResourceID != binding.ID {
		return errors.New("authsqlite: invalid initial owner bootstrap")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_users(id,username,username_normalized,email,email_normalized,display_name,status,password_change_required,registration_pending,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?,?)`, user.ID, user.Username, normalize(user.Username), user.Email, normalize(user.Email), user.DisplayName, user.Status, 0, 0, user.CreatedAt.Unix(), user.UpdatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_passkey_enrollment_tokens(token_hash,user_id,created_at,expires_at) VALUES(?,?,?,?)`, setup.Enrollment.Digest[:], user.ID, setup.Enrollment.CreatedAt.Unix(), setup.Enrollment.ExpiresAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organizations(id,slug,name,personal,personal_owner_user_id,created_at,status,revision,updated_at) VALUES(?,?,?,0,NULL,?,?,?,?)`, organization.ID, organization.Slug, organization.Name, organization.CreatedAt.Unix(), organization.Status, organization.Revision, organization.UpdatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organization_memberships(organization_id,user_id,status,joined_at) VALUES(?,?,?,?)`, organization.ID, user.ID, membership.Status, membership.JoinedAt.Unix()); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO gwf_access_bindings(id,organization_id,subject_kind,subject_id,role_name,project_id,environment_id,service_id,granted_by_user_id,granted_at) SELECT ?,?,'user',?,?,NULL,NULL,NULL,?,? FROM gwf_access_roles WHERE name=?`, binding.ID, organization.ID, user.ID, binding.Role, user.ID, binding.GrantedAt.Unix(), binding.Role)
	if err != nil {
		return err
	}
	if changed, rowsErr := result.RowsAffected(); rowsErr != nil || changed != 1 {
		if rowsErr != nil {
			return rowsErr
		}
		return errors.New("authsqlite: initial owner role has not been seeded")
	}
	if err = appendAudit(ctx, tx, setup.AuthAudit); err != nil {
		return err
	}
	if err = appendOrganizationAudit(ctx, tx, setup.OrganizationAudit); err != nil {
		return err
	}
	if err = appendAccessAudit(ctx, tx, setup.AccessAudit); err != nil {
		return err
	}
	return tx.Commit()
}

var _ bootstrap.Repository = (*Store)(nil)
