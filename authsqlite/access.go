// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gamertan.com/web/access"
)

func (store *Store) SeedAccessPolicy(ctx context.Context, policy access.Policy) error {
	if err := policy.Validate(); err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for name, description := range policy.Roles {
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_access_roles(name,description) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET description=excluded.description`, name, description); err != nil {
			return err
		}
	}
	for name, description := range policy.Permissions {
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_access_permissions(name,description) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET description=excluded.description`, name, description); err != nil {
			return err
		}
	}
	for role, permissions := range policy.Grants {
		if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_access_role_permissions WHERE role_name=?`, role); err != nil {
			return err
		}
		for _, permission := range permissions {
			if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_access_role_permissions(role_name,permission_name) VALUES(?,?)`, role, permission); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (store *Store) Grant(ctx context.Context, binding access.Binding) error {
	if !opaqueID(binding.ID) || (binding.SubjectKind != access.User && binding.SubjectKind != access.Team) || !opaqueID(binding.SubjectID) || !safeName(binding.Role) || binding.Scope.Validate() != nil || !opaqueID(binding.GrantedBy) || binding.GrantedAt.IsZero() {
		return errors.New("authsqlite: invalid access binding")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	query := `SELECT COUNT(*) FROM gwf_organization_memberships WHERE organization_id=? AND user_id=? AND status='active'`
	if binding.SubjectKind == access.Team {
		query = `SELECT COUNT(*) FROM gwf_teams WHERE organization_id=? AND id=?`
	}
	if err = tx.QueryRowContext(ctx, query, binding.Scope.OrganizationID, binding.SubjectID).Scan(&exists); err != nil {
		return err
	}
	if exists != 1 {
		return errors.New("authsqlite: access subject is not active in organization")
	}
	if err = tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_organization_memberships WHERE organization_id=? AND user_id=? AND status='active'`, binding.Scope.OrganizationID, binding.GrantedBy).Scan(&exists); err != nil || exists != 1 {
		if err != nil {
			return err
		}
		return errors.New("authsqlite: grantor is not active in organization")
	}
	scopeQuery, arguments := `SELECT 1`, []any{}
	switch {
	case binding.Scope.ServiceID != "":
		scopeQuery, arguments = `SELECT COUNT(*) FROM gwf_application_services WHERE id=? AND environment_id=? AND project_id=? AND organization_id=?`, []any{binding.Scope.ServiceID, binding.Scope.EnvironmentID, binding.Scope.ProjectID, binding.Scope.OrganizationID}
	case binding.Scope.EnvironmentID != "":
		scopeQuery, arguments = `SELECT COUNT(*) FROM gwf_environments WHERE id=? AND project_id=? AND organization_id=?`, []any{binding.Scope.EnvironmentID, binding.Scope.ProjectID, binding.Scope.OrganizationID}
	case binding.Scope.ProjectID != "":
		scopeQuery, arguments = `SELECT COUNT(*) FROM gwf_projects WHERE id=? AND organization_id=?`, []any{binding.Scope.ProjectID, binding.Scope.OrganizationID}
	}
	if err = tx.QueryRowContext(ctx, scopeQuery, arguments...).Scan(&exists); err != nil {
		return err
	}
	if exists != 1 {
		return errors.New("authsqlite: access scope does not exist")
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_access_bindings(id,organization_id,subject_kind,subject_id,role_name,project_id,environment_id,service_id,granted_by_user_id,granted_at) VALUES(?,?,?,?,?,NULLIF(?,''),NULLIF(?,''),NULLIF(?,''),?,?)`, binding.ID, binding.Scope.OrganizationID, binding.SubjectKind, binding.SubjectID, binding.Role, binding.Scope.ProjectID, binding.Scope.EnvironmentID, binding.Scope.ServiceID, binding.GrantedBy, binding.GrantedAt.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) Revoke(ctx context.Context, bindingID, actorUserID string, when time.Time) error {
	if !opaqueID(bindingID) || !opaqueID(actorUserID) || when.IsZero() {
		return errors.New("authsqlite: invalid access revocation")
	}
	result, err := store.db.ExecContext(ctx, `UPDATE gwf_access_bindings SET revoked_by_user_id=?,revoked_at=? WHERE id=? AND revoked_at IS NULL`, actorUserID, when.Unix(), bindingID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("authsqlite: access binding not found")
	}
	return nil
}

func (store *Store) EffectiveBindings(ctx context.Context, organizationID, userID string) ([]access.Binding, error) {
	if !opaqueID(organizationID) || !opaqueID(userID) {
		return nil, errors.New("authsqlite: invalid access query")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT b.id,b.subject_kind,b.subject_id,b.role_name,b.project_id,b.environment_id,b.service_id,b.granted_by_user_id,b.granted_at
		FROM gwf_access_bindings b
		WHERE b.organization_id=? AND b.revoked_at IS NULL
		AND EXISTS (SELECT 1 FROM gwf_organization_memberships m WHERE m.organization_id=b.organization_id AND m.user_id=? AND m.status='active')
		AND ((b.subject_kind='user' AND b.subject_id=?) OR (b.subject_kind='team' AND EXISTS (SELECT 1 FROM gwf_team_members tm JOIN gwf_teams t ON t.id=tm.team_id WHERE tm.team_id=b.subject_id AND tm.user_id=? AND t.organization_id=b.organization_id)))
		ORDER BY b.id`, organizationID, userID, userID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []access.Binding
	for rows.Next() {
		var binding access.Binding
		var project, environment, service sql.NullString
		var granted int64
		if err = rows.Scan(&binding.ID, &binding.SubjectKind, &binding.SubjectID, &binding.Role, &project, &environment, &service, &binding.GrantedBy, &granted); err != nil {
			return nil, err
		}
		binding.Scope = access.Scope{OrganizationID: organizationID, ProjectID: project.String, EnvironmentID: environment.String, ServiceID: service.String}
		binding.GrantedAt = time.Unix(granted, 0).UTC()
		result = append(result, binding)
	}
	return result, rows.Err()
}

func (store *Store) CreateBreakGlass(ctx context.Context, grant access.BreakGlass, audit access.AuditEvent) error {
	if !validBreakGlass(grant) || !validAccessAudit(audit) || audit.OrganizationID != grant.OrganizationID || audit.ActorUserID != grant.UserID {
		return errors.New("authsqlite: invalid break-glass event")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_break_glass(id,organization_id,user_id,permission_name,reason,created_at,expires_at) VALUES(?,?,?,?,?,?,?)`, grant.ID, grant.OrganizationID, grant.UserID, grant.Permission, grant.Reason, grant.CreatedAt.Unix(), grant.ExpiresAt.Unix()); err != nil {
		return err
	}
	if err = appendAccessAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) ActiveBreakGlass(ctx context.Context, organizationID, userID string, now time.Time) ([]access.BreakGlass, error) {
	if !opaqueID(organizationID) || !opaqueID(userID) || now.IsZero() {
		return nil, errors.New("authsqlite: invalid break-glass query")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT id,permission_name,reason,created_at,expires_at FROM gwf_break_glass WHERE organization_id=? AND user_id=? AND expires_at>? ORDER BY expires_at`, organizationID, userID, now.Unix())
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []access.BreakGlass
	for rows.Next() {
		var grant access.BreakGlass
		var created, expires int64
		if err = rows.Scan(&grant.ID, &grant.Permission, &grant.Reason, &created, &expires); err != nil {
			return nil, err
		}
		grant.OrganizationID, grant.UserID = organizationID, userID
		grant.CreatedAt, grant.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
		result = append(result, grant)
	}
	return result, rows.Err()
}

func (store *Store) AppendAccessAudit(ctx context.Context, audit access.AuditEvent) error {
	if !validAccessAudit(audit) {
		return errors.New("authsqlite: invalid access audit")
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO gwf_access_audit_events(id,organization_id,actor_user_id,action,resource_type,resource_id,request_id,summary,created_at) VALUES(?,?,?,?,?,?,NULLIF(?,''),?,?)`, audit.ID, audit.OrganizationID, audit.ActorUserID, audit.Action, audit.ResourceType, audit.ResourceID, audit.RequestID, audit.Summary, audit.CreatedAt.Unix())
	return err
}

func (store *Store) AccessAudit(ctx context.Context, organizationID string, limit int) ([]access.AuditEvent, error) {
	if !opaqueID(organizationID) || limit < 1 || limit > 1000 {
		return nil, errors.New("authsqlite: invalid access audit query")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT id,actor_user_id,action,resource_type,resource_id,request_id,summary,created_at FROM gwf_access_audit_events WHERE organization_id=? ORDER BY created_at DESC,id DESC LIMIT ?`, organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []access.AuditEvent
	for rows.Next() {
		var event access.AuditEvent
		var requestID sql.NullString
		var created int64
		if err = rows.Scan(&event.ID, &event.ActorUserID, &event.Action, &event.ResourceType, &event.ResourceID, &requestID, &event.Summary, &created); err != nil {
			return nil, err
		}
		event.OrganizationID = organizationID
		event.RequestID = requestID.String
		event.CreatedAt = time.Unix(created, 0).UTC()
		result = append(result, event)
	}
	return result, rows.Err()
}

func appendAccessAudit(ctx context.Context, tx *sql.Tx, audit access.AuditEvent) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO gwf_access_audit_events(id,organization_id,actor_user_id,action,resource_type,resource_id,request_id,summary,created_at) VALUES(?,?,?,?,?,?,NULLIF(?,''),?,?)`, audit.ID, audit.OrganizationID, audit.ActorUserID, audit.Action, audit.ResourceType, audit.ResourceID, audit.RequestID, audit.Summary, audit.CreatedAt.Unix())
	return err
}

func validBreakGlass(grant access.BreakGlass) bool {
	return opaqueID(grant.ID) && opaqueID(grant.OrganizationID) && opaqueID(grant.UserID) && safeName(grant.Permission) && text(grant.Reason, 1024, false) && !grant.CreatedAt.IsZero() && grant.ExpiresAt.After(grant.CreatedAt) && grant.ExpiresAt.Sub(grant.CreatedAt) <= time.Hour
}

func validAccessAudit(audit access.AuditEvent) bool {
	return opaqueID(audit.ID) && opaqueID(audit.OrganizationID) && opaqueID(audit.ActorUserID) && safeName(audit.Action) && safeName(audit.ResourceType) && text(audit.ResourceID, 256, false) && text(audit.RequestID, 128, true) && text(audit.Summary, 1024, true) && !audit.CreatedAt.IsZero()
}
