// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"time"

	"gamertan.com/web/organizations"
)

func (store *Store) CreateOrganization(ctx context.Context, organization organizations.Organization, owner organizations.Membership, audit organizations.AuditEvent) error {
	if !validOrganization(organization) || owner.OrganizationID != organization.ID || !opaqueID(owner.UserID) || owner.Status != "active" || owner.JoinedAt.IsZero() || !validOrganizationAudit(audit, organization.ID) {
		return errors.New("authsqlite: invalid organization")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var personalOwner any
	if organization.Personal {
		personalOwner = owner.UserID
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organizations(id,slug,name,personal,personal_owner_user_id,created_at,status,revision,updated_at) VALUES(?,?,?,?,?,?,?,?,?)`, organization.ID, organization.Slug, organization.Name, organization.Personal, personalOwner, organization.CreatedAt.Unix(), organization.Status, organization.Revision, organization.UpdatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organization_memberships(organization_id,user_id,status,joined_at) VALUES(?,?,?,?)`, owner.OrganizationID, owner.UserID, owner.Status, owner.JoinedAt.Unix()); err != nil {
		return err
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) CreateTeam(ctx context.Context, team organizations.Team, audit organizations.AuditEvent) error {
	if !validTeam(team) || !validOrganizationAudit(audit, team.OrganizationID) {
		return errors.New("authsqlite: invalid team")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO gwf_teams(id,organization_id,slug,name,created_at,status,revision,updated_at) SELECT ?,?,?,?,?,?,?,? FROM gwf_organizations WHERE id=? AND status='active'`, team.ID, team.OrganizationID, team.Slug, team.Name, team.CreatedAt.Unix(), team.Status, team.Revision, team.UpdatedAt.Unix(), team.OrganizationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrOrganizationNotFound
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) AddTeamMember(ctx context.Context, membership organizations.TeamMembership, audit organizations.AuditEvent) error {
	if !opaqueID(membership.TeamID) || !opaqueID(membership.UserID) || membership.JoinedAt.IsZero() || !validOrganizationAudit(audit, audit.OrganizationID) {
		return errors.New("authsqlite: invalid team membership")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `INSERT INTO gwf_team_members(team_id,user_id,joined_at)
		SELECT t.id,?,? FROM gwf_teams t
		JOIN gwf_organization_memberships m ON m.organization_id=t.organization_id AND m.user_id=? AND m.status='active'
		JOIN gwf_organizations o ON o.id=t.organization_id AND o.status='active'
		WHERE t.id=? AND t.status='active' AND t.organization_id=? ON CONFLICT(team_id,user_id) DO UPDATE SET joined_at=gwf_team_members.joined_at`, membership.UserID, membership.JoinedAt.Unix(), membership.UserID, membership.TeamID, audit.OrganizationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrMembershipNotFound
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) CreateProject(ctx context.Context, project organizations.Project) error {
	if !opaqueID(project.ID) || !opaqueID(project.OrganizationID) || !slugValue(project.Slug) || !text(project.Name, 128, false) || project.CreatedAt.IsZero() {
		return errors.New("authsqlite: invalid project")
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO gwf_projects(id,organization_id,slug,name,created_at) VALUES(?,?,?,?,?)`, project.ID, project.OrganizationID, project.Slug, project.Name, project.CreatedAt.Unix())
	return err
}

func (store *Store) CreateEnvironment(ctx context.Context, environment organizations.Environment) error {
	if !opaqueID(environment.ID) || !opaqueID(environment.OrganizationID) || !opaqueID(environment.ProjectID) || !slugValue(environment.Slug) || !text(environment.Name, 128, false) || environment.CreatedAt.IsZero() {
		return errors.New("authsqlite: invalid environment")
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO gwf_environments(id,organization_id,project_id,slug,name,created_at)
		SELECT ?,?,?,?,?,? FROM gwf_projects WHERE id=? AND organization_id=?`, environment.ID, environment.OrganizationID, environment.ProjectID, environment.Slug, environment.Name, environment.CreatedAt.Unix(), environment.ProjectID, environment.OrganizationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("authsqlite: project is outside organization")
	}
	return nil
}

func (store *Store) CreateApplicationService(ctx context.Context, application organizations.ApplicationService) error {
	if !opaqueID(application.ID) || !opaqueID(application.OrganizationID) || !opaqueID(application.ProjectID) || !opaqueID(application.EnvironmentID) || !slugValue(application.Slug) || !text(application.Name, 128, false) || application.CreatedAt.IsZero() {
		return errors.New("authsqlite: invalid application service")
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO gwf_application_services(id,organization_id,project_id,environment_id,slug,name,created_at)
		SELECT ?,?,?,?,?,?,? FROM gwf_environments WHERE id=? AND project_id=? AND organization_id=?`, application.ID, application.OrganizationID, application.ProjectID, application.EnvironmentID, application.Slug, application.Name, application.CreatedAt.Unix(), application.EnvironmentID, application.ProjectID, application.OrganizationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return errors.New("authsqlite: environment is outside project")
	}
	return nil
}

func (store *Store) CreateInvitation(ctx context.Context, invitation organizations.Invitation, audit organizations.AuditEvent) error {
	if !opaqueID(invitation.ID) || zeroDigest(invitation.Digest) || !opaqueID(invitation.OrganizationID) || !text(invitation.Email, 320, false) || !opaqueID(invitation.InvitedByUserID) || invitation.DirectRole != "" && !safeName(invitation.DirectRole) || !validInvitationTeamIDs(invitation.TeamIDs) || invitation.CreatedAt.IsZero() || !invitation.ExpiresAt.After(invitation.CreatedAt) || !invitation.UsedAt.IsZero() || !invitation.RevokedAt.IsZero() || !validOrganizationAudit(audit, invitation.OrganizationID) {
		return errors.New("authsqlite: invalid invitation")
	}
	teamIDs, err := json.Marshal(invitation.TeamIDs)
	if err != nil {
		return err
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = validateInvitationTeams(ctx, tx, invitation.OrganizationID, invitation.TeamIDs); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `INSERT INTO gwf_organization_invitations(token_hash,organization_id,email_normalized,invited_by_user_id,created_at,expires_at,id,direct_role,team_ids_json)
		SELECT ?,?,?,?,?,?,?,?,? FROM gwf_organization_memberships m JOIN gwf_organizations o ON o.id=m.organization_id
		WHERE m.organization_id=? AND m.user_id=? AND m.status='active' AND o.status='active'`, invitation.Digest[:], invitation.OrganizationID, normalize(invitation.Email), invitation.InvitedByUserID, invitation.CreatedAt.Unix(), invitation.ExpiresAt.Unix(), invitation.ID, invitation.DirectRole, teamIDs, invitation.OrganizationID, invitation.InvitedByUserID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrMembershipNotFound
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) InvitationByDigest(ctx context.Context, digest [32]byte, now time.Time) (organizations.Invitation, error) {
	if zeroDigest(digest) || now.IsZero() {
		return organizations.Invitation{}, organizations.ErrInvitationNotFound
	}
	var invitation organizations.Invitation
	var created, expires int64
	var teamIDs []byte
	err := store.db.QueryRowContext(ctx, `SELECT id,organization_id,email_normalized,invited_by_user_id,direct_role,team_ids_json,created_at,expires_at FROM gwf_organization_invitations WHERE token_hash=? AND used_at IS NULL AND revoked_at IS NULL AND expires_at>?`, digest[:], now.Unix()).Scan(&invitation.ID, &invitation.OrganizationID, &invitation.Email, &invitation.InvitedByUserID, &invitation.DirectRole, &teamIDs, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return organizations.Invitation{}, organizations.ErrInvitationNotFound
	}
	if err != nil {
		return organizations.Invitation{}, err
	}
	invitation.Digest = digest
	if err = json.Unmarshal(teamIDs, &invitation.TeamIDs); err != nil || !validInvitationTeamIDs(invitation.TeamIDs) {
		return organizations.Invitation{}, organizations.ErrInvitationNotFound
	}
	invitation.CreatedAt = time.Unix(created, 0).UTC()
	invitation.ExpiresAt = time.Unix(expires, 0).UTC()
	return invitation, nil
}

func (store *Store) AcceptInvitation(ctx context.Context, digest [32]byte, userID string, acceptedAt time.Time, audit organizations.AuditEvent) error {
	if zeroDigest(digest) || !opaqueID(userID) || acceptedAt.IsZero() || !validOrganizationAudit(audit, audit.OrganizationID) {
		return organizations.ErrInvitationNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var invitationID, organizationID, directRole, invitedBy string
	var teamIDsJSON []byte
	err = tx.QueryRowContext(ctx, `SELECT i.id,i.organization_id,i.direct_role,i.team_ids_json,i.invited_by_user_id FROM gwf_organization_invitations i JOIN gwf_users u ON u.id=? AND u.email_normalized=i.email_normalized JOIN gwf_organizations o ON o.id=i.organization_id AND o.status='active' WHERE i.token_hash=? AND i.used_at IS NULL AND i.revoked_at IS NULL AND i.expires_at>?`, userID, digest[:], acceptedAt.Unix()).Scan(&invitationID, &organizationID, &directRole, &teamIDsJSON, &invitedBy)
	if errors.Is(err, sql.ErrNoRows) {
		return organizations.ErrInvitationNotFound
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organization_memberships(organization_id,user_id,status,joined_at) VALUES(?,?,'active',?) ON CONFLICT(organization_id,user_id) DO UPDATE SET status='active'`, organizationID, userID, acceptedAt.Unix()); err != nil {
		return err
	}
	var teamIDs []string
	if json.Unmarshal(teamIDsJSON, &teamIDs) != nil || !validInvitationTeamIDs(teamIDs) {
		return organizations.ErrInvitationNotFound
	}
	if err = validateInvitationTeams(ctx, tx, organizationID, teamIDs); err != nil {
		return organizations.ErrInvitationNotFound
	}
	for _, teamID := range teamIDs {
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_team_members(team_id,user_id,joined_at) VALUES(?,?,?) ON CONFLICT(team_id,user_id) DO NOTHING`, teamID, userID, acceptedAt.Unix()); err != nil {
			return err
		}
	}
	if directRole != "" {
		if !safeName(directRole) {
			return organizations.ErrInvitationNotFound
		}
		result, err := tx.ExecContext(ctx, `INSERT INTO gwf_access_bindings(id,organization_id,subject_kind,subject_id,role_name,project_id,environment_id,service_id,granted_by_user_id,granted_at) SELECT ?,?,'user',?,?,NULL,NULL,NULL,?,? FROM gwf_access_roles WHERE name=?`, "invite-"+invitationID, organizationID, userID, directRole, invitedBy, acceptedAt.Unix(), directRole)
		if err != nil {
			return err
		}
		if changed, _ := result.RowsAffected(); changed != 1 {
			return organizations.ErrInvitationNotFound
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE gwf_organization_invitations SET used_at=? WHERE token_hash=? AND used_at IS NULL`, acceptedAt.Unix(), digest[:])
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrInvitationNotFound
	}
	if organizationID != audit.OrganizationID {
		return organizations.ErrInvitationNotFound
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) MembershipsForUser(ctx context.Context, userID string) ([]organizations.Membership, error) {
	if !opaqueID(userID) {
		return nil, errors.New("authsqlite: invalid user")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT organization_id,status,joined_at FROM gwf_organization_memberships WHERE user_id=? ORDER BY organization_id`, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []organizations.Membership
	for rows.Next() {
		var membership organizations.Membership
		var joined int64
		if err = rows.Scan(&membership.OrganizationID, &membership.Status, &joined); err != nil {
			return nil, err
		}
		membership.UserID = userID
		membership.JoinedAt = time.Unix(joined, 0).UTC()
		result = append(result, membership)
	}
	return result, rows.Err()
}

func (store *Store) TeamsForUser(ctx context.Context, organizationID, userID string) ([]organizations.Team, error) {
	if !opaqueID(organizationID) || !opaqueID(userID) {
		return nil, errors.New("authsqlite: invalid team query")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT t.id,t.slug,t.name,t.status,t.revision,t.created_at,t.updated_at FROM gwf_teams t JOIN gwf_team_members tm ON tm.team_id=t.id JOIN gwf_organizations o ON o.id=t.organization_id WHERE t.organization_id=? AND tm.user_id=? AND t.status='active' AND o.status='active' ORDER BY t.slug`, organizationID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []organizations.Team
	for rows.Next() {
		var team organizations.Team
		var created, updated int64
		if err = rows.Scan(&team.ID, &team.Slug, &team.Name, &team.Status, &team.Revision, &created, &updated); err != nil {
			return nil, err
		}
		team.OrganizationID = organizationID
		team.CreatedAt = time.Unix(created, 0).UTC()
		team.UpdatedAt = time.Unix(updated, 0).UTC()
		result = append(result, team)
	}
	return result, rows.Err()
}

func (store *Store) OrganizationByID(ctx context.Context, organizationID string) (organizations.Organization, error) {
	if !opaqueID(organizationID) {
		return organizations.Organization{}, organizations.ErrOrganizationNotFound
	}
	var value organizations.Organization
	var personal int
	var created, updated int64
	err := store.db.QueryRowContext(ctx, `SELECT id,slug,name,status,personal,revision,created_at,updated_at FROM gwf_organizations WHERE id=?`, organizationID).Scan(&value.ID, &value.Slug, &value.Name, &value.Status, &personal, &value.Revision, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return organizations.Organization{}, organizations.ErrOrganizationNotFound
	}
	if err != nil {
		return organizations.Organization{}, err
	}
	value.Personal = personal == 1
	value.CreatedAt, value.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return value, nil
}

func (store *Store) UpdateOrganization(ctx context.Context, value organizations.Organization, expectedRevision int64, audit organizations.AuditEvent) error {
	if !validOrganization(value) || expectedRevision < 1 || value.Revision != expectedRevision+1 || !validOrganizationAudit(audit, value.ID) {
		return errors.New("authsqlite: invalid organization update")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE gwf_organizations SET slug=?,name=?,status=?,revision=?,updated_at=? WHERE id=? AND revision=?`, value.Slug, value.Name, value.Status, value.Revision, value.UpdatedAt.Unix(), value.ID, expectedRevision)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrRevisionConflict
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) TeamByID(ctx context.Context, organizationID, teamID string) (organizations.Team, error) {
	if !opaqueID(teamID) || organizationID != "" && !opaqueID(organizationID) {
		return organizations.Team{}, organizations.ErrTeamNotFound
	}
	query := `SELECT id,organization_id,slug,name,status,revision,created_at,updated_at FROM gwf_teams WHERE id=?`
	args := []any{teamID}
	if organizationID != "" {
		query += ` AND organization_id=?`
		args = append(args, organizationID)
	}
	var value organizations.Team
	var created, updated int64
	err := store.db.QueryRowContext(ctx, query, args...).Scan(&value.ID, &value.OrganizationID, &value.Slug, &value.Name, &value.Status, &value.Revision, &created, &updated)
	if errors.Is(err, sql.ErrNoRows) {
		return organizations.Team{}, organizations.ErrTeamNotFound
	}
	if err != nil {
		return organizations.Team{}, err
	}
	value.CreatedAt, value.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return value, nil
}

func (store *Store) UpdateTeam(ctx context.Context, value organizations.Team, expectedRevision int64, audit organizations.AuditEvent) error {
	if !validTeam(value) || expectedRevision < 1 || value.Revision != expectedRevision+1 || !validOrganizationAudit(audit, value.OrganizationID) {
		return errors.New("authsqlite: invalid team update")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE gwf_teams SET slug=?,name=?,status=?,revision=?,updated_at=? WHERE id=? AND organization_id=? AND revision=?`, value.Slug, value.Name, value.Status, value.Revision, value.UpdatedAt.Unix(), value.ID, value.OrganizationID, expectedRevision)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrRevisionConflict
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) RemoveTeamMember(ctx context.Context, teamID, userID string, audit organizations.AuditEvent) error {
	if !opaqueID(teamID) || !opaqueID(userID) || !validOrganizationAudit(audit, audit.OrganizationID) {
		return organizations.ErrMembershipNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `DELETE FROM gwf_team_members WHERE team_id=? AND user_id=? AND EXISTS (SELECT 1 FROM gwf_teams WHERE id=? AND organization_id=?)`, teamID, userID, teamID, audit.OrganizationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrMembershipNotFound
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) SetMembershipStatus(ctx context.Context, organizationID, userID, status, ownerRole string, audit organizations.AuditEvent) error {
	if !opaqueID(organizationID) || !opaqueID(userID) || (status != "active" && status != "suspended") || status != "active" && !safeName(ownerRole) || !validOrganizationAudit(audit, organizationID) {
		return organizations.ErrMembershipNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if status != "active" {
		if err = protectLastOwner(ctx, tx, organizationID, userID, ownerRole); err != nil {
			return err
		}
	}
	result, err := tx.ExecContext(ctx, `UPDATE gwf_organization_memberships SET status=? WHERE organization_id=? AND user_id=?`, status, organizationID, userID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrMembershipNotFound
	}
	if status != "active" {
		if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_team_members WHERE user_id=? AND team_id IN (SELECT id FROM gwf_teams WHERE organization_id=?)`, userID, organizationID); err != nil {
			return err
		}
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) RemoveMembership(ctx context.Context, organizationID, userID, ownerRole string, audit organizations.AuditEvent) error {
	if !opaqueID(organizationID) || !opaqueID(userID) || !safeName(ownerRole) || !validOrganizationAudit(audit, organizationID) {
		return organizations.ErrMembershipNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if err = protectLastOwner(ctx, tx, organizationID, userID, ownerRole); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_team_members WHERE user_id=? AND team_id IN (SELECT id FROM gwf_teams WHERE organization_id=?)`, userID, organizationID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `UPDATE gwf_access_bindings SET revoked_by_user_id=?,revoked_at=? WHERE organization_id=? AND subject_kind='user' AND subject_id=? AND revoked_at IS NULL`, audit.ActorUserID, audit.CreatedAt.Unix(), organizationID, userID); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `DELETE FROM gwf_organization_memberships WHERE organization_id=? AND user_id=?`, organizationID, userID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrMembershipNotFound
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func protectLastOwner(ctx context.Context, tx *sql.Tx, organizationID, userID, ownerRole string) error {
	var targetIsOwner int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_access_bindings WHERE organization_id=? AND subject_kind='user' AND subject_id=? AND role_name=? AND project_id IS NULL AND environment_id IS NULL AND service_id IS NULL AND revoked_at IS NULL`, organizationID, userID, ownerRole).Scan(&targetIsOwner); err != nil {
		return err
	}
	if targetIsOwner == 0 {
		return nil
	}
	var activeOwners int
	if err := tx.QueryRowContext(ctx, `SELECT COUNT(DISTINCT b.subject_id) FROM gwf_access_bindings b JOIN gwf_organization_memberships m ON m.organization_id=b.organization_id AND m.user_id=b.subject_id AND m.status='active' WHERE b.organization_id=? AND b.subject_kind='user' AND b.role_name=? AND b.project_id IS NULL AND b.environment_id IS NULL AND b.service_id IS NULL AND b.revoked_at IS NULL`, organizationID, ownerRole).Scan(&activeOwners); err != nil {
		return err
	}
	if activeOwners <= 1 {
		return organizations.ErrLastOwner
	}
	return nil
}

func (store *Store) Invitations(ctx context.Context, organizationID string, limit int) ([]organizations.Invitation, error) {
	if !opaqueID(organizationID) || limit < 1 || limit > 1000 {
		return nil, errors.New("authsqlite: invalid invitation query")
	}
	rows, err := store.db.QueryContext(ctx, `SELECT id,email_normalized,invited_by_user_id,direct_role,team_ids_json,created_at,expires_at,COALESCE(used_at,0),COALESCE(revoked_at,0) FROM gwf_organization_invitations WHERE organization_id=? ORDER BY created_at DESC LIMIT ?`, organizationID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	result := make([]organizations.Invitation, 0)
	for rows.Next() {
		var value organizations.Invitation
		var created, expires, used, revoked int64
		var teamIDs []byte
		if err = rows.Scan(&value.ID, &value.Email, &value.InvitedByUserID, &value.DirectRole, &teamIDs, &created, &expires, &used, &revoked); err != nil {
			return nil, err
		}
		if json.Unmarshal(teamIDs, &value.TeamIDs) != nil || !validInvitationTeamIDs(value.TeamIDs) {
			return nil, errors.New("authsqlite: stored invitation is invalid")
		}
		value.OrganizationID = organizationID
		value.CreatedAt, value.ExpiresAt = time.Unix(created, 0).UTC(), time.Unix(expires, 0).UTC()
		if used != 0 {
			value.UsedAt = time.Unix(used, 0).UTC()
		}
		if revoked != 0 {
			value.RevokedAt = time.Unix(revoked, 0).UTC()
		}
		result = append(result, value)
	}
	return result, rows.Err()
}

func validInvitationTeamIDs(teamIDs []string) bool {
	if len(teamIDs) > 16 {
		return false
	}
	seen := make(map[string]struct{}, len(teamIDs))
	for _, teamID := range teamIDs {
		if !opaqueID(teamID) {
			return false
		}
		if _, exists := seen[teamID]; exists {
			return false
		}
		seen[teamID] = struct{}{}
	}
	return true
}

func validateInvitationTeams(ctx context.Context, tx *sql.Tx, organizationID string, teamIDs []string) error {
	for _, teamID := range teamIDs {
		var count int
		if err := tx.QueryRowContext(ctx, `SELECT COUNT(*) FROM gwf_teams WHERE id=? AND organization_id=? AND status='active'`, teamID, organizationID).Scan(&count); err != nil {
			return err
		}
		if count != 1 {
			return organizations.ErrTeamNotFound
		}
	}
	return nil
}

func (store *Store) RevokeInvitation(ctx context.Context, organizationID, invitationID string, revokedAt time.Time, audit organizations.AuditEvent) error {
	if !opaqueID(organizationID) || !opaqueID(invitationID) || revokedAt.IsZero() || !validOrganizationAudit(audit, organizationID) {
		return organizations.ErrInvitationNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE gwf_organization_invitations SET revoked_at=? WHERE organization_id=? AND id=? AND used_at IS NULL AND revoked_at IS NULL`, revokedAt.Unix(), organizationID, invitationID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrInvitationNotFound
	}
	if err = appendOrganizationAudit(ctx, tx, audit); err != nil {
		return err
	}
	return tx.Commit()
}

func validOrganization(value organizations.Organization) bool {
	return opaqueID(value.ID) && slugValue(value.Slug) && text(value.Name, 128, false) && (value.Status == "active" || value.Status == "archived") && value.Revision > 0 && !value.CreatedAt.IsZero() && !value.UpdatedAt.IsZero()
}

func validTeam(value organizations.Team) bool {
	return opaqueID(value.ID) && opaqueID(value.OrganizationID) && slugValue(value.Slug) && text(value.Name, 128, false) && (value.Status == "active" || value.Status == "archived") && value.Revision > 0 && !value.CreatedAt.IsZero() && !value.UpdatedAt.IsZero()
}

func validOrganizationAudit(value organizations.AuditEvent, organizationID string) bool {
	return opaqueID(value.ID) && opaqueID(organizationID) && value.OrganizationID == organizationID && opaqueID(value.ActorUserID) && text(value.Action, 128, false) && text(value.ResourceType, 128, false) && text(value.ResourceID, 128, false) && text(value.RequestID, 128, true) && text(value.Summary, 512, false) && !value.CreatedAt.IsZero()
}

func appendOrganizationAudit(ctx context.Context, tx *sql.Tx, value organizations.AuditEvent) error {
	_, err := tx.ExecContext(ctx, `INSERT INTO gwf_access_audit_events(id,organization_id,actor_user_id,action,resource_type,resource_id,request_id,summary,created_at) VALUES(?,?,?,?,?,?,NULLIF(?,''),?,?)`, value.ID, value.OrganizationID, value.ActorUserID, value.Action, value.ResourceType, value.ResourceID, value.RequestID, value.Summary, value.CreatedAt.Unix())
	return err
}

func slugValue(value string) bool {
	if len(value) < 2 || len(value) > 63 || (value[0] < 'a' || value[0] > 'z') && (value[0] < '0' || value[0] > '9') {
		return false
	}
	for _, character := range value {
		if character != '-' && (character < 'a' || character > 'z') && (character < '0' || character > '9') {
			return false
		}
	}
	return true
}
