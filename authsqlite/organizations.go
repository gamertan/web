// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"context"
	"database/sql"
	"errors"
	"time"

	"gamertan.com/web/organizations"
)

func (store *Store) CreateOrganization(ctx context.Context, organization organizations.Organization, owner organizations.Membership) error {
	if !opaqueID(organization.ID) || !slugValue(organization.Slug) || !text(organization.Name, 128, false) || organization.CreatedAt.IsZero() || owner.OrganizationID != organization.ID || !opaqueID(owner.UserID) || owner.Status != "active" || owner.JoinedAt.IsZero() {
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
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organizations(id,slug,name,personal,personal_owner_user_id,created_at) VALUES(?,?,?,?,?,?)`, organization.ID, organization.Slug, organization.Name, organization.Personal, personalOwner, organization.CreatedAt.Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organization_memberships(organization_id,user_id,status,joined_at) VALUES(?,?,?,?)`, owner.OrganizationID, owner.UserID, owner.Status, owner.JoinedAt.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) CreateTeam(ctx context.Context, team organizations.Team) error {
	if !opaqueID(team.ID) || !opaqueID(team.OrganizationID) || !slugValue(team.Slug) || !text(team.Name, 128, false) || team.CreatedAt.IsZero() {
		return errors.New("authsqlite: invalid team")
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO gwf_teams(id,organization_id,slug,name,created_at) VALUES(?,?,?,?,?)`, team.ID, team.OrganizationID, team.Slug, team.Name, team.CreatedAt.Unix())
	return err
}

func (store *Store) AddTeamMember(ctx context.Context, membership organizations.TeamMembership) error {
	if !opaqueID(membership.TeamID) || !opaqueID(membership.UserID) || membership.JoinedAt.IsZero() {
		return errors.New("authsqlite: invalid team membership")
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO gwf_team_members(team_id,user_id,joined_at)
		SELECT t.id,?,? FROM gwf_teams t
		JOIN gwf_organization_memberships m ON m.organization_id=t.organization_id AND m.user_id=? AND m.status='active'
		WHERE t.id=? ON CONFLICT(team_id,user_id) DO UPDATE SET joined_at=gwf_team_members.joined_at`, membership.UserID, membership.JoinedAt.Unix(), membership.UserID, membership.TeamID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrMembershipNotFound
	}
	return nil
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

func (store *Store) CreateInvitation(ctx context.Context, invitation organizations.Invitation) error {
	if zeroDigest(invitation.Digest) || !opaqueID(invitation.OrganizationID) || !text(invitation.Email, 320, false) || !opaqueID(invitation.InvitedByUserID) || invitation.CreatedAt.IsZero() || !invitation.ExpiresAt.After(invitation.CreatedAt) || !invitation.UsedAt.IsZero() {
		return errors.New("authsqlite: invalid invitation")
	}
	result, err := store.db.ExecContext(ctx, `INSERT INTO gwf_organization_invitations(token_hash,organization_id,email_normalized,invited_by_user_id,created_at,expires_at)
		SELECT ?,?,?,?,?,? FROM gwf_organization_memberships
		WHERE organization_id=? AND user_id=? AND status='active'`, invitation.Digest[:], invitation.OrganizationID, normalize(invitation.Email), invitation.InvitedByUserID, invitation.CreatedAt.Unix(), invitation.ExpiresAt.Unix(), invitation.OrganizationID, invitation.InvitedByUserID)
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrMembershipNotFound
	}
	return nil
}

func (store *Store) InvitationByDigest(ctx context.Context, digest [32]byte, now time.Time) (organizations.Invitation, error) {
	if zeroDigest(digest) || now.IsZero() {
		return organizations.Invitation{}, organizations.ErrInvitationNotFound
	}
	var invitation organizations.Invitation
	var created, expires int64
	err := store.db.QueryRowContext(ctx, `SELECT organization_id,email_normalized,invited_by_user_id,created_at,expires_at FROM gwf_organization_invitations WHERE token_hash=? AND used_at IS NULL AND expires_at>?`, digest[:], now.Unix()).Scan(&invitation.OrganizationID, &invitation.Email, &invitation.InvitedByUserID, &created, &expires)
	if errors.Is(err, sql.ErrNoRows) {
		return organizations.Invitation{}, organizations.ErrInvitationNotFound
	}
	if err != nil {
		return organizations.Invitation{}, err
	}
	invitation.Digest = digest
	invitation.CreatedAt = time.Unix(created, 0).UTC()
	invitation.ExpiresAt = time.Unix(expires, 0).UTC()
	return invitation, nil
}

func (store *Store) AcceptInvitation(ctx context.Context, digest [32]byte, userID string, acceptedAt time.Time) error {
	if zeroDigest(digest) || !opaqueID(userID) || acceptedAt.IsZero() {
		return organizations.ErrInvitationNotFound
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var organizationID string
	err = tx.QueryRowContext(ctx, `SELECT i.organization_id FROM gwf_organization_invitations i JOIN gwf_users u ON u.id=? AND u.email_normalized=i.email_normalized WHERE i.token_hash=? AND i.used_at IS NULL AND i.expires_at>?`, userID, digest[:], acceptedAt.Unix()).Scan(&organizationID)
	if errors.Is(err, sql.ErrNoRows) {
		return organizations.ErrInvitationNotFound
	}
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_organization_memberships(organization_id,user_id,status,joined_at) VALUES(?,?,'active',?) ON CONFLICT(organization_id,user_id) DO UPDATE SET status='active'`, organizationID, userID, acceptedAt.Unix()); err != nil {
		return err
	}
	result, err := tx.ExecContext(ctx, `UPDATE gwf_organization_invitations SET used_at=? WHERE token_hash=? AND used_at IS NULL`, acceptedAt.Unix(), digest[:])
	if err != nil {
		return err
	}
	if changed, _ := result.RowsAffected(); changed != 1 {
		return organizations.ErrInvitationNotFound
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
	rows, err := store.db.QueryContext(ctx, `SELECT t.id,t.slug,t.name,t.created_at FROM gwf_teams t JOIN gwf_team_members tm ON tm.team_id=t.id WHERE t.organization_id=? AND tm.user_id=? ORDER BY t.slug`, organizationID, userID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []organizations.Team
	for rows.Next() {
		var team organizations.Team
		var created int64
		if err = rows.Scan(&team.ID, &team.Slug, &team.Name, &created); err != nil {
			return nil, err
		}
		team.OrganizationID = organizationID
		team.CreatedAt = time.Unix(created, 0).UTC()
		result = append(result, team)
	}
	return result, rows.Err()
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
