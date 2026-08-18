// SPDX-License-Identifier: MPL-2.0

// Package authsqlite implements auth.Repository using a private no-CGO SQLite
// database and a namespaced schema.
package authsqlite

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
	"unicode/utf8"

	"gamertan.com/web/auth"
	_ "modernc.org/sqlite"
)

type Store struct{ db *sql.DB }

func Open(path string) (*Store, error) {
	absolute, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	if info, inspectErr := os.Lstat(absolute); inspectErr == nil {
		if info.Mode()&os.ModeSymlink != 0 || !info.Mode().IsRegular() {
			return nil, errors.New("authsqlite: database must be a regular file, not a symlink")
		}
		if err = os.Chmod(absolute, 0o600); err != nil {
			return nil, fmt.Errorf("authsqlite: secure database mode: %w", err)
		}
	} else if errors.Is(inspectErr, os.ErrNotExist) {
		file, createErr := os.OpenFile(absolute, os.O_CREATE|os.O_EXCL|os.O_RDWR, 0o600)
		if createErr != nil {
			return nil, fmt.Errorf("authsqlite: create private database: %w", createErr)
		}
		if closeErr := file.Close(); closeErr != nil {
			return nil, fmt.Errorf("authsqlite: create private database: %w", closeErr)
		}
	} else {
		return nil, inspectErr
	}
	dsn := (&url.URL{Scheme: "file", Path: filepath.ToSlash(absolute), RawQuery: "_pragma=busy_timeout(5000)&_pragma=foreign_keys(1)&_pragma=journal_mode(WAL)&_pragma=synchronous(FULL)"}).String()
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	db.SetMaxIdleConns(4)
	store := &Store{db: db}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
	defer cancel()
	if err = db.PingContext(ctx); err == nil {
		err = store.Migrate(ctx)
	}
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("authsqlite: open: %w", err)
	}
	return store, nil
}

func (store *Store) Close() error                   { return store.db.Close() }
func (store *Store) Ping(ctx context.Context) error { return store.db.PingContext(ctx) }

func (store *Store) Migrate(ctx context.Context) error {
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	statements := []string{
		`CREATE TABLE IF NOT EXISTS gamertan_web_migrations (version INTEGER PRIMARY KEY, applied_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS gwf_users (id TEXT PRIMARY KEY, username TEXT NOT NULL, username_normalized TEXT NOT NULL UNIQUE, email TEXT NOT NULL, email_normalized TEXT NOT NULL UNIQUE, display_name TEXT NOT NULL, status TEXT NOT NULL CHECK(status IN ('active','suspended','disabled')), password_change_required INTEGER NOT NULL DEFAULT 0 CHECK(password_change_required IN (0,1)), created_at INTEGER NOT NULL, updated_at INTEGER NOT NULL, last_login_at INTEGER)`,
		`CREATE TABLE IF NOT EXISTS gwf_password_credentials (user_id TEXT PRIMARY KEY REFERENCES gwf_users(id) ON DELETE CASCADE, password_hash TEXT NOT NULL, changed_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS gwf_roles (name TEXT PRIMARY KEY, description TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS gwf_permissions (name TEXT PRIMARY KEY, description TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS gwf_role_permissions (role_name TEXT NOT NULL REFERENCES gwf_roles(name) ON DELETE CASCADE, permission_name TEXT NOT NULL REFERENCES gwf_permissions(name) ON DELETE CASCADE, PRIMARY KEY(role_name,permission_name))`,
		`CREATE TABLE IF NOT EXISTS gwf_user_roles (user_id TEXT NOT NULL REFERENCES gwf_users(id) ON DELETE CASCADE, role_name TEXT NOT NULL REFERENCES gwf_roles(name) ON DELETE CASCADE, granted_at INTEGER NOT NULL, PRIMARY KEY(user_id,role_name))`,
		`CREATE TABLE IF NOT EXISTS gwf_auth_sessions (token_hash BLOB PRIMARY KEY, user_id TEXT NOT NULL REFERENCES gwf_users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, last_seen_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS gwf_auth_sessions_user ON gwf_auth_sessions(user_id)`,
		`CREATE INDEX IF NOT EXISTS gwf_auth_sessions_expiry ON gwf_auth_sessions(expires_at)`,
		`CREATE TABLE IF NOT EXISTS gwf_audit_events (id TEXT PRIMARY KEY, actor_user_id TEXT REFERENCES gwf_users(id) ON DELETE SET NULL, action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, request_id TEXT, summary TEXT NOT NULL, created_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS gwf_audit_created ON gwf_audit_events(created_at)`,
		`CREATE TABLE IF NOT EXISTS gwf_organizations (id TEXT PRIMARY KEY, slug TEXT NOT NULL UNIQUE, name TEXT NOT NULL, personal INTEGER NOT NULL CHECK(personal IN (0,1)), personal_owner_user_id TEXT UNIQUE REFERENCES gwf_users(id) ON DELETE CASCADE, created_at INTEGER NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS gwf_organization_memberships (organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES gwf_users(id) ON DELETE CASCADE, status TEXT NOT NULL CHECK(status IN ('active','suspended')), joined_at INTEGER NOT NULL, PRIMARY KEY(organization_id,user_id))`,
		`CREATE INDEX IF NOT EXISTS gwf_organization_memberships_user ON gwf_organization_memberships(user_id,organization_id)`,
		`CREATE TABLE IF NOT EXISTS gwf_teams (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, slug TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(organization_id,slug))`,
		`CREATE TABLE IF NOT EXISTS gwf_team_members (team_id TEXT NOT NULL REFERENCES gwf_teams(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES gwf_users(id) ON DELETE CASCADE, joined_at INTEGER NOT NULL, PRIMARY KEY(team_id,user_id))`,
		`CREATE INDEX IF NOT EXISTS gwf_team_members_user ON gwf_team_members(user_id,team_id)`,
		`CREATE TABLE IF NOT EXISTS gwf_projects (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, slug TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(organization_id,slug))`,
		`CREATE TABLE IF NOT EXISTS gwf_environments (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, project_id TEXT NOT NULL REFERENCES gwf_projects(id) ON DELETE CASCADE, slug TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(project_id,slug))`,
		`CREATE TABLE IF NOT EXISTS gwf_application_services (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, project_id TEXT NOT NULL REFERENCES gwf_projects(id) ON DELETE CASCADE, environment_id TEXT NOT NULL REFERENCES gwf_environments(id) ON DELETE CASCADE, slug TEXT NOT NULL, name TEXT NOT NULL, created_at INTEGER NOT NULL, UNIQUE(environment_id,slug))`,
		`CREATE TABLE IF NOT EXISTS gwf_organization_invitations (token_hash BLOB PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, email_normalized TEXT NOT NULL, invited_by_user_id TEXT NOT NULL REFERENCES gwf_users(id), created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL, used_at INTEGER)`,
		`CREATE INDEX IF NOT EXISTS gwf_organization_invitations_expiry ON gwf_organization_invitations(expires_at)`,
		`CREATE TABLE IF NOT EXISTS gwf_access_roles (name TEXT PRIMARY KEY, description TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS gwf_access_permissions (name TEXT PRIMARY KEY, description TEXT NOT NULL)`,
		`CREATE TABLE IF NOT EXISTS gwf_access_role_permissions (role_name TEXT NOT NULL REFERENCES gwf_access_roles(name) ON DELETE CASCADE, permission_name TEXT NOT NULL REFERENCES gwf_access_permissions(name) ON DELETE CASCADE, PRIMARY KEY(role_name,permission_name))`,
		`CREATE TABLE IF NOT EXISTS gwf_access_bindings (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, subject_kind TEXT NOT NULL CHECK(subject_kind IN ('user','team')), subject_id TEXT NOT NULL, role_name TEXT NOT NULL REFERENCES gwf_access_roles(name), project_id TEXT, environment_id TEXT, service_id TEXT, granted_by_user_id TEXT NOT NULL REFERENCES gwf_users(id), granted_at INTEGER NOT NULL, revoked_by_user_id TEXT REFERENCES gwf_users(id), revoked_at INTEGER)`,
		`CREATE INDEX IF NOT EXISTS gwf_access_bindings_scope ON gwf_access_bindings(organization_id,subject_kind,subject_id,revoked_at)`,
		`CREATE TABLE IF NOT EXISTS gwf_break_glass (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, user_id TEXT NOT NULL REFERENCES gwf_users(id), permission_name TEXT NOT NULL REFERENCES gwf_access_permissions(name), reason TEXT NOT NULL, created_at INTEGER NOT NULL, expires_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS gwf_break_glass_active ON gwf_break_glass(organization_id,user_id,expires_at)`,
		`CREATE TABLE IF NOT EXISTS gwf_access_audit_events (id TEXT PRIMARY KEY, organization_id TEXT NOT NULL REFERENCES gwf_organizations(id) ON DELETE CASCADE, actor_user_id TEXT NOT NULL REFERENCES gwf_users(id), action TEXT NOT NULL, resource_type TEXT NOT NULL, resource_id TEXT NOT NULL, request_id TEXT, summary TEXT NOT NULL, created_at INTEGER NOT NULL)`,
		`CREATE INDEX IF NOT EXISTS gwf_access_audit_created ON gwf_access_audit_events(organization_id,created_at)`,
	}
	for _, statement := range statements {
		if _, err = tx.ExecContext(ctx, statement); err != nil {
			return err
		}
	}
	hasPasswordRequirement, err := sqliteColumnExists(ctx, tx, "gwf_users", "password_change_required")
	if err != nil {
		return err
	}
	if !hasPasswordRequirement {
		if _, err = tx.ExecContext(ctx, `ALTER TABLE gwf_users ADD COLUMN password_change_required INTEGER NOT NULL DEFAULT 0 CHECK(password_change_required IN (0,1))`); err != nil {
			return err
		}
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO gamertan_web_migrations(version,applied_at) VALUES(1,?)`, time.Now().UTC().Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO gamertan_web_migrations(version,applied_at) VALUES(2,?)`, time.Now().UTC().Unix()); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO gamertan_web_migrations(version,applied_at) VALUES(3,?)`, time.Now().UTC().Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func sqliteColumnExists(ctx context.Context, tx *sql.Tx, table, column string) (bool, error) {
	rows, err := tx.QueryContext(ctx, `PRAGMA table_info(`+table+`)`)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	for rows.Next() {
		var position, notNull, primaryKey int
		var name, kind string
		var defaultValue sql.NullString
		if err = rows.Scan(&position, &name, &kind, &notNull, &defaultValue, &primaryKey); err != nil {
			return false, err
		}
		if name == column {
			return true, nil
		}
	}
	return false, rows.Err()
}

func (store *Store) CreateUser(ctx context.Context, user auth.User, passwordHash string) error {
	if !opaqueID(user.ID) || !text(user.Username, 64, false) || !text(user.Email, 320, false) || !text(user.DisplayName, 128, false) || (user.Status != "active" && user.Status != "suspended" && user.Status != "disabled") || user.CreatedAt.IsZero() || user.UpdatedAt.IsZero() || !text(passwordHash, 1024, false) {
		return errors.New("authsqlite: invalid user")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	_, err = tx.ExecContext(ctx, `INSERT INTO gwf_users(id,username,username_normalized,email,email_normalized,display_name,status,password_change_required,created_at,updated_at) VALUES(?,?,?,?,?,?,?,?,?,?)`, user.ID, user.Username, normalize(user.Username), user.Email, normalize(user.Email), user.DisplayName, user.Status, user.PasswordChangeRequired, user.CreatedAt.Unix(), user.UpdatedAt.Unix())
	if err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_password_credentials(user_id,password_hash,changed_at) VALUES(?,?,?)`, user.ID, passwordHash, user.CreatedAt.Unix()); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) CredentialByIdentifier(ctx context.Context, identifier string) (auth.User, string, error) {
	if !text(strings.TrimSpace(identifier), 320, false) {
		return auth.User{}, "", auth.ErrUserNotFound
	}
	var user auth.User
	var created, updated int64
	var passwordChangeRequired int
	var hash string
	err := store.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.email,u.display_name,u.status,u.password_change_required,u.created_at,u.updated_at,c.password_hash FROM gwf_users u JOIN gwf_password_credentials c ON c.user_id=u.id WHERE u.username_normalized=? OR u.email_normalized=?`, normalize(identifier), normalize(identifier)).Scan(&user.ID, &user.Username, &user.Email, &user.DisplayName, &user.Status, &passwordChangeRequired, &created, &updated, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, "", auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, "", err
	}
	user.PasswordChangeRequired = passwordChangeRequired == 1
	user.CreatedAt, user.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return user, hash, nil
}

func (store *Store) CredentialByUserID(ctx context.Context, userID string) (auth.User, string, error) {
	if !opaqueID(userID) {
		return auth.User{}, "", auth.ErrUserNotFound
	}
	var user auth.User
	var created, updated int64
	var passwordChangeRequired int
	var hash string
	err := store.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.email,u.display_name,u.status,u.password_change_required,u.created_at,u.updated_at,c.password_hash FROM gwf_users u JOIN gwf_password_credentials c ON c.user_id=u.id WHERE u.id=?`, userID).Scan(&user.ID, &user.Username, &user.Email, &user.DisplayName, &user.Status, &passwordChangeRequired, &created, &updated, &hash)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.User{}, "", auth.ErrUserNotFound
	}
	if err != nil {
		return auth.User{}, "", err
	}
	user.PasswordChangeRequired = passwordChangeRequired == 1
	user.CreatedAt, user.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	return user, hash, nil
}

func (store *Store) ReplacePasswordAndRevokeSessions(ctx context.Context, userID, expectedHash, newHash string, changedAt time.Time) error {
	if !opaqueID(userID) || !text(expectedHash, 1024, false) || !text(newHash, 1024, false) || changedAt.IsZero() {
		return auth.ErrInvalidCredentials
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	result, err := tx.ExecContext(ctx, `UPDATE gwf_password_credentials SET password_hash=?,changed_at=? WHERE user_id=? AND password_hash=?`, newHash, changedAt.Unix(), userID, expectedHash)
	if err != nil {
		return err
	}
	changed, err := result.RowsAffected()
	if err != nil {
		return err
	}
	if changed != 1 {
		return auth.ErrInvalidCredentials
	}
	if _, err = tx.ExecContext(ctx, `UPDATE gwf_users SET password_change_required=0,updated_at=? WHERE id=?`, changedAt.Unix(), userID); err != nil {
		return err
	}
	if _, err = tx.ExecContext(ctx, `DELETE FROM gwf_auth_sessions WHERE user_id=?`, userID); err != nil {
		return err
	}
	return tx.Commit()
}

func (store *Store) UpdateLastLogin(ctx context.Context, userID string, when time.Time) error {
	if !opaqueID(userID) || when.IsZero() {
		return errors.New("authsqlite: invalid login update")
	}
	_, err := store.db.ExecContext(ctx, `UPDATE gwf_users SET last_login_at=?,updated_at=? WHERE id=?`, when.Unix(), when.Unix(), userID)
	return err
}

func (store *Store) CreateSession(ctx context.Context, session auth.Session) error {
	if zeroDigest(session.Digest) || !opaqueID(session.UserID) || session.CreatedAt.IsZero() || !session.ExpiresAt.After(session.CreatedAt) || session.LastSeenAt.Before(session.CreatedAt) || session.LastSeenAt.After(session.ExpiresAt) {
		return errors.New("authsqlite: invalid session")
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO gwf_auth_sessions(token_hash,user_id,created_at,expires_at,last_seen_at) VALUES(?,?,?,?,?)`, session.Digest[:], session.UserID, session.CreatedAt.Unix(), session.ExpiresAt.Unix(), session.LastSeenAt.Unix())
	return err
}

func (store *Store) PrincipalBySession(ctx context.Context, digest [32]byte, now time.Time) (auth.Principal, auth.Session, error) {
	if zeroDigest(digest) || now.IsZero() {
		return auth.Principal{}, auth.Session{}, auth.ErrSessionNotFound
	}
	var principal auth.Principal
	var session auth.Session
	var created, updated, sessionCreated, expires, lastSeen int64
	var passwordChangeRequired int
	err := store.db.QueryRowContext(ctx, `SELECT u.id,u.username,u.email,u.display_name,u.status,u.password_change_required,u.created_at,u.updated_at,s.user_id,s.created_at,s.expires_at,s.last_seen_at FROM gwf_auth_sessions s JOIN gwf_users u ON u.id=s.user_id WHERE s.token_hash=? AND s.expires_at>?`, digest[:], now.Unix()).Scan(&principal.User.ID, &principal.User.Username, &principal.User.Email, &principal.User.DisplayName, &principal.User.Status, &passwordChangeRequired, &created, &updated, &session.UserID, &sessionCreated, &expires, &lastSeen)
	if errors.Is(err, sql.ErrNoRows) {
		return auth.Principal{}, auth.Session{}, auth.ErrSessionNotFound
	}
	principal.User.PasswordChangeRequired = passwordChangeRequired == 1
	if err != nil {
		return auth.Principal{}, auth.Session{}, err
	}
	principal.User.CreatedAt, principal.User.UpdatedAt = time.Unix(created, 0).UTC(), time.Unix(updated, 0).UTC()
	session.Digest = digest
	session.CreatedAt = time.Unix(sessionCreated, 0).UTC()
	session.ExpiresAt = time.Unix(expires, 0).UTC()
	session.LastSeenAt = time.Unix(lastSeen, 0).UTC()
	rows, err := store.db.QueryContext(ctx, `SELECT r.name,p.name FROM gwf_user_roles ur JOIN gwf_roles r ON r.name=ur.role_name LEFT JOIN gwf_role_permissions rp ON rp.role_name=r.name LEFT JOIN gwf_permissions p ON p.name=rp.permission_name WHERE ur.user_id=? ORDER BY r.name,p.name`, principal.User.ID)
	if err != nil {
		return auth.Principal{}, auth.Session{}, err
	}
	defer rows.Close()
	principal.Permissions = map[string]bool{}
	roleSet := map[string]struct{}{}
	for rows.Next() {
		var role string
		var permission sql.NullString
		if err = rows.Scan(&role, &permission); err != nil {
			return auth.Principal{}, auth.Session{}, err
		}
		roleSet[role] = struct{}{}
		if permission.Valid {
			principal.Permissions[permission.String] = true
		}
	}
	if err = rows.Err(); err != nil {
		return auth.Principal{}, auth.Session{}, err
	}
	for role := range roleSet {
		principal.Roles = append(principal.Roles, role)
	}
	sort.Strings(principal.Roles)
	return principal, session, nil
}

func (store *Store) TouchSession(ctx context.Context, digest [32]byte, when time.Time) error {
	if zeroDigest(digest) || when.IsZero() {
		return errors.New("authsqlite: invalid session touch")
	}
	_, err := store.db.ExecContext(ctx, `UPDATE gwf_auth_sessions SET last_seen_at=? WHERE token_hash=?`, when.Unix(), digest[:])
	return err
}
func (store *Store) DeleteSession(ctx context.Context, digest [32]byte) error {
	if zeroDigest(digest) {
		return errors.New("authsqlite: invalid session digest")
	}
	_, err := store.db.ExecContext(ctx, `DELETE FROM gwf_auth_sessions WHERE token_hash=?`, digest[:])
	return err
}
func (store *Store) RevokeUserSessions(ctx context.Context, userID string) error {
	if !opaqueID(userID) {
		return errors.New("authsqlite: invalid user identifier")
	}
	_, err := store.db.ExecContext(ctx, `DELETE FROM gwf_auth_sessions WHERE user_id=?`, userID)
	return err
}

func (store *Store) SeedPolicy(ctx context.Context, seed auth.PolicySeed) error {
	if len(seed.Roles) > 1000 || len(seed.Permissions) > 10000 || len(seed.RolePermissions) > 1000 {
		return errors.New("authsqlite: policy is too large")
	}
	tx, err := store.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	for name, description := range seed.Roles {
		if !safeName(name) || !text(description, 512, true) {
			return errors.New("authsqlite: invalid role")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_roles(name,description) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET description=excluded.description`, name, description); err != nil {
			return err
		}
	}
	for name, description := range seed.Permissions {
		if !safeName(name) || !text(description, 512, true) {
			return errors.New("authsqlite: invalid permission")
		}
		if _, err = tx.ExecContext(ctx, `INSERT INTO gwf_permissions(name,description) VALUES(?,?) ON CONFLICT(name) DO UPDATE SET description=excluded.description`, name, description); err != nil {
			return err
		}
	}
	for role, permissions := range seed.RolePermissions {
		if !safeName(role) || len(permissions) > 10000 {
			return errors.New("authsqlite: invalid role policy")
		}
		for _, permission := range permissions {
			if !safeName(permission) {
				return errors.New("authsqlite: invalid permission policy")
			}
			if _, err = tx.ExecContext(ctx, `INSERT OR IGNORE INTO gwf_role_permissions(role_name,permission_name) VALUES(?,?)`, role, permission); err != nil {
				return err
			}
		}
	}
	return tx.Commit()
}

func (store *Store) GrantRole(ctx context.Context, userID, role string, when time.Time) error {
	if !opaqueID(userID) || !safeName(role) || when.IsZero() {
		return errors.New("authsqlite: invalid role grant")
	}
	_, err := store.db.ExecContext(ctx, `INSERT OR IGNORE INTO gwf_user_roles(user_id,role_name,granted_at) VALUES(?,?,?)`, userID, role, when.Unix())
	return err
}
func (store *Store) AppendAudit(ctx context.Context, event auth.AuditEvent) error {
	if !opaqueID(event.ID) || event.ActorUserID != "" && !opaqueID(event.ActorUserID) || !safeName(event.Action) || !safeName(event.ResourceType) || !text(event.ResourceID, 256, false) || !text(event.RequestID, 128, true) || !text(event.Summary, 1024, true) || event.CreatedAt.IsZero() {
		return errors.New("authsqlite: invalid audit event")
	}
	_, err := store.db.ExecContext(ctx, `INSERT INTO gwf_audit_events(id,actor_user_id,action,resource_type,resource_id,request_id,summary,created_at) VALUES(?,NULLIF(?,''),?,?,?,?,?,?)`, event.ID, event.ActorUserID, event.Action, event.ResourceType, event.ResourceID, event.RequestID, event.Summary, event.CreatedAt.Unix())
	return err
}

func normalize(value string) string { return strings.ToLower(strings.TrimSpace(value)) }
func safeName(value string) bool {
	if value == "" || len(value) > 128 {
		return false
	}
	for _, r := range value {
		if !(r == '.' || r == '-' || r == '_' || r >= 'a' && r <= 'z' || r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

func opaqueID(value string) bool {
	if len(value) < 8 || len(value) > 128 {
		return false
	}
	for _, character := range value {
		if !(character == '-' || character == '_' || character >= 'a' && character <= 'z' || character >= 'A' && character <= 'Z' || character >= '0' && character <= '9') {
			return false
		}
	}
	return true
}

func text(value string, limit int, emptyOK bool) bool {
	return (emptyOK || value != "") && len(value) <= limit && utf8.ValidString(value) && !strings.ContainsAny(value, "\x00\r\n")
}

func zeroDigest(digest [32]byte) bool {
	for _, value := range digest {
		if value != 0 {
			return false
		}
	}
	return true
}
