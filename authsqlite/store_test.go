// SPDX-License-Identifier: MPL-2.0

package authsqlite

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"gamertan.com/web/auth"
)

func TestServiceRoundTripWithApplicationPolicy(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	now := time.Unix(1000, 0).UTC()
	service, err := auth.New(store, auth.Options{Random: strings.NewReader(strings.Repeat("r", 512)), Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.SeedPolicy(t.Context(), auth.PolicySeed{Roles: map[string]string{"reader": "Read the application"}, Permissions: map[string]string{"catalog.read": "Read catalog"}, RolePermissions: map[string][]string{"reader": {"catalog.read"}}}); err != nil {
		t.Fatal(err)
	}
	user, err := service.CreateUser(t.Context(), auth.CreateUser{Username: "reader.one", Email: "reader@example.test", DisplayName: "Reader", Password: "correct horse battery staple"})
	if err != nil {
		t.Fatal(err)
	}
	if err = store.GrantRole(t.Context(), user.ID, "reader", now); err != nil {
		t.Fatal(err)
	}
	token, principal, err := service.Authenticate(t.Context(), "READER.ONE", "correct horse battery staple", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	if token == "" || !principal.Has("catalog.read") || len(principal.Roles) != 1 {
		t.Fatalf("principal=%+v", principal)
	}
	loaded, err := service.Session(t.Context(), token)
	if err != nil || !loaded.Has("catalog.read") {
		t.Fatalf("loaded=%+v err=%v", loaded, err)
	}
	if err = service.RevokeSession(t.Context(), token); err != nil {
		t.Fatal(err)
	}
	if _, err = service.Session(t.Context(), token); err == nil {
		t.Fatal("revoked session accepted")
	}
}

func TestSchemaIsNamespacedAndSeedsNothing(t *testing.T) {
	path := filepath.Join(t.TempDir(), "accounts.db")
	store, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err = store.db.QueryRow(`SELECT COUNT(*) FROM gwf_roles`).Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("roles=%d", count)
	}
	var legacy int
	err = store.db.QueryRow(`SELECT COUNT(*) FROM sqlite_master WHERE type='table' AND name='users'`).Scan(&legacy)
	if err != nil {
		t.Fatal(err)
	}
	if legacy != 0 {
		t.Fatal("created unnamespaced users table")
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm() != 0o600 {
		t.Fatalf("mode=%o", info.Mode().Perm())
	}
}

func TestAdapterRejectsUnboundedPolicyAndInvalidAudit(t *testing.T) {
	store, err := Open(filepath.Join(t.TempDir(), "accounts.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if err = store.SeedPolicy(t.Context(), auth.PolicySeed{Roles: map[string]string{"BAD ROLE": "invalid"}}); err == nil {
		t.Fatal("invalid role accepted")
	}
	if err = store.AppendAudit(t.Context(), auth.AuditEvent{ID: "short"}); err == nil {
		t.Fatal("invalid audit event accepted")
	}
}

func TestOpenRejectsSymlinkDatabase(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink creation is privilege-dependent on Windows")
	}
	directory := t.TempDir()
	target := filepath.Join(directory, "target.db")
	if err := os.WriteFile(target, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(directory, "accounts.db")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if _, err := Open(link); err == nil {
		t.Fatal("symlink database accepted")
	}
}
