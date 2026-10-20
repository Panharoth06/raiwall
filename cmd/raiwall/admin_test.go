package main

import (
	"context"
	"fmt"
	"testing"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func TestAdminCLI_FullLifecycle(t *testing.T) {
	dbDSN := fmt.Sprintf("file:test_admin_%d?mode=memory&cache=shared", time.Now().UnixNano())

	// 1. Init
	fs := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	fs.String("db", dbDSN, "")
	fs.String("username", "superadmin", "")
	fs.String("password", "supersecret123", "")
	fs.String("role", "admin", "")
	fs.String("author", "cli-admin", "")
	fs.String("description", "CLI apply", "")
	fs.Int("version", 0, "")
	_ = fs.Parse([]string{"init"})

	code, err := cmdAdmin(caddycmd.Flags{FlagSet: fs})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	// Verify database was initialized
	store, err := sqlite.InitDB(dbDSN)
	require.NoError(t, err)
	defer store.Close()

	u, err := store.GetUserByUsername(context.Background(), "superadmin")
	require.NoError(t, err)
	require.Equal(t, "superadmin", u.Username)
	require.Equal(t, "admin", u.Role)

	// 2. Create-User (Viewer)
	fsUser := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	fsUser.String("db", dbDSN, "")
	fsUser.String("username", "bob_viewer", "")
	fsUser.String("password", "viewpass456", "")
	fsUser.String("role", "viewer", "")
	fsUser.String("author", "", "")
	fsUser.String("description", "", "")
	fsUser.Int("version", 0, "")
	_ = fsUser.Parse([]string{"create-user"})

	code, err = cmdAdmin(caddycmd.Flags{FlagSet: fsUser})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	bob, err := store.GetUserByUsername(context.Background(), "bob_viewer")
	require.NoError(t, err)
	require.Equal(t, "viewer", bob.Role)

	// 3. Validate
	fsValidate := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	fsValidate.String("db", dbDSN, "")
	fsValidate.String("username", "", "")
	fsValidate.String("password", "", "")
	fsValidate.String("role", "", "")
	fsValidate.String("author", "", "")
	fsValidate.String("description", "", "")
	fsValidate.Int("version", 0, "")
	_ = fsValidate.Parse([]string{"validate"})

	code, err = cmdAdmin(caddycmd.Flags{FlagSet: fsValidate})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	// 4. Apply
	fsApply := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	fsApply.String("db", dbDSN, "")
	fsApply.String("username", "", "")
	fsApply.String("password", "", "")
	fsApply.String("role", "", "")
	fsApply.String("author", "devops_bob", "")
	fsApply.String("description", "Deploy v1 snapshot", "")
	fsApply.Int("version", 0, "")
	_ = fsApply.Parse([]string{"apply"})

	code, err = cmdAdmin(caddycmd.Flags{FlagSet: fsApply})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	active := control.GetActiveSnapshot()
	require.NotNil(t, active)
	require.Equal(t, uint64(1), active.Version)

	// Deploy a second snapshot
	code, err = cmdAdmin(caddycmd.Flags{FlagSet: fsApply})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	active = control.GetActiveSnapshot()
	require.Equal(t, uint64(2), active.Version)

	// 5. Rollback to version 1
	fsRollback := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	fsRollback.String("db", dbDSN, "")
	fsRollback.String("username", "", "")
	fsRollback.String("password", "", "")
	fsRollback.String("role", "", "")
	fsRollback.String("author", "", "")
	fsRollback.String("description", "", "")
	fsRollback.Int("version", 1, "")
	_ = fsRollback.Parse([]string{"rollback"})

	code, err = cmdAdmin(caddycmd.Flags{FlagSet: fsRollback})
	require.NoError(t, err)
	require.Equal(t, 0, code)

	active = control.GetActiveSnapshot()
	require.Equal(t, uint64(1), active.Version)
}

func TestAdminCLI_Errors(t *testing.T) {
	// Missing subcommand
	fs := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	code, err := cmdAdmin(caddycmd.Flags{FlagSet: fs})
	require.Error(t, err)
	require.Equal(t, 1, code)

	// Invalid role
	fsRole := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	fsRole.String("db", "file:mem?mode=memory&cache=shared", "")
	fsRole.String("username", "test", "")
	fsRole.String("password", "test", "")
	fsRole.String("role", "invalid_role", "")
	_ = fsRole.Parse([]string{"create-user"})
	code, err = cmdAdmin(caddycmd.Flags{FlagSet: fsRole})
	require.Error(t, err)
	require.Equal(t, 1, code)

	// Missing version for rollback
	fsRollback := pflag.NewFlagSet("admin", pflag.ContinueOnError)
	fsRollback.String("db", "file:mem?mode=memory&cache=shared", "")
	fsRollback.Int("version", 0, "")
	_ = fsRollback.Parse([]string{"rollback"})
	code, err = cmdAdmin(caddycmd.Flags{FlagSet: fsRollback})
	require.Error(t, err)
	require.Equal(t, 1, code)
}
