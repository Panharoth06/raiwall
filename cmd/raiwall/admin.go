package main

import (
	"context"
	"flag"
	"fmt"
	"time"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/google/uuid"
	"golang.org/x/crypto/bcrypt"

	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage/sqlite"
	"github.com/Panharoth06/raiwall/internal/core/control"
)

func init() {
	fs := flag.NewFlagSet("admin", flag.ExitOnError)
	fs.String("db", "file:raiwall_control.db", "Path or DSN to SQLite database")
	fs.String("username", "", "Username for user creation or init")
	fs.String("password", "", "Password for user creation or init")
	fs.String("role", "admin", "User role: admin or viewer")
	fs.String("author", "cli-admin", "Author tag for configuration deployment")
	fs.String("description", "Applied via CLI", "Description of configuration changes")
	fs.Int("version", 0, "Configuration snapshot version for rollback")

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "admin",
		Usage: "<init|create-user|validate|apply|rollback> [flags]",
		Short: "Administrative CLI for database bootstrap, user management, and config deployment",
		Flags: fs,
		Func:  cmdAdmin,
	})
}

func cmdAdmin(flags caddycmd.Flags) (int, error) {
	args := flags.Args()
	if len(args) == 0 {
		return 1, fmt.Errorf("missing admin subcommand: choose from init, create-user, validate, apply, rollback")
	}

	subcommand := args[0]
	dbDSN := flags.String("db")
	if dbDSN == "" {
		dbDSN = "file:raiwall_control.db"
	}

	ctx := context.Background()

	switch subcommand {
	case "init":
		store, err := sqlite.InitDB(dbDSN)
		if err != nil {
			return 1, fmt.Errorf("failed to initialize database: %w", err)
		}
		defer store.Close()

		username := flags.String("username")
		if username == "" {
			username = "admin"
		}
		password := flags.String("password")
		if password == "" {
			password = "admin"
		}

		// Check if user already exists
		existing, _ := store.GetUserByUsername(ctx, username)
		if existing.ID == "" {
			hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
			if err != nil {
				return 1, fmt.Errorf("failed to hash password: %w", err)
			}
			now := time.Now().UTC()
			err = store.CreateUser(ctx, sqlite.CreateUserParams{
				ID:           uuid.NewString(),
				Username:     username,
				PasswordHash: string(hash),
				Role:         "admin",
				IsActive:     1,
				CreatedAt:    now,
				UpdatedAt:    now,
			})
			if err != nil {
				return 1, fmt.Errorf("failed to create admin user: %w", err)
			}
			fmt.Printf("Database schema initialized. Admin user '%s' created successfully.\n", username)
		} else {
			fmt.Printf("Database schema initialized. Admin user '%s' already exists.\n", username)
		}
		return 0, nil

	case "create-user":
		username := flags.String("username")
		if username == "" {
			return 1, fmt.Errorf("--username is required")
		}
		password := flags.String("password")
		if password == "" {
			return 1, fmt.Errorf("--password is required")
		}
		role := flags.String("role")
		if role != "admin" && role != "viewer" {
			return 1, fmt.Errorf("--role must be 'admin' or 'viewer'")
		}

		store, err := sqlite.InitDB(dbDSN)
		if err != nil {
			return 1, fmt.Errorf("failed to connect to database: %w", err)
		}
		defer store.Close()

		hash, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
		if err != nil {
			return 1, fmt.Errorf("failed to hash password: %w", err)
		}

		now := time.Now().UTC()
		err = store.CreateUser(ctx, sqlite.CreateUserParams{
			ID:           uuid.NewString(),
			Username:     username,
			PasswordHash: string(hash),
			Role:         role,
			IsActive:     1,
			CreatedAt:    now,
			UpdatedAt:    now,
		})
		if err != nil {
			return 1, fmt.Errorf("failed to create user: %w", err)
		}

		fmt.Printf("User '%s' with role '%s' created successfully.\n", username, role)
		return 0, nil

	case "validate":
		store, err := sqlite.InitDB(dbDSN)
		if err != nil {
			return 1, fmt.Errorf("failed to connect to database: %w", err)
		}
		defer store.Close()

		snap, err := control.CompileSnapshot(ctx, store)
		if err != nil {
			return 1, fmt.Errorf("pre-flight configuration validation failed: %w", err)
		}

		fmt.Printf("Configuration is VALID. Contains %d sites, %d exceptions, %d ACL rules.\n",
			len(snap.Apps), len(snap.Exceptions), len(snap.ACLRules))
		return 0, nil

	case "apply":
		store, err := sqlite.InitDB(dbDSN)
		if err != nil {
			return 1, fmt.Errorf("failed to connect to database: %w", err)
		}
		defer store.Close()

		author := flags.String("author")
		if author == "" {
			author = "cli-admin"
		}
		desc := flags.String("description")
		if desc == "" {
			desc = "Applied via CLI"
		}

		snap, err := control.DeploySnapshot(ctx, store, author, desc)
		if err != nil {
			return 1, fmt.Errorf("failed to deploy configuration: %w", err)
		}

		fmt.Printf("Configuration version %d deployed and activated successfully.\n", snap.Version)
		return 0, nil

	case "rollback":
		targetVer := flags.Int("version")
		if targetVer <= 0 {
			return 1, fmt.Errorf("--version must be a positive integer")
		}

		store, err := sqlite.InitDB(dbDSN)
		if err != nil {
			return 1, fmt.Errorf("failed to connect to database: %w", err)
		}
		defer store.Close()

		snap, err := control.RollbackToVersion(ctx, store, uint64(targetVer))
		if err != nil {
			return 1, fmt.Errorf("rollback failed: %w", err)
		}

		fmt.Printf("Successfully rolled back to configuration snapshot version %d.\n", snap.Version)
		return 0, nil

	default:
		return 1, fmt.Errorf("unknown admin subcommand '%s': choose from init, create-user, validate, apply, rollback", subcommand)
	}
}
