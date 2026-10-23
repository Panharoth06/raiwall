package migration

import (
	"context"
	"database/sql"
	"embed"
	"fmt"
	"strings"
	"time"
)

//go:embed sqlite/*.sql postgres/*.sql
var migrationFS embed.FS

// Migration represents a single versioned schema upgrade.
type Migration struct {
	Version     int
	Description string
	File        string
}

var migrations = []Migration{
	{Version: 1, Description: "control_initial", File: "0001_control_initial.sql"},
	{Version: 2, Description: "telemetry_initial", File: "0002_telemetry_initial.sql"},
	{Version: 3, Description: "phase7_ipgroups_templates", File: "0003_phase7_ipgroups_templates.sql"},
	{Version: 4, Description: "semantic_matrix", File: "0004_semantic_matrix.sql"},
}

// NormalizeDriver standardizes dialect names to "sqlite" or "postgres".
func NormalizeDriver(driver string) string {
	d := strings.ToLower(strings.TrimSpace(driver))
	switch d {
	case "postgres", "postgresql", "pgx", "pg":
		return "postgres"
	case "sqlite", "sqlite3", "control_sqlite":
		return "sqlite"
	default:
		return d
	}
}

// Run executes all pending migrations on db for the given driver.
func Run(ctx context.Context, db *sql.DB, driver string) error {
	dialect := NormalizeDriver(driver)
	if dialect != "sqlite" && dialect != "postgres" {
		return fmt.Errorf("unsupported database dialect: %s", driver)
	}

	if err := ensureMigrationTable(ctx, db, dialect); err != nil {
		return fmt.Errorf("ensure migration table: %w", err)
	}

	applied, err := getAppliedVersions(ctx, db)
	if err != nil {
		return fmt.Errorf("query applied migrations: %w", err)
	}

	for _, m := range migrations {
		if applied[m.Version] {
			continue
		}

		filePath := fmt.Sprintf("%s/%s", dialect, m.File)
		sqlBytes, err := migrationFS.ReadFile(filePath)
		if err != nil {
			return fmt.Errorf("read migration file %s: %w", filePath, err)
		}

		if err := applyMigration(ctx, db, dialect, m.Version, string(sqlBytes)); err != nil {
			return fmt.Errorf("apply migration %d (%s): %w", m.Version, m.Description, err)
		}
	}

	return nil
}

func ensureMigrationTable(ctx context.Context, db *sql.DB, dialect string) error {
	var query string
	if dialect == "postgres" {
		query = `CREATE TABLE IF NOT EXISTS raiwall_schema_migrations (
			version INT PRIMARY KEY,
			applied_at TIMESTAMPTZ NOT NULL DEFAULT CURRENT_TIMESTAMP
		);`
	} else {
		query = `CREATE TABLE IF NOT EXISTS raiwall_schema_migrations (
			version INTEGER PRIMARY KEY,
			applied_at TEXT NOT NULL
		);`
	}
	_, err := db.ExecContext(ctx, query)
	return err
}

func getAppliedVersions(ctx context.Context, db *sql.DB) (map[int]bool, error) {
	rows, err := db.QueryContext(ctx, "SELECT version FROM raiwall_schema_migrations")
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	applied := make(map[int]bool)
	for rows.Next() {
		var v int
		if err := rows.Scan(&v); err != nil {
			return nil, err
		}
		applied[v] = true
	}
	return applied, rows.Err()
}

func applyMigration(ctx context.Context, db *sql.DB, dialect string, version int, sqlScript string) error {
	tx, err := db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer func() { _ = tx.Rollback() }()

	if _, err := tx.ExecContext(ctx, sqlScript); err != nil {
		return fmt.Errorf("exec script: %w", err)
	}

	var recordSQL string
	if dialect == "postgres" {
		recordSQL = "INSERT INTO raiwall_schema_migrations (version, applied_at) VALUES ($1, $2)"
	} else {
		recordSQL = "INSERT INTO raiwall_schema_migrations (version, applied_at) VALUES (?, ?)"
	}

	now := time.Now().UTC()
	var appliedVal any = now.Format(time.RFC3339Nano)
	if dialect == "postgres" {
		appliedVal = now
	}
	if _, err := tx.ExecContext(ctx, recordSQL, version, appliedVal); err != nil {
		return fmt.Errorf("record migration: %w", err)
	}

	return tx.Commit()
}
