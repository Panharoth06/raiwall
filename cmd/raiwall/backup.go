package main

import (
	"context"
	"database/sql"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/Panharoth06/raiwall/internal/config"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	_ "modernc.org/sqlite"
)

func init() {
	fs := flag.NewFlagSet("backup", flag.ExitOnError)
	fs.String("config", "", "Path to a raiwall.yaml document (defaults to discovery)")
	fs.String("output", "", "Destination file for the backup")

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "backup",
		Usage: "--output <file> [--config <path>]",
		Short: "Create a consistent SQLite control-plane backup",
		Long: `Create an online backup of the embedded SQLite control database using
VACUUM INTO. PostgreSQL deployments should use scripts/backup-postgres.sh
(pg_dump -Fc) instead.

  raiwall backup --config /etc/raiwall/raiwall.yaml --output ./raiwall-backup.db`,
		Flags: fs,
		Func:  cmdBackup,
	})
}

func cmdBackup(flags caddycmd.Flags) (int, error) {
	output := getFlagString(flags, "output", "")
	if output == "" {
		return 1, fmt.Errorf("--output is required")
	}
	resolved, err := config.DiscoverPath(getFlagString(flags, "config", ""))
	if err != nil {
		return 1, err
	}
	data, err := os.ReadFile(resolved)
	if err != nil {
		return 1, fmt.Errorf("read config %s: %w", resolved, err)
	}
	file, warnings, err := config.Parse(data, resolved)
	if err != nil {
		return 1, err
	}
	for _, warning := range warnings {
		fmt.Fprintf(os.Stderr, "warning: %s\n", warning)
	}

	if err := backupSQLite(file.Storage.DatabaseURL, output); err != nil {
		return 1, err
	}
	fmt.Printf("backup written to %s\n", output)
	return 0, nil
}

// backupSQLite writes a consistent snapshot with VACUUM INTO and verifies its
// integrity. The destination must not exist so a backup cannot overwrite one.
func backupSQLite(dsn, output string) error {
	if strings.TrimSpace(output) == "" {
		return fmt.Errorf("backup output path is required")
	}
	if !strings.HasPrefix(dsn, "file:") && dsn != ":memory:" {
		return fmt.Errorf("SQLite backup requires a file: DSN; use scripts/backup-postgres.sh for PostgreSQL")
	}
	if _, err := os.Stat(output); err == nil {
		return fmt.Errorf("backup output %s already exists", output)
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("check backup output: %w", err)
	}

	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return fmt.Errorf("open control database: %w", err)
	}
	defer db.Close()

	escaped := strings.ReplaceAll(output, "'", "''")
	if _, err := db.ExecContext(context.Background(), "VACUUM INTO '"+escaped+"'"); err != nil {
		return fmt.Errorf("backup database: %w", err)
	}

	backup, err := sql.Open("sqlite", "file:"+output)
	if err != nil {
		return fmt.Errorf("open backup: %w", err)
	}
	defer backup.Close()
	var integrity string
	if err := backup.QueryRow("PRAGMA integrity_check").Scan(&integrity); err != nil {
		return fmt.Errorf("verify backup: %w", err)
	}
	if integrity != "ok" {
		return fmt.Errorf("backup integrity check failed: %s", integrity)
	}
	return nil
}
