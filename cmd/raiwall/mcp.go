package main

import (
	"context"
	"flag"
	"os"

	"github.com/Panharoth06/raiwall/internal/adapters/inbound/mcp"
	"github.com/Panharoth06/raiwall/internal/adapters/outbound/storage"
	caddycmd "github.com/caddyserver/caddy/v2/cmd"
)

func init() {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	fs.String("db", "file:raiwall_control.db", "Path or DSN to SQLite database")
	fs.String("dsn", "", "Database connection DSN (overrides --db)")
	fs.String("driver", "", "Database driver (sqlite, postgres; auto-detected if empty)")

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "mcp",
		Usage: "[--db <dsn>] [--dsn <dsn>] [--driver <driver>]",
		Short: "Runs the Model Context Protocol (MCP) stdio server for AI assistants",
		Flags: fs,
		Func:  cmdMCP,
	})
}

func cmdMCP(flags caddycmd.Flags) (int, error) {
	dbDSN := getFlagString(flags, "dsn", "")
	if dbDSN == "" {
		dbDSN = getFlagString(flags, "db", "file:raiwall_control.db")
	}
	driver := getFlagString(flags, "driver", "")

	ctx := context.Background()
	store, err := storage.OpenControlStore(ctx, driver, dbDSN)
	if err != nil {
		return 1, err
	}
	defer store.Close()

	server := mcp.NewServer(store)
	if err := server.ServeStdio(ctx, os.Stdin, os.Stdout); err != nil {
		return 1, err
	}
	return 0, nil
}
