package main

import (
	"context"
	"flag"
	"os"

	caddycmd "github.com/caddyserver/caddy/v2/cmd"
	"github.com/Panharoth06/raiwall/pkg/control/db"
	"github.com/Panharoth06/raiwall/pkg/control/mcp"
)

func init() {
	fs := flag.NewFlagSet("mcp", flag.ExitOnError)
	fs.String("db", "file:raiwall_control.db", "Path or DSN to SQLite database")

	caddycmd.RegisterCommand(caddycmd.Command{
		Name:  "mcp",
		Usage: "[--db <dsn>]",
		Short: "Runs the Model Context Protocol (MCP) stdio server for AI assistants",
		Flags: fs,
		Func:  cmdMCP,
	})
}

func cmdMCP(flags caddycmd.Flags) (int, error) {
	dbDSN := flags.String("db")
	if dbDSN == "" {
		dbDSN = "file:raiwall_control.db"
	}

	store, err := db.InitDB(dbDSN)
	if err != nil {
		return 1, err
	}
	defer store.Close()

	server := mcp.NewServer(store)
	if err := server.ServeStdio(context.Background(), os.Stdin, os.Stdout); err != nil {
		return 1, err
	}
	return 0, nil
}
