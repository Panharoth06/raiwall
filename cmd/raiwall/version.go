package main

import (
	"fmt"

	"github.com/caddyserver/caddy/v2"
)

var (
	// Version is the current version of Raiwall.
	Version = "0.1.0"
	// Commit is the git commit hash at build time.
	Commit = "unknown"
	// BuildDate is the date of the build.
	BuildDate = "unknown"
)

func init() {
	if caddy.CustomVersion == "" {
		caddy.CustomVersion = fmt.Sprintf("v%s (Raiwall)", Version)
	}
}
