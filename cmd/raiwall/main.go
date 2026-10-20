package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Plug in Caddy standard modules
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Plug in Raiwall modules
	_ "github.com/Panharoth06/raiwall/internal/adapters/inbound/caddy"
)

func main() {
	caddycmd.Main()
}
