package main

import (
	caddycmd "github.com/caddyserver/caddy/v2/cmd"

	// Plug in Caddy standard modules
	_ "github.com/caddyserver/caddy/v2/modules/standard"

	// Plug in Raiwall modules
	_ "github.com/raiwall/raiwall/pkg/proxy"
)

func main() {
	caddycmd.Main()
}
