package web

import "embed"

// DistFS contains the production static assets for the Raiwall admin UI.
//
//go:embed all:dist
var DistFS embed.FS
