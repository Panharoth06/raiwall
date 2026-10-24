# CLAUDE.md

@AGENTS.md

AGENTS.md is the canonical project spec. The notes below correct places where it has drifted from the actual repo. **Where they conflict, this file wins.**

## Commands (verified against Makefile / package.json)

```bash
# Go
make build                      # go build -> bin/raiwall (needs web/dist to exist, see below)
make test                       # go test -v ./...
make test-race                  # go test -v -race ./...
make test-integration           # -tags=integration ./tests/e2e/...
make lint                       # go vet only; golangci-lint is NOT wired into the Makefile
go test -race ./internal/core/waf/...   # single package (there is no ./pkg/ tree)

# Web (pnpm, not npm)
cd web && pnpm dev              # Vite on :5173, proxies /api and /.raiwall/api -> :8080
cd web && pnpm build            # -> web/dist (embedded by web/embed.go)
cd web && pnpm test             # vitest run (there is no test:unit script)
cd web && pnpm test:e2e         # Playwright
cd web && pnpm exec vue-tsc --noEmit -p tsconfig.app.json   # type check (no script defined)

# Full stack
docker compose up -d --build    # postgres:18 + raiwall on :8080 / :8443
curl -f http://localhost:8080/.raiwall/api/openapi.json     # readiness
```

There is no `lint` script and no ESLint/Prettier config in `web/`. The `npm run lint` and `npm run test:unit` commands in AGENTS.md and `.agents/rules/` don't exist.

## Corrections to AGENTS.md

- **No `pkg/` directory.** All Go code lives under `cmd/raiwall` and `internal/`. `sqlc.yaml` still points at `pkg/control/db/` and is stale. The real sqlc sources are `internal/adapters/outbound/storage/sqlite/{schema.sql,query.sql,query.sql.go}`. Fix `sqlc.yaml` before you regenerate.
- **Storage is multi-driver**, not SQLite-only: `internal/adapters/outbound/storage/{sqlite,postgres,clickhouse,redis,memory}`. Versioned migrations are in `storage/migration/{sqlite,postgres}/` and get embedded by `migrator.go`. Set `DATABASE_URL` to pick the driver (auto-detected, see `inbound/caddy/provision_storage.go`). docker-compose runs **Postgres**, not SQLite.
- **Frontend stack differs:**
  - Routing is a **custom router** in `web/src/router/index.ts`. Vue Router is not installed.
  - Charts and visualizations use **d3**. ECharts and Globe.gl are not dependencies.
  - UI primitives are `radix-vue` with shadcn-style components in `web/src/components/ui/`, styled with Tailwind 3.
  - Route pages live in `web/src/views/` (not `pages/`). Other dirs: `api/`, `layouts/`, `lib/`, `composables/`, `stores/`, `types/`.
- **Dockerfile** builds with `golang:alpine` + `CGO_ENABLED=0` and runs on `alpine:3.21`. `Dockerfile.all-in-one` is an alternative image.

## Gotchas

- `web/embed.go` uses `//go:embed all:dist`, so the Go build fails if `web/dist` is missing. Run `pnpm build` first on a clean checkout.
- The Caddy module ID is `http.handlers.raiwall`, configured through the `raiwall { ... }` Caddyfile directive (`examples/Caddyfile`, parsers in `inbound/caddy/caddyfile_*.go`).
- Playwright's default `baseURL` is a Vite dev server it starts on `:5193`. To test the Docker stack, set `PLAYWRIGHT_BASE_URL=http://localhost:8080/.raiwall/`. Only a 1440×900 Chromium project is configured, so tablet/mobile viewports must be set per test.
- `tests/e2e/live_container_test.go` (tag `integration`) expects a running container that accepts `admin:admin` Basic Auth.
- `test-lab/` holds an OWASP CRS / go-ftw attack harness (`run-ftw.sh`, `test-attacks.sh`). `web-draft/` is an old scaffold that `.dockerignore` excludes. The real frontend is `web/`.
- After changing Go files, run `graphify update .` (see `.agents/rules/graphify.md`).
- UI work must follow `.agents/rules/{ui-consistency,anti-ui-slop,frontend-design}.md`. In particular, no arbitrary hex Tailwind classes.
