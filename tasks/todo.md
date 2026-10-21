# Tasks: Raiwall Domain 7 (Control Plane, Customization & Ecosystem Integration)

## Completed Milestones
- [x] **Milestone 1: Domain 1 (Reverse Proxy & Gateway)** — Tasks 1 through 8 completed and verified.
- [x] **Milestone 2: Domain 2 (Semantic Threat Detection Engine)** — Tasks 9 through 17 completed and verified.
- [x] **Milestone 3: Domain 3 (Bot Mitigation & Active Defense)** — Tasks 18 through 27 completed and verified.
- [x] **Milestone 4: Domain 4 (DDoS, HTTP Flood & Rate Limiting)** — Tasks 28 through 36 completed and verified.
- [x] **Milestone 5: Domain 5 (Access Control & Zero-Trust Identity Gateway)** — Tasks 37 through 45 completed and verified.
- [x] **Milestone 6: Domain 6 (Observability, Forensics & Real-Time Alerting)** — Tasks 46 through 57 completed and verified.

---

## Phase 1: Database Schema, `sqlc` Code Generation & In-Memory Config Rollback Engine

### Task 58: SQLite Schema & `sqlc` Repository for Control Plane Persistence
**Description:** Implement `pkg/control/db/schema.sql`, `pkg/control/db/query.sql`, `sqlc.yaml`, and generate Go models and queries via `sqlc`. Define relational schema in pure-Go SQLite WAL mode (`modernc.org/sqlite`) persisting protected sites (`raiwall_apps`), false-positive exceptions (`raiwall_exceptions`), compiled ACL rules (`raiwall_acl_rules`), rate limit policies (`raiwall_rate_policies`), bot defense settings (`raiwall_bot_configs`), versioned snapshots (`raiwall_config_snapshots`), admin users (`raiwall_users`), and API keys (`raiwall_api_keys`). Implement database connection bootstrap with pragmas (`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;`).

**Acceptance criteria:**
- [x] Define comprehensive SQLite schema with foreign key constraints, indexes, and timestamps.
- [x] Write SQL queries for CRUD operations on sites, exceptions, ACLs, rate policies, snapshots, users, and API keys.
- [x] Configure `sqlc.yaml` and compile type-safe Go code in `pkg/control/db/`.
- [x] Implement `InitDB(dsn string) (*Store, error)` applying automated schema migrations on startup.
- [x] Unit tests cover all CRUD queries, transaction rollbacks, and schema integrity.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/control/db/...`
- [x] Build succeeds: `go build ./pkg/control/db/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/control/db/schema.sql`
- `pkg/control/db/query.sql`
- `pkg/control/db/store.go`
- `pkg/control/db/store_test.go`
- `sqlc.yaml`
**Estimated scope:** Medium (4 files)

---

### Task 59: Atomic Config Snapshot Compiler, Pre-Flight Validator & Rollback Engine
**Description:** Implement `pkg/config/compiler.go`, `pkg/config/validator.go`, and test suite in `pkg/config/compiler_test.go`. Build the configuration compiler transforming relational SQLite records into an immutable `ConfigSnapshot`. Implement strict pre-flight validation: parse and compile `expr-lang/expr` ACL rules, validate BART CIDR IP blocks, test regex patterns, and verify upstream dial address formats. Implement the rollback engine that stores snapshot versions in SQLite history and executes atomic swaps via `atomic.Pointer[ConfigSnapshot]`.

**Acceptance criteria:**
- [x] Implement `CompileSnapshot(store *db.Store) (*ConfigSnapshot, error)` assembling all active configuration entities.
- [x] Pre-flight validator verifies `expr` syntax, CIDR prefixes, regex validity, and upstream network addresses.
- [x] Rejects invalid configurations with structured errors, leaving active runtime data plane unaffected.
- [x] Persist compiled snapshot JSON and metadata to `raiwall_config_snapshots` table with auto-incremented version.
- [x] Implement atomic swap updating `atomic.Pointer[ConfigSnapshot]` with zero lock contention.
- [x] Implement `RollbackToVersion(targetVersion uint64)` reverting data plane to any historical snapshot.
- [x] Unit and concurrent race tests verify compilation, validation failures, atomic swapping, and rollback.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/config/...`
- [x] Build succeeds: `go build ./pkg/config/...`

**Dependencies:** Task 58
**Files likely touched:**
- `pkg/config/compiler.go`
- `pkg/config/validator.go`
- `pkg/config/rollback.go`
- `pkg/config/compiler_test.go`
**Estimated scope:** Medium (4 files)

---

## Checkpoint: Database Persistence & Atomic Config Rollback
- [x] Relational configuration schema persisted in WAL-mode SQLite with type-safe `sqlc` models.
- [x] Pre-flight compiler validates all rules and prevents invalid states from reaching data plane.
- [x] Atomic pointer swap and 1-click rollback verified under concurrent traffic.

---

## Phase 2: Huma v2 OpenAPI 3.1 REST API, Auth & MCP Tool Bridge

### Task 60: Huma v2 REST Framework Setup, Admin Auth & 2-Tier RBAC
**Description:** Implement `pkg/control/api/server.go`, `pkg/control/api/auth.go`, and test suite in `pkg/control/api/auth_test.go`. Integrate `github.com/danielgtaylor/huma/v2` with Chi router to provide an OpenAPI 3.1 compliant REST API. Implement authentication supporting both Bearer API keys (`X-Raiwall-Key` or `Authorization: Bearer <key>`) and session cookies. Enforce 2-tier RBAC (`admin` read-write, `viewer` read-only). Mount interactive Scalar and Swagger UI documentation at `/.raiwall/api/docs`.

**Acceptance criteria:**
- [x] Initialize Huma v2 API instance with OpenAPI 3.1 specification metadata.
- [x] Implement authentication middleware validating Bearer API tokens against SQLite hashed keys.
- [x] Implement session cookie authentication with HMAC signature verification.
- [x] Enforce role-based access control (`admin` vs `viewer`) on mutating HTTP methods (`POST`, `PUT`, `DELETE`).
- [x] Serve interactive Scalar documentation at `/.raiwall/api/docs` and OpenAPI JSON at `/.raiwall/api/openapi.json`.
- [x] Unit tests verify token parsing, role enforcement, unauthorized rejections, and docs endpoints.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/control/api/...`
- [x] Build succeeds: `go build ./pkg/control/api/...`

**Dependencies:** Task 58, Task 59
**Files likely touched:**
- `pkg/control/api/server.go`
- `pkg/control/api/auth.go`
- `pkg/control/api/middleware.go`
- `pkg/control/api/auth_test.go`
**Estimated scope:** Medium (4 files)

---

### Task 61: Configuration CRUD Endpoints & Staged Deployment API
**Description:** Implement `pkg/control/api/sites.go`, `pkg/control/api/exceptions.go`, `pkg/control/api/acls.go`, `pkg/control/api/snapshots.go`, and tests. Provide Huma v2 endpoints for managing Sites (with upstream pools and health check parameters), Exceptions (with test dry-run), ACLs (with syntax dry-run), Rate Limiting, and Bot policies. Implement staged deployment workflow: `GET /api/v1/config/draft/diff` (visual diff against active snapshot), `POST /api/v1/config/apply` (pre-flight validation, version bump, atomic swap), and `POST /api/v1/config/rollback/{version}`.

**Acceptance criteria:**
- [x] Implement CRUD endpoints for Sites, Exceptions, ACLs, and Policies with strict Huma request/response validation.
- [x] Implement dry-run evaluation endpoint for testing exception and ACL rules against synthetic request inputs.
- [x] Implement diff endpoint comparing staged database draft changes against active snapshot.
- [x] Implement apply endpoint executing pre-flight validation, committing snapshot revision, and triggering swap.
- [x] Implement rollback endpoint reverting active configuration to any specified past revision.
- [x] Unit tests verify all endpoints, validation errors, diff generation, and rollback execution.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/control/api/...`
- [x] Build succeeds: `go build ./pkg/control/api/...`

**Dependencies:** Task 60
**Files likely touched:**
- `pkg/control/api/sites.go`
- `pkg/control/api/exceptions.go`
- `pkg/control/api/acls.go`
- `pkg/control/api/snapshots.go`
- `pkg/control/api/sites_test.go`
- `pkg/control/api/snapshots_test.go`
**Estimated scope:** Medium (6 files)

---

### Task 62: Model Context Protocol (MCP) Server Endpoint & CLI Stdio Adapter
**Description:** Implement `pkg/control/mcp/server.go`, `pkg/control/mcp/tools.go`, `pkg/control/mcp/mcp_test.go`, and `cmd/raiwall/mcp.go`. Expose Raiwall Control Plane as a Model Context Protocol (MCP) server for AI assistants and LLMs. Define tools: `get_waf_status`, `list_threat_events`, `create_exception_rule`, `apply_configuration`, and `rollback_configuration`. Expose MCP over SSE at `/.raiwall/api/mcp` and provide `raiwall mcp` stdio CLI command for desktop agent integration.

**Acceptance criteria:**
- [x] Implement MCP protocol handler supporting JSON-RPC 2.0 tool discovery and execution.
- [x] Expose core WAF tools with JSON schemas describing arguments and return payloads.
- [x] Serve MCP SSE transport at `/.raiwall/api/mcp` authenticated via API keys.
- [x] Implement `raiwall mcp` stdio command connecting AI agents (Claude Desktop, Cursor, Antigravity) to local or remote Raiwall instances.
- [x] Unit tests verify tool schema generation, tool execution, and error handling.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/control/mcp/...`
- [x] Build succeeds: `go build ./cmd/raiwall`

**Dependencies:** Task 61
**Files likely touched:**
- `pkg/control/mcp/server.go`
- `pkg/control/mcp/tools.go`
- `pkg/control/mcp/mcp_test.go`
- `cmd/raiwall/mcp.go`
**Estimated scope:** Medium (4 files)

---

## Checkpoint: REST Management API & AI/MCP Tooling
- [x] Huma v2 OpenAPI 3.1 REST API is live with interactive Scalar documentation.
- [x] 2-tier RBAC protects mutating configuration endpoints.
- [x] Staged deployment diff and 1-click rollback endpoints operational.
- [x] Model Context Protocol (MCP) server enables AI-assisted operations via SSE and stdio CLI.

---

## Phase 3: Redis Pub/Sub Cluster Synchronization

### Task 63: Redis Pub/Sub Cluster Sync Engine & Reconnect Re-synchronization
**Description:** Implement `pkg/control/cluster/pubsub.go`, `pkg/control/cluster/sync.go`, and `pkg/control/cluster/sync_test.go`. Build the distributed cluster configuration synchronizer. When a configuration is deployed on the master node, broadcast a version notification (`{"version": 42, "hash": "...", "timestamp": ...}`) over Redis Pub/Sub channel `raiwall:cluster:events` and cache the latest compiled snapshot in Redis key `raiwall:config:snapshot:latest`. Implement worker node subscriber that fetches, validates, and swaps snapshots upon notification, with automated poll re-synchronization on reconnect.

**Acceptance criteria:**
- [x] Implement master publisher sending version notifications on config deployment.
- [x] Store active compiled snapshot in Redis cache key with configurable TTL.
- [x] Implement worker subscriber receiving notifications, fetching latest snapshot, and executing atomic swap.
- [x] Automatic re-synchronization worker polling latest version upon Redis reconnect or startup.
- [x] Graceful fallback: continue serving cached active snapshot if Redis connection is temporarily interrupted.
- [x] Unit and mock tests verify publish/subscribe flow, reconnect re-sync, and hash validation.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/control/cluster/...`
- [x] Build succeeds: `go build ./pkg/control/cluster/...`

**Dependencies:** Task 59, Task 61
**Files likely touched:**
- `pkg/control/cluster/pubsub.go`
- `pkg/control/cluster/sync.go`
- `pkg/control/cluster/sync_test.go`
**Estimated scope:** Medium (3 files)

---

## Checkpoint: Cluster Synchronization
- [x] Master nodes broadcast config versions via Redis Pub/Sub.
- [x] Worker nodes fetch and apply snapshots atomically with zero downtime.
- [x] Network partition and reconnect healing verified with tests.

---

## Phase 4: Envoy External Processor (`ext_proc/v3`) gRPC Sidecar Engine

### Task 64: Envoy `ext_proc/v3` gRPC Server Protocol Implementation
**Description:** Implement `pkg/sidecar/server.go`, `pkg/sidecar/processor.go`, and test suite in `pkg/sidecar/server_test.go`. Implement the Envoy External Processor gRPC protocol (`envoy.service.ext_proc.v3.ExternalProcessorServer`). Process bidirectional gRPC request streams: on `RequestHeaders`, extract client IP, JA4 fingerprint, evaluate ACLs, Bot defense, and Route classification, returning 403 `ImmediateResponse` or header modifications. On `RequestBody`, buffer payloads up to 1 MB and evaluate the semantic WAF engine (normalization, `libinjection`, AST verification), returning 403 or continuation.

**Acceptance criteria:**
- [x] Implement `ExternalProcessorServer` interface handling bidirectional gRPC streaming.
- [x] Handle `RequestHeaders` message: evaluate client IP, JA4, rate limiting, and ACL rules.
- [x] Handle `RequestBody` message: buffer chunked body up to 1 MB and evaluate semantic WAF engine.
- [x] Return `ImmediateResponse` with configured status code (403/429) and custom block HTML on threat match.
- [x] Stream payloads > 1 MB directly without buffering to prevent sidecar OOM.
- [x] Record sanitized telemetry to the async ring buffer for all inspected sidecar requests.
- [x] Unit tests verify gRPC stream processing, threat blocking, header mutation, and body buffering limits.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/sidecar/...`
- [x] Build succeeds: `go build ./pkg/sidecar/...`

**Dependencies:** Task 59
**Files likely touched:**
- `pkg/sidecar/server.go`
- `pkg/sidecar/processor.go`
- `pkg/sidecar/server_test.go`
**Estimated scope:** Medium (3 files)

---

### Task 65: Sidecar CLI Command & Caddyfile Directive Integration
**Description:** Implement `cmd/raiwall/sidecar.go`, wire the sidecar listener into `pkg/proxy/caddyfile.go`, and update `pkg/proxy/middleware.go`. Implement the standalone CLI command `raiwall sidecar --listen :50051 --config ...` for dedicated Kubernetes sidecar deployments. Add `sidecar { listen :50051; max_body_size 1MB; }` directive to Caddyfile to enable concurrent dual-mode reverse proxy and ext_proc gRPC processing within a single binary process.

**Acceptance criteria:**
- [x] Implement `raiwall sidecar` CLI subcommand with flags for listen address, SQLite path, and Redis address.
- [x] Parse `sidecar` directive in Caddyfile: `sidecar { listen <addr>; max_body_size <size>; }`.
- [x] Start background gRPC server in Caddy provision phase when sidecar directive is specified.
- [x] Ensure clean shutdown of gRPC server on Caddy reload or termination.
- [x] Unit tests verify Caddyfile parsing and CLI flag validation.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/proxy/...`
- [x] Build succeeds: `go build ./cmd/raiwall`

**Dependencies:** Task 64
**Files likely touched:**
- `cmd/raiwall/sidecar.go`
- `pkg/proxy/caddyfile.go`
- `pkg/proxy/middleware.go`
- `pkg/proxy/caddyfile_test.go`
**Estimated scope:** Medium (4 files)

---

## Checkpoint: Envoy ext_proc Sidecar Mode
- [x] Envoy ext_proc gRPC server inspects headers and bodies with sub-millisecond triage.
- [x] Standalone CLI command runs in Kubernetes sidecar containers.
- [x] Caddyfile directive runs reverse proxy and ext_proc sidecar concurrently in single binary.

---

## Phase 5: Embedded Vue 3 Enterprise Admin Dashboard (Full Control Plane UI)

### Task 66: Dashboard Shell, Navigation, Pinia API Client & Auth Views
**Description:** Implement `web/src/layouts/DashboardLayout.vue`, `web/src/router/index.ts`, `web/src/stores/auth.ts`, `web/src/stores/config.ts`, `web/src/api/client.ts`, and `web/src/views/LoginView.vue`. Build the enterprise dashboard navigation with sidebar, header, active snapshot status pill, and breadcrumbs. Implement typed API client against Huma OpenAPI 3.1 endpoints with token refresh and error toast notifications. Implement login screen with session cookie authentication and route guards.

**Acceptance criteria:**
- [x] Configure Vue Router 4 with nested layout, authentication guards, and dark-mode styling.
- [x] Build responsive sidebar navigation linking to all core management views.
- [x] Implement Pinia auth store handling login, logout, and active user roles (`admin` vs `viewer`).
- [x] Implement typed API client wrapping `fetch` with error interceptors and OpenAPI types.
- [x] Build `LoginView.vue` with form validation and error handling.
- [x] Vitest unit tests verify router navigation guards and auth store actions.

**Verification:**
- [x] Frontend tests pass: `cd web && pnpm test`
- [x] Frontend build succeeds: `cd web && pnpm build`

**Dependencies:** Task 60, Task 61
**Files likely touched:**
- `web/src/layouts/DashboardLayout.vue`
- `web/src/router/index.ts`
- `web/src/stores/auth.ts`
- `web/src/stores/config.ts`
- `web/src/api/client.ts`
- `web/src/views/LoginView.vue`
**Estimated scope:** Medium (6 files)

---

### Task 67: Sites, Upstream Pools & Run Mode Management View
**Description:** Implement `web/src/views/SitesView.vue`, `web/src/components/SiteDialog.vue`, `web/src/components/UpstreamPoolEditor.vue`, and component tests. Build full CRUD interface for protected sites: configure hostnames, load-balanced upstreams (dial address, weight, health check probe path, interval, fail timeout), operational modes (`defense`, `audit`, `offline`), and custom block/offline response templates. Changes are saved to staged draft configuration with visual indicators.

**Acceptance criteria:**
- [x] Display sites table with status badges (mode, healthy upstreams count, requests volume).
- [x] Build dialog for creating and editing sites with hostname chips and mode selector.
- [x] Build upstream pool editor supporting dynamic adding/removing of backend targets with weight sliders.
- [x] Save changes to draft configuration store and show "Unsaved changes" staging banner.
- [x] Vitest tests verify site creation, upstream editing, and draft store mutations.

**Verification:**
- [x] Frontend tests pass: `cd web && pnpm test`
- [x] Frontend build succeeds: `cd web && pnpm build`

**Dependencies:** Task 66
**Files likely touched:**
- `web/src/views/SitesView.vue`
- `web/src/components/SiteDialog.vue`
- `web/src/components/UpstreamPoolEditor.vue`
- `web/src/views/__tests__/SitesView.spec.ts`
**Estimated scope:** Medium (4 files)

---

### Task 68: False-Positive Exceptions & ACL Rules Builder with Test Simulator
**Description:** Implement `web/src/views/ExceptionsView.vue`, `web/src/views/ACLsView.vue`, `web/src/components/ACLExprEditor.vue`, and `web/src/components/ExceptionTestModal.vue`. Build exception rules management view linked with the Live Inspector 1-click modal. Build ACL rules view featuring visual condition builder alongside raw `expr-lang/expr` editor with real-time syntax validation. Implement test simulator modal allowing operators to test synthetic HTTP requests against draft rules before deploying.

**Acceptance criteria:**
- [x] Exceptions table displays rules with Host, Path, Method, Location, ParamName, and Reason.
- [x] 1-Click exception from Live Inspector pre-populates exception modal and saves to draft.
- [x] ACL editor validates `expr` syntax in real time against backend API dry-run endpoint.
- [x] Test simulator evaluates sample HTTP requests against draft rules and displays match verdicts.
- [x] Vitest tests verify rule formulation, syntax validation, and simulator modal.

**Verification:**
- [x] Frontend tests pass: `cd web && pnpm test`
- [x] Frontend build succeeds: `cd web && pnpm build`

**Dependencies:** Task 66
**Files likely touched:**
- `web/src/views/ExceptionsView.vue`
- `web/src/views/ACLsView.vue`
- `web/src/components/ACLExprEditor.vue`
- `web/src/components/ExceptionTestModal.vue`
**Estimated scope:** Medium (4 files)

---

### Task 69: Rate Limiting, Bot Defense & Cluster Settings Views
**Description:** Implement `web/src/views/PoliciesView.vue`, `web/src/views/SettingsView.vue`, `web/src/components/ApiKeysManager.vue`, and tests. Build policy views configuring Tier 1 velocity rate limits, Tier 2 attack frequency auto-ban, Tier 3 scanner trap thresholds, and Virtual Waiting Room parameters. Configure bot defense modes, PoW difficulty, and honeypot traps. In settings view, display cluster nodes, Redis sync health, and provide API key generation modal with copyable token.

**Acceptance criteria:**
- [x] Form controls for Tier 1-3 rate limits and Virtual Waiting Room concurrency parameters.
- [x] Bot defense toggles for PoW challenge mode, difficulty slider, and trap URL paths.
- [x] Settings view displays Redis cluster synchronization status and connected nodes.
- [x] API keys manager allows generating new Bearer keys with name, role (`admin`/`viewer`), and expiration.
- [x] Vitest tests verify form state persistence and API key creation.

**Verification:**
- [x] Frontend tests pass: `cd web && pnpm test`
- [x] Frontend build succeeds: `cd web && pnpm build`

**Dependencies:** Task 66
**Files likely touched:**
- `web/src/views/PoliciesView.vue`
- `web/src/views/SettingsView.vue`
- `web/src/components/ApiKeysManager.vue`
- `web/src/views/__tests__/PoliciesView.spec.ts`
**Estimated scope:** Medium (4 files)

---

### Task 70: Staged Deployment Diff Review, Snapshot History & 1-Click Rollback View
**Description:** Implement `web/src/views/DeploymentsView.vue`, `web/src/components/ConfigDiffViewer.vue`, and component tests. Build deployment management view showing color-coded visual diff between staged draft modifications and the active live snapshot. Provide "Deploy Changes" button with commit message prompt and real-time pre-flight validation status. Render historical snapshot timeline showing version numbers, authors, timestamps, and 1-Click Rollback button.

**Acceptance criteria:**
- [x] Render side-by-side or unified color-coded diff of staged changes vs active snapshot.
- [x] "Deploy Changes" triggers pre-flight validation and atomic swap with loading feedback and error modal.
- [x] Snapshot timeline lists all historical versions with description and author.
- [x] 1-Click Rollback button triggers confirmation modal and instantly reverts to selected version.
- [x] Vitest tests verify diff rendering, deployment submission, and rollback invocation.

**Verification:**
- [x] Frontend tests pass: `cd web && pnpm test`
- [x] Frontend build succeeds: `cd web && pnpm build`

**Dependencies:** Task 66, Task 67, Task 68, Task 69
**Files likely touched:**
- `web/src/views/DeploymentsView.vue`
- `web/src/components/ConfigDiffViewer.vue`
- `web/src/views/__tests__/DeploymentsView.spec.ts`
**Estimated scope:** Medium (3 files)

---

## Checkpoint: Embedded Vue 3 Enterprise Admin Dashboard
- [x] Complete Vue 3 Control Plane UI operational with full dark-mode styling.
- [x] Sites, Exceptions, ACLs, Policies, and Deployments views connected to Huma v2 API.
- [x] Visual diff reviewer and 1-Click Rollback verified in browser tests.
- [x] Production frontend bundles cleanly into `web/dist` and embeds into single Go binary.

---

## Phase 6: End-to-End Integration, CLI Tooling & Production Verification

### Task 71: Admin CLI Commands (`raiwall admin init`, `create-user`, `apply`, `rollback`)
**Description:** Implement `cmd/raiwall/admin.go` and test suite in `cmd/raiwall/admin_test.go`. Provide CLI commands for headless server operations: initialize database (`raiwall admin init`), create admin/viewer users (`raiwall admin create-user`), validate staged configuration (`raiwall admin validate`), apply configuration (`raiwall admin apply`), and disaster recovery rollback (`raiwall admin rollback --version <N>`).

**Acceptance criteria:**
- [x] Implement `raiwall admin init` bootstrapping SQLite schema and initial admin credentials.
- [x] Implement `raiwall admin create-user --username <name> --role <admin|viewer>` generating secure password hash.
- [x] Implement `raiwall admin validate` executing pre-flight compiler checks on draft database.
- [x] Implement `raiwall admin apply` committing draft to snapshot and swapping pointer.
- [x] Implement `raiwall admin rollback --version <N>` reverting active configuration from terminal.
- [x] Unit and CLI tests verify argument parsing, exit codes, and database updates.

**Verification:**
- [x] Tests pass: `go test -v -race ./cmd/raiwall/...`
- [x] Build succeeds: `go build ./cmd/raiwall`

**Dependencies:** Task 58, Task 59, Task 70
**Files likely touched:**
- `cmd/raiwall/admin.go`
- `cmd/raiwall/admin_test.go`
**Estimated scope:** Medium (2 files)

---

### Task 72: Domain 7 End-to-End Integration Tests, Sidecar Verification & Benchmark Validation
**Description:** Implement `tests/e2e/control_plane_test.go`, `tests/e2e/sidecar_test.go`, and update `Makefile`. Conduct end-to-end integration tests verifying complete control plane lifecycle: CRUD mutation -> draft diff -> staged apply with pre-flight check -> atomic swap -> Redis pub/sub delta broadcast -> Envoy ext_proc gRPC threat block -> 1-click rollback. Verify single binary builds cleanly as a compact binary (~50 MB) with embedded admin UI and all tests pass with `-race`.

**Acceptance criteria:**
- [x] End-to-end integration tests verify:
  - Huma REST API creates site and exception rule in SQLite.
  - Staged draft diff detects modified configuration.
  - Apply endpoint validates and swaps snapshot atomically with zero dropped requests.
  - Redis Pub/Sub broadcasts version update to worker nodes.
  - Envoy ext_proc gRPC server blocks SQLi/XSS requests and passes benign traffic.
  - 1-Click rollback restores previous snapshot version and updates data plane immediately.
  - Embedded admin UI serves at `/.raiwall/` and Scalar docs at `/.raiwall/api/docs`.
- [x] Zero race conditions under high concurrent requests (`go test -race`).
- [x] Single binary builds cleanly as a compact binary (~50 MB) (`make build`).

**Verification:**
- [x] Integration tests pass: `go test -v -race -tags=integration ./tests/e2e/...`
- [x] Build succeeds: `make build`
- [x] Manual check: verify binary size is compact (~50 MB, not strictly bounded <50 MB) via `ls -lh bin/raiwall`.

**Dependencies:** Tasks 58–71
**Files likely touched:**
- `tests/e2e/control_plane_test.go`
- `tests/e2e/sidecar_test.go`
- `Makefile`
**Estimated scope:** Medium (3 files)

---

## Final Checkpoint: Milestone 7 (Domain 7) Completion
- [x] All 15 tasks (Tasks 58–72) implemented and verified.
- [x] SQLite schema & `sqlc` persistence layer active with WAL mode pragmas.
- [x] In-memory atomic snapshot compiler, pre-flight validator, and rollback engine operational.
- [x] Huma v2 OpenAPI 3.1 REST API, RBAC, and Model Context Protocol (MCP) bridge active.
- [x] Redis Pub/Sub cluster synchronization verified with reconnect recovery.
- [x] Envoy `ext_proc/v3` gRPC sidecar server operational in CLI and Caddyfile modes.
- [x] Full Vue 3 enterprise admin dashboard built, tested, and embedded in single compact binary (~50 MB).
- [x] All unit, integration, and e2e tests pass cleanly with `-race`.


---

# Major Update: SafeLine v9.4.2 Parity & Enterprise Architecture (Tasks 73–96)

## Phase 1: Frontend Architecture Foundation & Router Modernization

### Task 73: `SimpleRouter` Query-Param & Route Param Engine + `App.vue` RouterView Wiring
**Description:** Enhance `web/src/router/index.ts` so that `SimpleRouter` fully supports hash-based URL query strings (e.g. `#/attacks?ip=1.2.3.4&tab=log`) and route parameters. Parse search parameters using `URLSearchParams` and expose reactive `query` and `params` in `useRoute()`. Update `web/src/App.vue` to render `LoginView` when on `#/login` and `DashboardLayout` wrapping `<RouterView />` for authenticated routes, deconstructing the hardcoded `WafCommandCenter` fallback.

**Acceptance criteria:**
- [ ] `SimpleRouter` parses hash paths containing query parameters (e.g. `#/attacks?tab=log&ip=10.0.0.1`) without breaking route matching.
- [ ] `useRoute().value.query` returns a reactive key-value map of current URL query parameters.
- [ ] `useRoute().value.params` correctly captures dynamic route parameters (e.g. `/sites/:id`).
- [ ] `web/src/App.vue` mounts `<RouterView />` inside `DashboardLayout.vue`.
- [ ] All 53 existing Vitest tests continue to pass.

**Verification:**
- [ ] Tests pass: `cd web && pnpm test`
- [ ] Build succeeds: `cd web && pnpm build`

**Dependencies:** None
**Files likely touched:**
- `web/src/router/index.ts`
- `web/src/App.vue`
- `web/src/router/__tests__/router.spec.ts`
**Estimated scope:** Medium (3 files)

---

### Task 74: `DashboardLayout.vue` Shell Overhaul (SafeLine 8-Domain Navigation)
**Description:** Update `web/src/layouts/DashboardLayout.vue` to match SafeLine v9.4.2's persistent left sidebar structure:
1. `Statistics` (`/statistics`)
2. `Applications` (`/sites`)
3. `Attacks` (`/attacks`)
4. `Allow & Deny` (`/allow-deny`)
5. `HTTP Flood` (`/http-flood`)
6. `Anti-Bot` (`/anti-bot`)
7. `Auth` (`/auth`)
8. `Settings` (`/system`)
Plus dedicated `/topology` link to access Raiwall's 3D Globe / Sankey operations center. Include active route highlighting, tenant selector, active snapshot version badge, and staged deployment alert banner.

**Acceptance criteria:**
- [ ] Left navigation drawer renders the 8 core SafeLine functional domains plus Topology.
- [ ] Active route is visually highlighted with blue accent styling.
- [ ] Top bar displays active configuration version badge (`v{{ version }}` LIVE) and staged changes indicator.
- [ ] Navigation transitions smoothly update the `<slot />` content.
- [ ] Vitest component tests verify sidebar navigation rendering and route active states.

**Verification:**
- [ ] Tests pass: `cd web && pnpm test -- DashboardLayout`
- [ ] Build succeeds: `cd web && pnpm build`

**Dependencies:** Task 73
**Files likely touched:**
- `web/src/layouts/DashboardLayout.vue`
- `web/src/layouts/__tests__/DashboardLayout.spec.ts`
**Estimated scope:** Medium (2 files)

---

### Checkpoint 1: Frontend Foundation
- [ ] `SimpleRouter` preserves URL query parameters during navigation.
- [ ] `DashboardLayout.vue` successfully hosts child view pages with persistent navigation.

---

## Phase 2: Forensic Inspector & Incident Telemetry Upgrades

### Task 75: Backend Incident Aggregation & Rich Parameter Location Telemetry
**Description:** Extend `pkg/telemetry/event.go` and `pkg/telemetry/sqlite.go` to support incident-level grouping and enhanced parameter-level diagnostics. Store exact parameter location (`URLPATH`, `QUERY`, `HEADER`, `BODY`, `COOKIE`), isolated malicious syntax token, attack classification category, and both raw request and response headers/bodies. Implement an incident aggregation query grouping events by `client_ip + host + time_window` (sliding 5 minutes).

**Acceptance criteria:**
- [ ] `ForensicEvent` struct updated with `PayloadLocation`, `MatchedToken`, `AttackCategory`, `ResponseHeaders`, and `ResponseBody`.
- [ ] SQLite telemetry schema updated with compound index on `(client_ip, host, timestamp)`.
- [ ] `GetAggregatedIncidents` query groups events occurring within a sliding 5-minute window.
- [ ] Endpoint `GET /api/v1/telemetry/incidents` returns paginated incident records with total request count and duration.
- [ ] Unit tests verify incident aggregation queries and parameter location serialization.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/telemetry/event.go`
- `pkg/telemetry/sqlite.go`
- `pkg/telemetry/api.go`
- `pkg/telemetry/storage_test.go`
**Estimated scope:** Medium (4 files)

---

### Task 76: Reproducible cURL Command Generator API
**Description:** Implement `pkg/telemetry/curl.go` and expose `GET /api/v1/telemetry/events/{id}/curl`. Generate an executable, drop-in `curl` command string matching the captured HTTP request, complete with method, URL, headers, cookies, and escaped request body for offline terminal triage by security analysts.

**Acceptance criteria:**
- [ ] cURL generator correctly formats headers (`-H 'Header: Value'`), method (`-X POST`), and escaped body (`--data-raw '...'`).
- [ ] Cookie headers are correctly serialized into `-H 'Cookie: ...'` or `-b '...'`.
- [ ] API endpoint returns `{ "curl": "curl -X ..." }` for valid event UUID.
- [ ] Unit tests verify cURL generation across GET, POST (JSON, form-urlencoded, multipart), and header edge cases.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** Task 75
**Files likely touched:**
- `pkg/telemetry/curl.go`
- `pkg/telemetry/curl_test.go`
- `pkg/telemetry/api.go`
**Estimated scope:** Small (3 files)

---

### Task 77: Frontend Forensic Drawer & Incident-Level UX
**Description:** Refactor `web/src/components/LiveInspector.vue` to introduce SafeLine's dual-tab model: **Aggregated Incidents (`EVENTS`)** and **Granular Logs (`LOGS`)**. Clicking an incident card switches to `LOGS` with URL query parameters pre-populated (`?ip=...&host=...`). Implement full-height `ForensicDrawer.vue` featuring: parameter location badge, highlighted malicious token, JA4 verification link, dual tab raw viewer (`REQUEST` with `UTF-8`/`GBK` encoding selector and `RESPONSE`), **"Copy as cURL"** button, and in-place **"Add to IP Group"** / **"Create Exception"** buttons.

**Acceptance criteria:**
- [ ] LiveInspector provides toggleable `EVENTS` (incident cards) and `LOGS` (raw requests) tabs.
- [ ] Clicking an incident card populates URL query parameters and switches to logs view.
- [ ] Drawer displays exact parameter location and highlights the malicious syntax token.
- [ ] Drawer provides REQUEST and RESPONSE tabs with character encoding switcher (`UTF-8` vs `GBK`).
- [ ] "Copy as cURL" copies ready-to-run curl command to clipboard.
- [ ] Buttons to trigger "Add to IP Group" and "Create Exception" without leaving drawer.
- [ ] Vitest unit tests verify tab switching, cURL copying, and drawer actions.

**Verification:**
- [ ] Tests pass: `cd web && pnpm test -- LiveInspector`
- [ ] Build succeeds: `cd web && pnpm build`

**Dependencies:** Tasks 73, 75, 76
**Files likely touched:**
- `web/src/components/LiveInspector.vue`
- `web/src/components/ForensicDrawer.vue`
- `web/src/types/telemetry.ts`
- `web/src/components/__tests__/LiveInspector.spec.ts`
**Estimated scope:** Medium (4 files)

---

### Checkpoint 2: Forensic Triage
- [ ] Incident-level grouping and rich parameter diagnostics verified end-to-end.
- [ ] Dual-tab inspection drawer, cURL copying, and encoding selector verified in browser.

---

## Phase 3: Semantic Threat Detection Matrix & Enhanced Vulnerability Rules (Virtual Patching)

### Task 78: 14-Module Semantic Matrix & Sensitivity Policy Engine
**Description:** Implement `pkg/engine/matrix.go` and `pkg/engine/types.go` defining the full **14 SafeLine Semantic Modules**: SQL Inj, XSS, File Upload, File Include, CMD Inj, Java Code Inj, Java Deserialization, PHP Deserialization, PHP Code Inj, ASP Code Inj, SSTI, CSRF, SSRF, and Mal HTTP. Implement 4 operating modes per module: `Disabled` (0), `Audit` (1), `Balance` (2), `Strict` (3). Implement per-site semantic override resolution in `pkg/config/types.go` and snapshot compiler.

**Acceptance criteria:**
- [ ] Define 14 semantic modules with independent mode enums in `pkg/engine/types.go`.
- [ ] Sensitivity thresholds: `Strict` enforces lower anomaly thresholds; `Balance` applies heuristics to avoid false positives; `Audit` logs without blocking; `Disabled` skips inspection.
- [ ] `AppConfig` supports per-site semantic overrides inheriting from global defaults.
- [ ] REST API endpoints `GET /api/v1/detector` and `POST /api/v1/detector` update global and per-site modes.
- [ ] Unit tests verify mode resolution and sensitivity thresholds.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/engine/...`
- [ ] Build succeeds: `go build ./pkg/engine/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/engine/types.go`
- `pkg/engine/matrix.go`
- `pkg/config/types.go`
- `pkg/config/compiler.go`
- `pkg/engine/matrix_test.go`
**Estimated scope:** Medium (5 files)

---

### Task 79: Code Injection & Deserialization Semantic Detectors (Java, PHP, ASP, SSTI)
**Description:** Implement semantic detectors in `pkg/engine/detectors_code.go` targeting:
1. **Java Code Inj**: OGNL (`#context`, `#_memberAccess`), SpEL (`T(java.lang.Runtime)`), Groovy expressions.
2. **Java Deserialization**: Magic bytes (`aced0005`, `rO0AB`), CommonCollections, Fastjson `@type` gadgets.
3. **PHP Code & Deserialization**: `eval()`, `assert()`, `preg_replace /e`, PHP serialized strings (`O:8:"...":...`).
4. **ASP Code Inj**: Classic ASP `<% ... %>` and ASP.NET arbitrary code execution markers.
5. **SSTI**: Server-Side Template Injection syntax for Jinja2, Twig, Freemarker (`{{7*7}}`, `${7*7}`).

**Acceptance criteria:**
- [ ] Detectors evaluate normalized tokens with sub-microsecond lexical heuristics.
- [ ] Unit tests verify detection of Java OGNL, Fastjson, PHP `eval`, and Jinja2 SSTI payloads.
- [ ] Benign mathematical expressions and template strings are permitted in `Balance` mode.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/engine/...`
- [ ] Build succeeds: `go build ./pkg/engine/...`

**Dependencies:** Task 78
**Files likely touched:**
- `pkg/engine/detectors_code.go`
- `pkg/engine/detectors_code_test.go`
- `pkg/engine/semantic.go`
**Estimated scope:** Medium (3 files)

---

### Task 80: Web & Network Flaw Semantic Detectors (File Upload, LFI/RFI, SSRF, CSRF, Mal HTTP)
**Description:** Implement detectors in `pkg/engine/detectors_web.go` targeting:
1. **File Uploading**: Executable extension detection (`.php`, `.jsp`, `.asp`, `.sh`, polyglot magic bytes) in multipart form uploads.
2. **File Including (LFI/RFI)**: Directory traversal sequences (`../`, `..%2f`, `..%5c`), absolute path leaks (`/etc/passwd`, `C:\Windows\win.ini`), PHP wrappers (`php://filter`).
3. **SSRF**: Cloud metadata IP detection (`169.254.169.254`, `metadata.google.internal`), loopback addresses in redirect/URL parameters.
4. **CSRF**: Validation of origin vs host headers on state-changing methods.
5. **Mal HTTP**: HTTP Request Smuggling markers (duplicate `Content-Length`, conflicting `Transfer-Encoding: chunked`).

**Acceptance criteria:**
- [ ] Detectors block webshell uploads, directory traversal, and cloud metadata SSRF attempts.
- [ ] Unit tests verify LFI/RFI traversal, SSRF IP blocking, and request smuggling detection.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/engine/...`
- [ ] Build succeeds: `go build ./pkg/engine/...`

**Dependencies:** Task 78
**Files likely touched:**
- `pkg/engine/detectors_web.go`
- `pkg/engine/detectors_web_test.go`
- `pkg/engine/semantic.go`
**Estimated scope:** Medium (3 files)

---

### Task 81: Enhanced Virtual Patching CVE Engine (`inner_rules`)
**Description:** Implement `pkg/engine/cve/` virtual patching engine housing a curated library of **193 CVE signatures** (e.g. Log4j JNDI CVE-2021-44228, Apache Shiro bypass, Spring4Shell, Ghostscript RCE, Git config disclosure `.git/config`, Vite file read CVE-2025-31125, MongoDB injection). Optimize evaluation using fast path method and URI prefix indexing. Support per-rule enable/disable toggles and category grouping.

**Acceptance criteria:**
- [ ] Embed compressed 193 CVE signature database in `pkg/engine/cve/rules.json`.
- [ ] Build fast lookup index by HTTP method and URI prefix to ensure sub-microsecond evaluation.
- [ ] Support per-rule enable/disable toggles and category grouping.
- [ ] Unit tests verify Log4j, Shiro, Spring4Shell, and `.git/config` exploit attempts are blocked.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/engine/cve/...`
- [ ] Build succeeds: `go build ./pkg/engine/cve/...`

**Dependencies:** Tasks 78, 79, 80
**Files likely touched:**
- `pkg/engine/cve/engine.go`
- `pkg/engine/cve/rules.json`
- `pkg/engine/cve/matcher.go`
- `pkg/engine/cve/cve_test.go`
**Estimated scope:** Medium (4 files)

---

### Task 82: Frontend Semantic Matrix & Inner Rules Management Views
**Description:** Implement `web/src/views/SemanticsView.vue` and `web/src/views/InnerRulesView.vue`. Provide an interactive 14-module matrix where operators can toggle policy modes (`Disabled`, `Audit`, `Balance`, `Strict`) globally or per application. Build the Enhanced Rules view listing all 193 CVE virtual patches with search, category filters, rule ID tags, and batch enable/disable switches.

**Acceptance criteria:**
- [ ] Grid view displaying all 14 semantic modules with 4-way mode radio buttons.
- [ ] Application selector dropdown allowing site-specific override configuration.
- [ ] Inner rules table displaying 193 CVE rules with search, status toggles, and CVE tags.
- [ ] Batch toggle actions (e.g. "Enable All RCE Rules", "Disable All").
- [ ] Vitest unit tests verify mode changes and rule toggle mutations.

**Verification:**
- [ ] Tests pass: `cd web && pnpm test -- Semantics`
- [ ] Build succeeds: `cd web && pnpm build`

**Dependencies:** Tasks 74, 78, 81
**Files likely touched:**
- `web/src/views/SemanticsView.vue`
- `web/src/views/InnerRulesView.vue`
- `web/src/api/client.ts`
- `web/src/views/__tests__/SemanticsView.spec.ts`
**Estimated scope:** Medium (4 files)

---

### Checkpoint 3: Threat Detection & Virtual Patching
- [ ] 14 semantic modules and 193 CVE rules verified blocking exploits in unit tests.
- [ ] Matrix UI and inner rules management verified in frontend tests.

---

## Phase 4: Dynamic Proxying, Sub-Path Forwarding & API Auto-Discovery

### Task 83: Dynamic Upstream Proxying & Path-Prefix Forwarding in Caddy Middleware
**Description:** Wire `UpstreamPool` from [`pkg/proxy/upstream.go`](file:///Users/macbook/Code/raiwall/pkg/proxy/upstream.go) directly into [`pkg/proxy/middleware.go`](file:///Users/macbook/Code/raiwall/pkg/proxy/middleware.go) to support dynamic proxying and **Path-Prefix Forwarding Rules** (`/sites/detail?tab=forwardingRule`). When an `AppConfig` has custom `upstreams` or `forwarding_rules` defined in snapshot, route matching requests to the designated backend target with longest prefix matching, path stripping, and host header override before falling back to `next.ServeHTTP`. Update SQLite schema and `driver.go` with `raiwall_forwarding_rules`.

**Acceptance criteria:**
- [ ] Add `ForwardingRule` struct (`Prefix`, `Upstreams`, `StripPrefix`, `HostHeaderOverride`, `Comment`, `IsActive`) to `pkg/config/types.go`.
- [ ] Update SQLite schema, `sqlc` queries, and in-memory `driver.go` with `raiwall_forwarding_rules`.
- [ ] Middleware dispatches requests to dynamic `UpstreamPool` matching longest prefix before default app upstreams.
- [ ] Unit and integration tests verify path routing, prefix stripping, and host header overrides.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/proxy/...`
- [ ] Build succeeds: `go build ./pkg/proxy/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/config/types.go`
- `pkg/control/db/schema.sql`
- `pkg/control/db/driver.go`
- `pkg/proxy/middleware.go`
- `pkg/proxy/forwarding_test.go`
**Estimated scope:** Medium (5 files)

---

### Task 84: Advanced Proxy Settings Matrix
**Description:** Implement granular per-site proxy tuning in `AppConfig`: client IP extraction source (`socket`, `xff`, custom header), X-Forwarded-For rewrite/sanitization toggle, HSTS header injection, SSE streaming toggle (disables proxy buffering for Server-Sent Events / LLM AI streams), Gzip/Brotli compression switches, IPv6 socket listen toggle, and automatic HTTP-to-HTTPS 301 redirection.

**Acceptance criteria:**
- [ ] Extend `AppConfig` with `ProxySettings` struct covering all 7 configuration options.
- [ ] Middleware enforces XFF rewriting (stripping outer untrusted client headers).
- [ ] Middleware injects HSTS headers on HTTPS responses when enabled.
- [ ] Proxy disables response buffering for SSE when enabled.
- [ ] Unit tests verify header rewrite, HSTS injection, and HTTP->HTTPS redirection.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/proxy/...`
- [ ] Build succeeds: `go build ./pkg/proxy/...`

**Dependencies:** Task 83
**Files likely touched:**
- `pkg/config/types.go`
- `pkg/proxy/middleware.go`
- `pkg/proxy/client_ip.go`
- `pkg/proxy/advanced_test.go`
**Estimated scope:** Medium (4 files)

---

### Task 85: Passive Runtime API Auto-Discovery & Shadow API Inventory Engine
**Description:** Implement `pkg/proxy/discovery.go` passive API cataloger. When enabled, sample clean transit traffic and record unique API endpoints (HTTP method, normalized URI path template, detected Content-Type, 24-hour request counter, and last seen timestamp) into SQLite table `raiwall_api_resources` (with `driver.go` support). Provide API endpoints for querying and pruning discovered shadow APIs.

**Acceptance criteria:**
- [ ] Asynchronous sampling ring buffer captures clean request paths and methods.
- [ ] Normalizer collapses numeric and UUID path parameters into template variables (e.g. `/users/123` → `/users/{id}`).
- [ ] Periodic flush persists discovered endpoints to SQLite with 24-hour hit counters.
- [ ] REST API endpoints support `GET /api/v1/sites/{id}/resources` and `DELETE /api/v1/sites/{id}/resources/{resource_id}`.
- [ ] Unit tests verify path normalization, async logging, and pruning.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/proxy/...`
- [ ] Build succeeds: `go build ./pkg/proxy/...`

**Dependencies:** Task 83
**Files likely touched:**
- `pkg/proxy/discovery.go`
- `pkg/control/db/schema.sql`
- `pkg/control/db/driver.go`
- `pkg/control/api/sites.go`
- `pkg/proxy/discovery_test.go`
**Estimated scope:** Medium (5 files)

---

### Task 86: Frontend Application Detail Overhaul
**Description:** Refactor `web/src/views/SitesView.vue` and create `web/src/views/SiteDetailView.vue` with 4 dedicated management tabs:
1. `Basic Information`: metadata, bound ports, upstreams, operational mode.
2. `Forwarding Rules`: path-prefix routing list with add/edit rule modal.
3. `Advanced Settings`: proxy configuration matrix (XFF rewrite, HSTS, SSE, compression, IPv6, HTTP redirect).
4. `Routings / API Inventory`: auto-discovered API catalog with search, access counts, and prune actions.

**Acceptance criteria:**
- [ ] Application detail view renders 4 tabs matching SafeLine's site detail UX.
- [ ] Forwarding rules tab allows adding/editing/deleting path prefixes with upstream target assignment.
- [ ] Advanced settings tab provides intuitive toggles for XFF, HSTS, SSE, and compression.
- [ ] Routings tab lists auto-discovered APIs with request counters and delete action.
- [ ] Vitest unit tests verify site detail tab navigation and form submissions.

**Verification:**
- [ ] Tests pass: `cd web && pnpm test -- SiteDetail`
- [ ] Build succeeds: `cd web && pnpm build`

**Dependencies:** Tasks 74, 83, 84, 85
**Files likely touched:**
- `web/src/views/SiteDetailView.vue`
- `web/src/components/ForwardingRulesEditor.vue`
- `web/src/components/ProxyConfigEditor.vue`
- `web/src/components/ApiInventoryTable.vue`
- `web/src/views/__tests__/SiteDetailView.spec.ts`
**Estimated scope:** Large (5 files)

---

### Checkpoint 4: Application Gateway & Microservices
- [ ] Dynamic proxying, sub-path routing, and API auto-discovery verified in Go tests.
- [ ] 4-tab Site Detail UI verified in Vitest component tests.

---

## Phase 5: Volumetric Defense, Active Ban Registry & Virtual Waiting Room

### Task 87: Active Banned IP Registry & Emergency "Unblock All" API
**Description:** Extend `pkg/rate/` to expose an active blocked clients registry tracking banned IPs, trigger reason (Tier 1 velocity, Tier 2 attack frequency, Tier 3 scanner trap, or ACL blacklist), ban timestamp, remaining duration, and target site. Expose REST endpoints: `GET /api/v1/rate/bans`, `POST /api/v1/rate/bans/release` (unblock single IP), and `POST /api/v1/rate/bans/release-all` ("UNBLOCK ALL" emergency release).

**Acceptance criteria:**
- [x] Active ban store tracks all currently banned clients across local memory and Redis.
- [x] Release endpoint immediately evicts IP from memory cache and Redis ban set.
- [x] "Unblock All" clears entire ban registry and broadcasts unblock event across cluster.
- [x] Unit tests verify ban listing, single release, and emergency unblock-all.

**Verification:**
- [x] Tests pass: `go test -v -race ./internal/core/rate/...`
- [x] Build succeeds: `go build ./internal/core/rate/...`

**Dependencies:** None
**Files likely touched:**
- `internal/core/rate/ban.go`
- `internal/adapters/inbound/http/policies_unified.go`
- `internal/core/rate/ban_test.go`
**Estimated scope:** Medium (3 files)

---

### Task 88: Virtual Waiting Room Path Targeting, Telemetry Metrics & HTTP 465 Status Code
**Description:** Upgrade [`pkg/rate/waitingroom.go`](file:///Users/macbook/Code/raiwall/pkg/rate/waitingroom.go) and [`pkg/rate/templates.go`](file:///Users/macbook/Code/raiwall/pkg/rate/templates.go) to support path-level targeting (e.g. only queue flash crowd requests targeting `/tickets/checkout` or `/flash-sale/*`, leaving static assets unqueued). Standardize the response code to **HTTP 465** (updating from HTTP 503). Add real-time telemetry tracking: Active In-Flight Users, Total Users Waiting, Peak Queue Depth, Average Wait Seconds, and Client Bounce Rate. Expose `GET /api/v1/waiting-room/metrics`.

**Acceptance criteria:**
- [x] Waiting Room supports configurable target path prefixes in policy snapshot.
- [x] Waiting Room returns deterministic **HTTP 465** status code on queue redirection and API load shedding.
- [x] Telemetry collector computes live queue metrics and bounce rate percentages.
- [x] Caddy middleware only enqueues requests matching configured path prefixes.
- [x] Unit tests verify path targeting, HTTP 465 responses, and metrics calculation.

**Verification:**
- [x] Tests pass: `go test -v -race ./internal/core/rate/...`
- [x] Build succeeds: `go build ./internal/core/rate/...`

**Dependencies:** Task 87
**Files likely touched:**
- `internal/core/rate/waitingroom.go`
- `internal/core/rate/templates.go`
- `internal/core/rate/types.go`
- `internal/adapters/inbound/http/policies_unified.go`
- `internal/core/rate/waitingroom_test.go`
**Estimated scope:** Medium (5 files)

---

### Task 89: Frontend HTTP Flood & Waiting Room Console View
**Description:** Implement `web/src/views/HttpFloodView.vue` with 3 sub-views:
1. `Active Blocked Clients`: real-time table of banned IPs with countdown timer, reason, and individual "Unblock" and prominent "UNBLOCK ALL" buttons.
2. `3-Tier Limits Configuration`: form controls for Tier 1 velocity, Tier 2 attack ban, Tier 3 scanner trap.
3. `Waiting Room Dashboard`: live gauge cards (Active Users Allowed, Users Waiting, Avg Wait Time), queue trend chart, and path-prefix queue settings.

**Acceptance criteria:**
- [x] Active blocked clients table refreshes live and allows single and bulk unblocking.
- [x] "UNBLOCK ALL" modal prompts for confirmation before purging ban table.
- [x] Waiting Room dashboard displays live queue telemetry and bounce rates.
- [x] Vitest tests verify unblock actions, modal confirmation, and form saves.

**Verification:**
- [x] Tests pass: `cd web && pnpm test -- HttpFlood`
- [x] Build succeeds: `cd web && pnpm build`

**Dependencies:** Tasks 74, 87, 88
**Files likely touched:**
- `web/src/views/HttpFloodView.vue`
- `web/src/components/ActiveBansTable.vue`
- `web/src/components/WaitingRoomDashboard.vue`
- `web/src/views/__tests__/HttpFloodView.spec.ts`
**Estimated scope:** Medium (4 files)

---

### Checkpoint 5: Volumetric Defense & Traffic Buffering
- [x] Active ban registry and emergency "Unblock All" verified in Go tests.
- [x] HTTP Flood and Waiting Room dashboard with HTTP 465 verified in Vitest tests.

---

## Phase 6: Pre-Application Zero-Trust Identity Gateway (HTTP 467)

### Task 90: SQLite Identity User Directory (5,000 Accounts, RBAC, 2FA TOTP Cryptography)
**Description:** Implement `pkg/auth/user_store.go` and database schema tables `raiwall_identity_users` in `pkg/control/db/schema.sql` (and `driver.go`). Provide an enterprise identity directory supporting up to 5,000 end-users (separate from admin console operators) with username, password hashing (bcrypt), email, assigned application permissions, and 2FA TOTP secret generation/validation (`pquerna/otp`). Provide REST API CRUD endpoints.

**Acceptance criteria:**
- [ ] SQLite schema stores `raiwall_identity_users` with password hash, TOTP secret, enabled state, and assigned app IDs.
- [ ] In-memory `driver.go` supports `raiwall_identity_users` table queries.
- [ ] 2FA TOTP validator verifies 6-digit codes against stored secret.
- [ ] REST API CRUD endpoints for user accounts, password reset, and TOTP reset.
- [ ] Unit tests cover local user creation, login validation, and TOTP verification.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/auth/... ./pkg/control/db/...`
- [ ] Build succeeds: `go build ./pkg/auth/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/auth/user_store.go`
- `pkg/auth/totp.go`
- `pkg/control/db/schema.sql`
- `pkg/control/db/driver.go`
- `pkg/control/api/auth_users.go`
- `pkg/auth/user_store_test.go`
**Estimated scope:** Medium (6 files)

---

### Task 91: External Identity Provider Connectors (LDAP & GitHub OAuth2)
**Description:** Expand `pkg/auth/` with external enterprise IdP connectors: LDAP/Active Directory (`go-ldap/ldap/v3`) and GitHub OAuth2, complementing the existing `OIDCClient`. Implement unified `IdentityProvider` interface allowing authentication via local directory, OIDC, LDAP, or GitHub. Store IdP configurations in `raiwall_identity_providers`.

**Acceptance criteria:**
- [ ] Unified `IdentityProvider` interface implemented by Local, OIDC, LDAP, and GitHub providers.
- [ ] LDAP connector authenticates users against Active Directory / OpenLDAP via Bind DN.
- [ ] GitHub connector exchanges OAuth2 code for verified GitHub user profile.
- [ ] SQLite schema and `driver.go` store provider connection parameters.
- [ ] Unit tests verify mock LDAP authentication and GitHub token exchange.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/auth/...`
- [ ] Build succeeds: `go build ./pkg/auth/...`

**Dependencies:** Task 90
**Files likely touched:**
- `pkg/auth/ldap.go`
- `pkg/auth/github.go`
- `pkg/auth/provider.go`
- `pkg/control/db/schema.sql`
- `pkg/control/db/driver.go`
- `pkg/auth/ldap_test.go`
**Estimated scope:** Medium (6 files)

---

### Task 92: Per-App HTTP 467 Auth Challenge Gate, API Bypass & Unified SSO Session Token
**Description:** Wire per-site Pre-Application Authentication into [`pkg/proxy/middleware.go`](file:///Users/macbook/Code/raiwall/pkg/proxy/middleware.go). When `AppConfig.AuthEnabled: true`, unauthenticated browser requests are intercepted and return **HTTP 467** serving the branded login portal. Upon successful login + 2FA, issue encrypted HMAC clearance session cookie (`sl_jwt_session`) valid across all authorized sites (Unified SSO). Ensure API fast-paths (`Authorization: Bearer`, `/api/*`) bypass the challenge.

**Acceptance criteria:**
- [ ] `AppConfig` extended with `AuthEnabled` boolean and `AuthBypassPaths []string`.
- [ ] Unauthenticated browser requests targeting protected sites return **HTTP 467** with login UI.
- [ ] API routes and Bearer tokens bypass interactive HTTP 467 challenge transparently.
- [ ] Successful authentication issues signed clearance cookie and redirects back to destination.
- [ ] Unit and integration tests verify HTTP 467 interception, cookie clearance, and API bypass.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/proxy/... ./pkg/auth/...`
- [ ] Build succeeds: `go build ./pkg/proxy/...`

**Dependencies:** Tasks 90, 91
**Files likely touched:**
- `pkg/config/types.go`
- `pkg/auth/handler.go`
- `pkg/auth/session.go`
- `pkg/proxy/middleware.go`
- `pkg/auth/gateway_test.go`
**Estimated scope:** Medium (5 files)

---

### Task 93: Frontend Auth Gateway Management Console (User Directory, SSO Portal, IdP Settings)
**Description:** Implement `web/src/views/AuthGatewayView.vue` with 4 management sub-views:
1. `Authentication Logs`: audit table of login events (account, app, method, result, IP, country).
2. `User Management`: 5,000 user directory table with add user dialog, password reset, app assignments, and 2FA TOTP status.
3. `Single Sign-On (SSO)`: Unified SSO portal toggle and app binding checkboxes.
4. `Login Configuration`: credentials branding editor and IdP connector forms (OIDC, LDAP, GitHub OAuth).

**Acceptance criteria:**
- [ ] User directory table supports search, user creation, app assignment, and TOTP reset.
- [ ] SSO tab allows toggling unified portal across selected domains.
- [ ] IdP configuration forms validate connection parameters.
- [ ] Vitest tests verify user creation, TOTP reset dialog, and IdP form validation.

**Verification:**
- [ ] Tests pass: `cd web && pnpm test -- AuthGateway`
- [ ] Build succeeds: `cd web && pnpm build`

**Dependencies:** Tasks 74, 90, 91, 92
**Files likely touched:**
- `web/src/views/AuthGatewayView.vue`
- `web/src/components/UserDirectoryTable.vue`
- `web/src/components/IdPConfigModal.vue`
- `web/src/views/__tests__/AuthGatewayView.spec.ts`
**Estimated scope:** Medium (4 files)

---

### Checkpoint 6: Zero-Trust Identity Gateway
- [ ] 5,000 user directory, 2FA TOTP, and HTTP 467 auth challenge gate verified in Go.
- [ ] Auth management console verified in Vitest tests.

---

## Phase 7: IP Groups, Deterministic Templates & Production Verification

### Task 94: Named IP Groups Engine with BART Integration
**Description:** Implement `pkg/acl/ipgroup.go` managing named IP groups: Enhanced Malicious IP Group (5,000 active threat IPs), Search Engine Spider Group (verified Google, Bing, Baidu spider CIDRs), Threat Intelligence Feeds, and custom user-defined CIDR groups. Integrate directly with `gaissmai/bart` routing tables for sub-15 ns evaluation. Expose "In IP Group" operator in `expr` ACL engine and "Add to IP Group" endpoint.

**Acceptance criteria:**
- [ ] SQLite schema and `driver.go` store `raiwall_ip_groups` and entries.
- [ ] BART routing tables compiled in memory for sub-15 ns lookups across 500K+ IPs.
- [ ] Pre-populate verified Search Spiders and Malicious Threat Intelligence CIDRs.
- [ ] `expr` ACL engine supports `client_ip in ip_group("search_spiders")`.
- [ ] "Add to IP Group" API dynamically updates memory table and SQLite.
- [ ] Unit tests verify BART IP group matching, dynamic appends, and ACL integration.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/acl/...`
- [ ] Build succeeds: `go build ./pkg/acl/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/acl/ipgroup.go`
- `pkg/acl/engine.go`
- `pkg/control/db/schema.sql`
- `pkg/control/db/driver.go`
- `pkg/control/api/acls.go`
- `pkg/acl/ipgroup_test.go`
**Estimated scope:** Medium (6 files)

---

### Task 95: Custom HTML/CSS Response Template Manager & Visual Code Editor
**Description:** Implement `pkg/control/templates/` storing and rendering custom HTML error and challenge templates for deterministic status codes: `403` (Attack Blocked), `404` (Not Found), `429` (Rate Limited), `465` (Waiting Room), `466` (App Offline), `467` (Auth Challenge), `468` (Anti-Bot PoW), `502` (Bad Gateway), `504` (Timeout). Expose REST API and Vue UI editor `web/src/views/BlockPagesView.vue` with live in-browser preview, CSS customization, and corporate branding support.

**Acceptance criteria:**
- [ ] SQLite schema and `driver.go` store custom HTML/CSS templates per status code with fallback to defaults.
- [ ] Proxy middleware serves customized templates on corresponding status code triggers.
- [ ] REST API endpoints for fetching, updating, and previewing rendered templates.
- [ ] Frontend template editor view with responsive preview pane and custom branding.
- [ ] Unit and frontend tests verify template rendering and editor persistence.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/control/...`
- [ ] Frontend tests pass: `cd web && pnpm test -- BlockPage`
- [ ] Build succeeds: `go build ./...`

**Dependencies:** None
**Files likely touched:**
- `pkg/control/templates/manager.go`
- `pkg/control/api/templates.go`
- `pkg/control/db/schema.sql`
- `pkg/control/db/driver.go`
- `web/src/views/BlockPagesView.vue`
- `web/src/components/TemplateCodeEditor.vue`
**Estimated scope:** Medium (6 files)

---

### Task 96: End-to-End Enterprise Integration Suite, Single Binary Build & Performance Benchmark
**Description:** Implement comprehensive end-to-end integration tests in `tests/e2e/enterprise_waf_test.go` exercising the entire major update lifecycle: 14-module threat blocking, CVE virtual patches, path-prefix forwarding with dynamic `UpstreamPool`, active IP ban & unblock-all, Waiting Room queuing (HTTP 465), pre-application HTTP 467 auth challenge, and custom template rendering. Verify single binary builds cleanly as a compact binary (~50 MB) with all embedded web assets.

**Acceptance criteria:**
- [ ] End-to-end integration tests verify:
  - 14 semantic modules block exploits according to configured sensitivity modes.
  - CVE virtual patch blocks Log4j and Shiro exploits while permitting benign traffic.
  - Dynamic `UpstreamPool` routes path prefixes with header overrides.
  - Active ban table blocks attacker and releases immediately on "Unblock All".
  - Virtual Waiting Room returns HTTP 465 and admits clients in FIFO queue order.
  - Unauthenticated requests to protected app receive HTTP 467 auth challenge.
  - Custom HTML templates render with custom branding.
- [ ] Zero race conditions under high concurrent requests (`go test -race`).
- [ ] Production binary `bin/raiwall` builds cleanly as a compact binary (~50 MB, not strictly $< 50\text{ MB}$).

**Verification:**
- [ ] Tests pass: `go test -v -race -tags=integration ./tests/e2e/...`
- [ ] Build succeeds: `make build`
- [ ] Manual check: verify compact binary size (~50 MB) via `ls -lh bin/raiwall`.

**Dependencies:** Tasks 73–95
**Files likely touched:**
- `tests/e2e/enterprise_waf_test.go`
- `Makefile`
**Estimated scope:** Medium (2 files)

---

## Final Checkpoint: Major Update Complete
- [ ] All 24 tasks (Tasks 73–96) implemented and verified.
- [ ] 100% functional, operational, and UX parity with SafeLine v9.4.2 achieved.
- [ ] Single compact binary (~50 MB, not strictly < 50 MB) verified with zero CGO dependencies and zero runtime regressions.
