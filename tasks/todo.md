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
**Description:** Implement `tests/e2e/control_plane_test.go`, `tests/e2e/sidecar_test.go`, and update `Makefile`. Conduct end-to-end integration tests verifying complete control plane lifecycle: CRUD mutation -> draft diff -> staged apply with pre-flight check -> atomic swap -> Redis pub/sub delta broadcast -> Envoy ext_proc gRPC threat block -> 1-click rollback. Verify single binary builds cleanly under 50 MB with embedded admin UI and all tests pass with `-race`.

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
- [x] Single binary builds cleanly under 50 MB (`make build`).

**Verification:**
- [x] Integration tests pass: `go test -v -race -tags=integration ./tests/e2e/...`
- [x] Build succeeds: `make build`
- [x] Manual check: verify binary size is $<50\text{ MB}$ via `ls -lh bin/raiwall`.

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
- [x] Full Vue 3 enterprise admin dashboard built, tested, and embedded in single binary under 50 MB.
- [x] All unit, integration, and e2e tests pass cleanly with `-race`.
