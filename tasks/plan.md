# Implementation Plan: Raiwall Domain 7 (Control Plane, Customization & Ecosystem Integration)

## Overview
Implement **Domain 7: Control Plane, Customization & Ecosystem Integration** for **Raiwall**: an enterprise-grade control plane, dynamic configuration engine, Envoy `ext_proc/v3` sidecar inspection server, and embedded Vue 3 management suite.

Domain 7 delivers six integrated pillars:
1. **SQLite Schema & `sqlc` Persistence Layer (`pkg/control/db/`):** Pure-Go WAL-mode SQLite database with type-safe `sqlc` models storing protected Sites/Apps, parameter-level Exceptions, compiled ACL rules, Rate Limiting & Bot policies, versioned `ConfigSnapshot` revisions, and admin users/API keys.
2. **Atomic Config Compiler & 1-Click Rollback Engine (`pkg/config/`):** Lock-free atomic configuration swap via `atomic.Pointer[ConfigSnapshot]` with comprehensive pre-flight validation (compiling `expr-lang/expr` expressions, checking BART CIDRs, validating regexes, testing upstream dials). Rejects faulty configurations before live application and supports instantaneous 1-click rollback to any historical snapshot.
3. **Type-Safe Huma v2 OpenAPI 3.1 REST API & MCP Protocol Bridge (`pkg/control/api/`, `pkg/control/mcp/`):** Modern OpenAPI 3.1 management API using `danielgtaylor/huma/v2` with interactive Scalar documentation (`/.raiwall/api/docs`), Bearer API keys + session cookies with 2-tier RBAC (`admin`, `viewer`), and Model Context Protocol (MCP) server support (`/.raiwall/api/mcp` and `raiwall mcp` CLI) for AI-assisted operations.
4. **Redis Pub/Sub Cluster Synchronization (`pkg/control/cluster/`):** Distributed cluster configuration broadcast across Raiwall instances. Publishes lightweight version notifications to Redis Pub/Sub, caches the latest compiled snapshot in Redis, and automatically reconciles worker node configurations upon startup or network reconnection.
5. **Envoy `ext_proc/v3` gRPC Sidecar Inspection Engine (`pkg/sidecar/`):** High-performance gRPC server implementing Envoy's External Processor protocol (`envoy.service.ext_proc.v3.ExternalProcessorServer`). Operates in dual mode: as a standalone Kubernetes sidecar daemon (`raiwall sidecar --listen :50051`) or concurrently alongside Caddy reverse proxy via Caddyfile directive (`sidecar { listen :50051 }`).
6. **Embedded Vue 3 Enterprise Admin Dashboard (`web/`):** Full single-page management application built with Vue 3, TypeScript, Vite, `shadcn-vue`, Pinia, and Vue Router. Features comprehensive views for Sites/Upstreams, Exceptions (with test simulator), ACL Builder (with live `expr` validator), Rate & Bot Defense, Staged Deployment Diff Review, Snapshot Timeline with 1-Click Rollback, and API Key administration.

---

## Architecture Decisions

- **Hybrid Control Plane Listener:** By default, the Control Plane (Huma REST API, Scalar docs, and Admin UI) is served securely under the internal namespace `/.raiwall/` on the main proxy listener (protected by RBAC and IP ACLs). An optional dedicated management port (e.g. `admin_listen 127.0.0.1:9090`) is supported in Caddyfile and CLI for air-gapped enterprise architectures.
- **2-Tier RBAC with Dual Auth:** Huma REST API and Admin UI support Bearer tokens (`X-Raiwall-Key` or `Authorization: Bearer <key>`) for automation/CI/CD and secure HMAC-signed session cookies for the UI. Roles are partitioned into `admin` (full read/write, deploy, rollback) and `viewer` (read-only telemetry and rule inspection).
- **Staged Revisions with Pre-Flight Validation:** Configuration mutations are staged in SQLite draft state, enabling review of visual diffs before applying. On "Deploy Changes", the compiler compiles `expr` bytecode, validates BART CIDR blocks, and verifies upstream endpoints. Upon passing, a new immutable `ConfigSnapshot` is committed to history and swapped atomically via `atomic.Pointer`.
- **Lightweight Cluster Notification with Snapshot Fetch:** In clustered deployments, the master node publishes a version notification (`{"version": 42, "hash": "..."}`) to Redis Pub/Sub channel `raiwall:cluster:events` and stores the compiled snapshot in Redis key `raiwall:config:snapshot:latest`. Worker nodes fetch, validate, and swap the snapshot, with automatic poll reconciliation on reconnect.
- **Dual-Mode Envoy `ext_proc/v3` Engine:** The sidecar inspection engine shares the exact same threat detection pipeline, normalizers, `libinjection`, AST checkers, and ACL rules as the Caddy reverse proxy. It can run as a standalone sidecar microservice (`raiwall sidecar`) or as an embedded listener in Caddyfile.
- **OpenAPI 3.1 & MCP Protocol Bridge:** OpenAPI 3.1 JSON and interactive Scalar docs are exposed at `/.raiwall/api/docs`. An MCP server endpoint at `/.raiwall/api/mcp` and CLI `raiwall mcp` allow AI assistants to inspect telemetry, draft exceptions, and trigger rollbacks safely.

---

## Dependency Graph

```
SQLite Database Schema & sqlc Models (pkg/control/db/)
   │
   ├── Config Compiler, Pre-Flight Validator & Rollback (pkg/config/compiler.go, rollback.go)
   │       │
   │       ├── Huma v2 OpenAPI 3.1 REST API & RBAC (pkg/control/api/server.go, auth.go)
   │       │       │
   │       │       ├── Configuration CRUD & Deployment Diff Endpoints (pkg/control/api/sites.go, snapshots.go)
   │       │       │       │
   │       │       │       └── Model Context Protocol (MCP) Bridge (pkg/control/mcp/server.go)
   │       │       │
   │       │       └── Redis Pub/Sub Cluster Sync (pkg/control/cluster/pubsub.go)
   │       │
   │       └── Envoy ext_proc/v3 gRPC Sidecar Engine (pkg/sidecar/server.go, processor.go)
   │               │
   │               └── Caddy Middleware & CLI Integration (cmd/raiwall/sidecar.go, pkg/proxy/caddyfile.go)
   │
   └── Vue 3 Enterprise Admin Dashboard (web/src/)
           │
           ├── Typed API Client & Pinia Stores (web/src/api/client.ts, stores/config.ts)
           │
           ├── Sites & Upstream Pools Manager (web/src/views/SitesView.vue)
           │
           ├── Exceptions & ACL Rules Builder (web/src/views/ExceptionsView.vue, ACLsView.vue)
           │
           ├── Rate Limiting & Bot Defense Policies (web/src/views/PoliciesView.vue)
           │
           └── Staged Diff Review, Snapshot History & 1-Click Rollback (web/src/views/DeploymentsView.vue)
```

---

## Task List Index

Tasks are tracked in `tasks/todo.md`:

### Phase 1: Database Schema, `sqlc` Code Generation & In-Memory Config Rollback Engine
- [ ] **Task 58: SQLite Schema & `sqlc` Repository for Control Plane Persistence** (Size: M)
- [ ] **Task 59: Atomic Config Snapshot Compiler, Pre-Flight Validator & Rollback Engine** (Size: M)
- [ ] *Checkpoint: Control Plane DB schema and Atomic Config Compiler/Rollback pass all unit and concurrency tests.*

### Phase 2: Huma v2 OpenAPI 3.1 REST API, Auth & MCP Tool Bridge
- [ ] **Task 60: Huma v2 REST Framework Setup, Admin Auth & 2-Tier RBAC** (Size: M)
- [ ] **Task 61: Configuration CRUD Endpoints & Staged Deployment API** (Size: M)
- [ ] **Task 62: Model Context Protocol (MCP) Server Endpoint & CLI Stdio Adapter** (Size: M)
- [ ] *Checkpoint: Huma REST API, Scalar docs, RBAC, CRUD endpoints, and MCP tools fully tested and verified.*

### Phase 3: Redis Pub/Sub Cluster Synchronization
- [ ] **Task 63: Redis Pub/Sub Cluster Sync Engine & Reconnect Re-synchronization** (Size: M)
- [ ] *Checkpoint: Cluster synchronization verified across mock and live Redis instances.*

### Phase 4: Envoy External Processor (`ext_proc/v3`) gRPC Sidecar Engine
- [ ] **Task 64: Envoy `ext_proc/v3` gRPC Server Protocol Implementation** (Size: M)
- [ ] **Task 65: Sidecar CLI Command & Caddyfile Directive Integration** (Size: M)
- [ ] *Checkpoint: Envoy ext_proc gRPC passes integration tests blocking SQLi/XSS and enforcing ACLs.*

### Phase 5: Embedded Vue 3 Enterprise Admin Dashboard (Full Control Plane UI)
- [ ] **Task 66: Dashboard Shell, Navigation, Pinia API Client & Auth Views** (Size: M)
- [ ] **Task 67: Sites, Upstream Pools & Run Mode Management View** (Size: M)
- [ ] **Task 68: False-Positive Exceptions & ACL Rules Builder with Test Simulator** (Size: M)
- [ ] **Task 69: Rate Limiting, Bot Defense & Cluster Settings Views** (Size: M)
- [ ] **Task 70: Staged Deployment Diff Review, Snapshot History & 1-Click Rollback View** (Size: M)
- [ ] *Checkpoint: Complete Vue 3 Admin Dashboard builds cleanly, tests pass with Vitest, and embedded assets render flawlessly.*

### Phase 6: End-to-End Integration, CLI Tooling & Production Verification
- [ ] **Task 71: Admin CLI Commands (`raiwall admin init`, `create-user`, `apply`, `rollback`)** (Size: M)
- [ ] **Task 72: Domain 7 End-to-End Integration Tests, Sidecar Verification & Benchmark Validation** (Size: M)
- [ ] *Checkpoint: Milestone 7 complete, all unit/integration/e2e tests pass with `-race`, binary size verified under 50 MB.*

---

## Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **Faulty Config Reload Breaks Production Traffic** | **Critical** | Pre-flight compilation step validates all `expr` rules, CIDRs, and upstream addresses before atomic swap. If validation fails, deployment is rejected. 1-click rollback instantly restores the last known healthy snapshot. |
| **Cluster Worker Node Network Partition** | **High** | Worker nodes poll the latest snapshot version from Redis cache upon reconnect or startup, healing missed Pub/Sub events automatically. |
| **gRPC Ext_Proc Stream Buffer Exhaustion** | **High** | Envoy request body buffering is capped at 1 MB. Streaming payloads exceeding 1 MB are passed through with header inspection only. |
| **Single Binary Size Inflation (>50 MB)** | **Medium** | Tree-shake unused icons and frontend components in Vite; compile pure-Go SQLite without CGO overhead; verify binary size in CI. |
| **Admin Route Unauthorized Access** | **Critical** | Default `/.raiwall/api` and UI endpoints enforce Bearer key or session cookie authentication with CSRF protection and optional BART CIDR IP whitelisting. |
