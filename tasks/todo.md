# Tasks: Raiwall Domain 1 (Reverse Proxy & Gateway)

## Phase 1: Project Scaffolding & Build Pipeline

### Task 1: Workspace Initialization & Build Tooling
**Description:** Initialize the Go module `github.com/raiwall/raiwall`, set up the project folder structure (`cmd/raiwall`, `pkg/proxy`, `pkg/engine`, `pkg/config`), write a `Makefile` with build/test/lint targets, and create `cmd/raiwall/main.go` embedding Caddy v2's CLI runtime.

**Acceptance criteria:**
- [x] `go.mod` exists with Go 1.27+ and imports `github.com/caddyserver/caddy/v2`.
- [x] Standard directory layout created (`cmd/`, `pkg/`, `tests/`, `examples/`).
- [x] `cmd/raiwall/main.go` compiles and executes `caddy.Main()`, outputting Caddy/Raiwall version on `--version`.
- [x] `Makefile` provides working `build`, `test`, `lint`, and `run` targets.

**Verification:**
- [x] Build succeeds: `go build -o bin/raiwall ./cmd/raiwall`
- [x] Manual check: `./bin/raiwall version` outputs version information cleanly.

**Dependencies:** None
**Files likely touched:**
- `go.mod`
- `Makefile`
- `cmd/raiwall/main.go`
- `cmd/raiwall/version.go`
**Estimated scope:** Small (1–3 files)

---

### Task 2: Core Configuration Snapshot & Run Modes
**Description:** Implement thread-safe in-memory configuration structures for applications, upstreams, and protection modes (**Defense**, **Audit**, **Offline**). Provide an atomic pointer wrapper (`atomic.Pointer[ConfigSnapshot]`) for lock-free, zero-latency reads in the HTTP request pipeline.

**Acceptance criteria:**
- [x] Define `AppConfig`, `UpstreamTarget`, `RunMode` (Defense, Audit, Offline), and `ConfigSnapshot`.
- [x] Implement `StoreSnapshot(newSnap *ConfigSnapshot)` and `LoadSnapshot() *ConfigSnapshot` using `atomic.Pointer`.
- [x] Thread-safe concurrent read/write unit test verifies zero race conditions (`go test -race`).

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/config/...`
- [x] Build succeeds: `go build ./pkg/config/...`

**Dependencies:** Task 1
**Files likely touched:**
- `pkg/config/types.go`
- `pkg/config/snapshot.go`
- `pkg/config/snapshot_test.go`
**Estimated scope:** Small (2–3 files)

---

## Checkpoint: Foundation
- [x] Application compiles into `bin/raiwall` with embedded Caddy.
- [x] `pkg/config` unit tests pass with zero race conditions (`go test -race ./pkg/config/...`).
- [x] Foundation ready for Caddy module registration.

---

## Phase 2: Core Reverse Proxy & WAF Middleware

### Task 3: Caddy WAF Middleware Registration & Caddyfile Directive
**Description:** Register Raiwall as an official Caddy v2 HTTP middleware module (`caddy.Module`, `caddy.Provisioner`, `caddy.Validator`, `caddyhttp.MiddlewareHandler`). Implement the Caddyfile unmarshaler supporting the `raiwall` directive.

**Acceptance criteria:**
- [x] Register module ID `http.handlers.raiwall` with Caddy runtime.
- [x] Implement `Provision()` and `Validate()` to initialize default configs and buffer pools.
- [x] Implement Caddyfile parser recognizing directive `raiwall { mode <defense|audit|offline> }`.
- [x] Unit test verifies parsing Caddyfile blocks into the middleware configuration struct.

**Verification:**
- [x] Tests pass: `go test -v ./pkg/proxy/caddyfile_test.go`
- [x] Build succeeds: `go build ./pkg/proxy/...`

**Dependencies:** Task 1, Task 2
**Files likely touched:**
- `pkg/proxy/middleware.go`
- `pkg/proxy/caddyfile.go`
- `pkg/proxy/caddyfile_test.go`
**Estimated scope:** Medium (3–4 files)

---

### Task 4: Real Client IP & Header Extraction
**Description:** Implement robust client IP extraction supporting `X-Forwarded-For`, `X-Real-IP`, `CF-Connecting-IP`, and HAProxy `PROXY` protocol headers. Inject the parsed `net.IP` into the request context for downstream rate limiting and GeoIP modules.

**Acceptance criteria:**
- [x] Priority-based header lookup (`CF-Connecting-IP` > `X-Real-IP` > `X-Forwarded-For` > `RemoteAddr`).
- [x] Safely parses IPv4 and IPv6 addresses, ignoring invalid or spoofed header values.
- [x] Injects client IP into `r.Context()` with helper `GetClientIP(r *http.Request) net.IP`.
- [x] Unit tests cover multiple CDN header combinations and edge cases (private vs public IPs).

**Verification:**
- [x] Tests pass: `go test -v ./pkg/proxy/client_ip_test.go`
- [x] Build succeeds: `go build ./pkg/proxy/...`

**Dependencies:** Task 3
**Files likely touched:**
- `pkg/proxy/client_ip.go`
- `pkg/proxy/client_ip_test.go`
**Estimated scope:** Small (2 files)

---

### Task 5: Two-Phase Request & Response Interceptor
**Description:** Implement the two-phase HTTP inspection lifecycle in Caddy's `ServeHTTP`. In the request phase, evaluate run modes (`Offline` serves a static maintenance screen; `Defense` blocks with customizable HTML template; `Audit` passes through with telemetry). In the response phase, wrap `http.ResponseWriter` to record 403/404 error codes and strip sensitive backend headers (`Server`, `X-Powered-By`).

**Acceptance criteria:**
- [x] `Offline` mode immediately halts request and returns HTTP 503 with maintenance HTML.
- [x] `Defense` block verdict immediately returns HTTP 403 with SafeLine-style block template.
- [x] Custom `responseWriter` captures upstream status code without breaking chunked encoding or streaming.
- [x] Strips or overrides sensitive backend response headers (`Server`, `X-Powered-By`, `X-AspNet-Version`).

**Verification:**
- [x] Tests pass: `go test -v ./pkg/proxy/interceptor_test.go`
- [x] Build succeeds: `go build ./pkg/proxy/...`

**Dependencies:** Task 3, Task 4
**Files likely touched:**
- `pkg/proxy/interceptor.go`
- `pkg/proxy/response_writer.go`
- `pkg/proxy/interceptor_test.go`
**Estimated scope:** Medium (3 files)

---

## Checkpoint: Core Middleware
- [x] Caddy module successfully registers and unmarshals Caddyfile syntax.
- [x] Real client IP extracted accurately across test cases.
- [x] Two-phase interceptor correctly enforces `Offline`, `Defense`, and `Audit` modes.

---

## Phase 3: Inspection Contract & Upstream Integration

### Task 6: Abstract WAF Engine Contract & Passthrough Engine
**Description:** Define the `WAFEngine` interface in `pkg/engine` (`InspectRequest(ctx *RequestContext) (*Verdict, error)` and `InspectResponse(ctx *ResponseContext) (*Verdict, error)`). Implement a thread-safe `PassthroughEngine` and mock engine for testing, ensuring the proxy layer remains completely decoupled from threat detection details.

**Acceptance criteria:**
- [x] Define `RequestContext`, `ResponseContext`, `Verdict` (Action: Allow, Block, Challenge, Audit), and `WAFEngine` interface.
- [x] Implement `PassthroughEngine` that returns `VerdictAllow` with sub-microsecond latency.
- [x] Wire `WAFEngine` into `pkg/proxy/middleware.go`.

**Verification:**
- [x] Tests pass: `go test -v ./pkg/engine/...`
- [x] Build succeeds: `go build ./pkg/engine/...`

**Dependencies:** Task 2, Task 5
**Files likely touched:**
- `pkg/engine/types.go`
- `pkg/engine/engine.go`
- `pkg/engine/engine_test.go`
- `pkg/proxy/middleware.go`
**Estimated scope:** Small (3–4 files)

---

### Task 7: Upstream Reverse Proxy Configuration & Active Health Checks
**Description:** Configure backend routing integrating Caddy's native `reverseproxy.Handler`. Provide an example `Caddyfile` demonstrating multi-upstream load balancing (Weighted Round-Robin) with active health check probes.

**Acceptance criteria:**
- [x] Example `examples/Caddyfile` routes incoming traffic to mock upstream HTTP backends.
- [x] Configures active health check parameters (interval, path, status expect).
- [x] Verifies traffic evenly distributes across healthy backends and automatically evicts a failing backend.

**Verification:**
- [x] Tests pass: `go test -v ./pkg/proxy/upstream_test.go`
- [x] Manual check: Run `bin/raiwall run --config examples/Caddyfile` and curl against mock upstreams.

**Dependencies:** Task 3, Task 6
**Files likely touched:**
- `pkg/proxy/upstream.go`
- `pkg/proxy/upstream_test.go`
- `examples/Caddyfile`
**Estimated scope:** Medium (3 files)

---

## Phase 4: Verification & End-to-End Validation

### Task 8: End-to-End Proxy Integration Test Suite & Dockerfile
**Description:** Build an end-to-end integration test suite spinning up ephemeral HTTP/WebSocket test servers behind Raiwall. Write a multi-stage `Dockerfile` producing a minimal, secure production container image.

**Acceptance criteria:**
- [x] Integration test spins up Raiwall and proxies HTTP/1.1, HTTP/2, and WebSocket traffic to mock upstreams.
- [x] Validates dynamic run mode flipping (`Defense` -> `Offline` -> `Audit`) on live connections without dropping sockets.
- [x] Multi-stage `Dockerfile` (`golang:1.27-alpine` builder $\to$ `alpine:latest` runner) compiles Raiwall into $<50\text{ MB}$ image.

**Verification:**
- [x] Integration test passes: `go test -v -tags=integration ./tests/e2e/...`
- [x] Container build succeeds: `docker build -t raiwall:latest .`

**Dependencies:** Tasks 1–7
**Files likely touched:**
- `tests/e2e/proxy_test.go`
- `Dockerfile`
- `.dockerignore`
**Estimated scope:** Medium (3 files)

---

## Final Checkpoint: Milestone 1 Completion
- [x] All 8 tasks completed and verified with automated tests.
- [x] Standalone binary compiles cleanly with zero warnings.
- [x] Docker container runs and passes end-to-end reverse proxying and mode switching tests.
- [x] Ready to proceed to Milestone 2 (Domain 2: CGO libinjection & AST Semantic Threat Engine).
