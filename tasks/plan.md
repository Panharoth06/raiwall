# Implementation Plan: Raiwall Domain 1 (Reverse Proxy & Gateway)

## Overview
Build the foundational Data Plane for **Raiwall**: an enterprise-grade, high-performance reverse proxy and WAF gateway embedded as an official Caddy v2 module. This data plane provides multi-protocol reverse proxying (HTTP/1.1, HTTP/2, HTTP/3, WebSockets, gRPC), automated SSL/TLS via CertMagic, zero-latency in-memory configuration updates via `atomic.Pointer[ConfigSnapshot]`, a two-phase request/response interception hook, real client IP extraction, and upstream health-checked load balancing.

## Architecture Decisions
- **Embedded Caddy v2 Module:** Implemented as a native Caddy HTTP handler (`caddyhttp.MiddlewareHandler`) compiled directly into a single standalone binary (`cmd/raiwall/main.go`).
- **Hybrid Configuration:** Supports both declarative Caddyfile syntax (`raiwall` directive) for homelab/GitOps, and programmatic dynamic in-memory configuration (`atomic.Pointer[ConfigSnapshot]`) for UI/API synchronization.
- **Two-Phase Interceptor:** Intercepts incoming requests prior to upstream proxying (`BeforeRequest` verdict: Defense block, Audit log, or Offline maintenance screen) and wraps the `http.ResponseWriter` post-proxy to capture upstream 403/404 error codes (for Domain 4 Scanner Trap) and sanitize server headers.
- **Zero-Allocation Buffer Pooling:** Implements `sync.Pool` byte-buffer pooling and selective payload streaming ($>1\text{ MB}$ streams directly to upstream) to avoid Go GC latency under high QPS.
- **Decoupled Engine Contract:** The proxy delegates inspection to an abstract `pkg/engine.WAFEngine` interface, making the threat detection pipeline independent of the proxy layer (enabling future Envoy `ext_proc` sidecar export).

## Task List Index
Tasks are tracked in `tasks/todo.md`:
- **Phase 1: Project Scaffolding & Build Pipeline**
  - [x] Task 1: Workspace Initialization & Build Tooling (Size: S)
  - [x] Task 2: Core Configuration Snapshot & Run Modes (Size: S)
  - *Checkpoint: Foundation passes tests and builds cleanly.*
- **Phase 2: Core Reverse Proxy & WAF Middleware**
  - [x] Task 3: Caddy WAF Middleware Registration & Caddyfile Directive (Size: M)
  - [x] Task 4: Real Client IP & Header Extraction (Size: S)
  - [x] Task 5: Two-Phase Request & Response Interceptor (Size: M)
  - *Checkpoint: Caddy middleware intercepts HTTP pipeline and handles run modes.*
- **Phase 3: Inspection Contract & Upstream Integration**
  - [x] Task 6: Abstract WAF Engine Contract & Passthrough Engine (Size: S)
  - [x] Task 7: Upstream Reverse Proxy Configuration & Active Health Checks (Size: M)
  - *Checkpoint: Upstream routing, load balancing, and health checks operational.*
- **Phase 4: Verification & End-to-End Validation**
  - [x] Task 8: End-to-End Proxy Integration Test Suite & Dockerfile (Size: M)
  - *Checkpoint: Complete end-to-end integration test passes.*

## Risks and Mitigations
| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **Go GC Latency under High Concurrency** | **High** | Use `sync.Pool` for byte buffers and selective streaming for bodies $>1\text{ MB}$. |
| **Caddy Module API Breaking Changes** | **Medium** | Pin exact Caddy v2 minor version in `go.mod` (v2.8.4+). |
| **Incomplete Client IP Extraction behind CDNs** | **Medium** | Support multiple header priority fallbacks (`CF-Connecting-IP`, `X-Forwarded-For`, `X-Real-IP`, and `PROXY` protocol). |
| **Upstream WebSocket & SSE Connection Severing** | **Medium** | Implement graceful connection draining on configuration reloads without abruptly terminating open sockets. |

## Open Questions & Future Work
- *Domain 2 Hand-off:* Next milestone will implement native C `libinjection` (CGO FFI) and bounded AST context verification inside `pkg/engine`.
