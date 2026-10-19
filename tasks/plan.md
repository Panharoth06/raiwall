# Implementation Plan: Raiwall Domain 6 (Observability, Forensics & Real-Time Alerting)

## Overview
Implement **Domain 6: Observability, Forensics & Real-Time Alerting** for **Raiwall**: an enterprise-grade telemetry, forensics, real-time alerting, and live visual analytics engine.

Domain 6 delivers six integrated pillars:
1. **Zero-Latency In-Memory Async Ring Buffer (`pkg/telemetry/ring_buffer.go`):** Non-blocking push pipeline capturing forensic events (client IP, JA4 fingerprint, GeoIP, rule ID, action verdict, latency, headers, truncated payload) with zero allocations on hot paths. Features non-blocking buffer saturation handling with dropped-event telemetry and a background worker flushing batches every $500\text{ ms}$.
2. **Automated PII & PCI-DSS 4.0 Sanitizer (`pkg/telemetry/sanitizer.go`):** In-stream scrubber sanitizing sensitive headers (`Authorization`, `Cookie`, `X-Auth-*`), blacklisted parameter keys (`password`, `token`, `secret`, `cvv`, `card`, `api_key`), regex pattern scanners for credit card numbers (PCI-DSS) and bearer tokens, plus hard context truncation to $1\text{–}2\text{ KB}$ per event before persistence.
3. **Pluggable Dual-Tier Forensic Storage (`pkg/telemetry/storage.go`):** 
   - **Embedded / Homelab Mode (Default):** Zero-dependency pure-Go SQLite in WAL mode (`modernc.org/sqlite`) with optimized multi-column indexes and automated background retention pruning (age and size limits).
   - **Enterprise Scaled Mode:** Native columnar batch ingestion into ClickHouse (`github.com/ClickHouse/clickhouse-go/v2`) for multi-million record analytics with $10\times$ compression.
4. **Multi-Channel ChatOps Alerts (`pkg/telemetry/alert.go`):** Notification dispatcher using `containrrr/shoutrrr` supporting Slack, Discord, Telegram, Email, and generic webhooks with sliding-window debouncing and per-target/per-rule cooldowns (preventing alert fatigue during scans).
5. **Real-Time Live Inspector & Prometheus Metrics (`pkg/telemetry/streamer.go`, `metrics.go`):** High-throughput Server-Sent Events (SSE) broadcaster (`/.raiwall/api/events/stream`) with real-time query filtering, REST log search/aggregation APIs (`/.raiwall/api/events`), and standard Prometheus `/metrics` exporter.
6. **Embedded Vue 3 Admin Dashboard & Visualizer (`web/`):** Full migration of `web-draft` into `web/`, embedding `dist/` into the single Go binary via `go:embed` served at `/.raiwall/` with SPA history fallback, featuring real-time SSE Live Event Inspector, Apache ECharts QPS/threat analytics, and 3D Attack Globe (`globe.gl`) rendering geolocated threat origin arcs.

---

## Architecture Decisions

- **Non-Blocking Lock-Free Telemetry Ring Buffer:** Request handling in the Caddy data plane must never block on logging I/O. The ring buffer accepts events synchronously in $<1\text{ µs}$ and delegates disk/network flushing to a decoupled background worker. If buffer saturation occurs under extreme load, excess events are dropped with atomic counter increments exported to Prometheus (`raiwall_telemetry_dropped_total`).
- **Multi-Layer PII / PCI-DSS Sanitization:** Applied in-stream prior to disk persistence or network streaming. Sensitive headers and parameters are masked (`[REDACTED]`), credit card regexes scrub PANs, and raw payload context is clamped to $2\text{ KB}$ to prevent data leakage and memory bloat.
- **Pluggable `ForensicStore` Interface:** Abstract interface (`SaveBatch`, `Query`, `QueryAggregates`, `Prune`, `Close`) decoupling business logic from underlying storage engines. SQLite WAL is the zero-config embedded default; ClickHouse batch driver is activated when a ClickHouse DSN is provided.
- **Severity-Gated Alert Debouncing:** ChatOps alerts are gated by event severity (e.g. `block`, `ban`, high-risk AST threats) and governed by a sliding-window debouncer with per-rule/per-IP cooldowns (e.g., maximum 1 notification per target per 5 minutes) to avoid chat flooding.
- **SSE Live Streamer with REST Historical Query APIs:** Server-Sent Events (SSE) provide an HTTP/2-friendly, unidirectional live stream to connected browser clients with automatic browser reconnection. Complementary REST endpoints provide paginated historical search and aggregated stats for ECharts and the 3D Globe.
- **Frontend Migration and Single Binary Embedding:** Migrate the draft Vue 3 codebase from `web-draft/` to `web/`, add ECharts, Globe.gl, and Live Inspector components, build production assets to `web/dist/`, and embed them into the Go binary via `go:embed` mounted at `/.raiwall/`.
- **Dedicated Internal Route Namespace:** Management routes (`/.raiwall/` UI, `/.raiwall/api/...` APIs, `/.raiwall/metrics`) are handled internally without interfering with upstream reverse proxying.

---

## Dependency Graph

```
Forensic Event Model & PII Sanitizer (pkg/telemetry/event.go, sanitizer.go)
   │
   ├── Ring Buffer & Flush Worker (pkg/telemetry/ring_buffer.go)
   │       │
   │       ├── ForensicStore Interface & SQLite WAL Driver (pkg/telemetry/sqlite.go)
   │       │       │
   │       │       └── ClickHouse Batch Driver (pkg/telemetry/clickhouse.go)
   │       │
   │       ├── Shoutrrr Alert Dispatcher & Debouncer (pkg/telemetry/alert.go, debouncer.go)
   │       │
   │       └── Prometheus Metrics Exporter (pkg/telemetry/metrics.go)
   │
   ├── SSE Streamer & REST Analytics APIs (pkg/telemetry/streamer.go, api.go)
   │       │
   │       └── Caddy Middleware Pipeline & 'telemetry' Directive (pkg/proxy/middleware.go, caddyfile.go)
   │               │
   │               └── Frontend Migration & UI Embedding (web/ -> pkg/proxy/ui.go)
   │                       │
   │                       ├── Live Inspector & 1-Click Exception (web/src/components/LiveInspector.vue)
   │                       │
   │                       ├── ECharts Analytics & 3D Attack Globe (web/src/components/ThreatAnalytics.vue, AttackGlobe.vue)
   │                       │
   │                       └── End-to-End Integration & High-QPS Benchmarks
```

---

## Task List Index

Tasks are tracked in `tasks/todo.md`:

### Phase 1: Telemetry Data Model, PII/PCI-DSS Sanitizer & High-Throughput Ring Buffer
- [ ] **Task 46: Forensic Event Model & Multi-Layer PII/PCI-DSS Sanitizer** (Size: M)
- [ ] **Task 47: Zero-Latency Non-Blocking In-Memory Ring Buffer & Flush Worker** (Size: S)
- [ ] *Checkpoint: Core forensic event model, PII sanitization, and lock-free ring buffer pass all unit and race tests.*

### Phase 2: Dual-Tier Forensic Storage (SQLite WAL & ClickHouse)
- [ ] **Task 48: Pluggable ForensicStore Interface & Pure-Go SQLite WAL Implementation** (Size: M)
- [ ] **Task 49: Enterprise Scaled ClickHouse Batch Storage Driver** (Size: M)
- [ ] *Checkpoint: Both SQLite WAL and ClickHouse forensic stores ingest batches, query filtered logs, and prune expired records.*

### Phase 3: Real-Time Alerting (`containrrr/shoutrrr`) & Prometheus Metrics
- [ ] **Task 50: Multi-Channel Alert Engine with Sliding-Window Debouncing & Rate Limiting** (Size: M)
- [ ] **Task 51: Prometheus Metrics Exporter & Data Plane Instrumentation** (Size: S)
- [ ] *Checkpoint: Alerts dispatch safely without chat spam, and Prometheus exposes accurate WAF telemetry.*

### Phase 4: Real-Time SSE Event Streamer, REST Query APIs & Caddy Middleware Integration
- [ ] **Task 52: Server-Sent Events (SSE) Live Streamer & Forensic Query REST Endpoints** (Size: M)
- [ ] **Task 53: Caddyfile Directive Parsing (`telemetry`) & Pipeline Telemetry Interception** (Size: M)
- [ ] *Checkpoint: End-to-end telemetry flows from Caddy middleware through ring buffer to SQLite storage, SSE streamer, and alert dispatcher.*

### Phase 5: Frontend Migration (`web/`), Live Inspector & Dashboard Visualizations
- [ ] **Task 54: Frontend Project Migration (`web-draft` -> `web`) & Embedding Infrastructure** (Size: M)
- [ ] **Task 55: Real-Time Live Inspector Table & SSE Composable** (Size: M)
- [ ] **Task 56: Apache ECharts Analytics Dashboards & 3D Threat Globe (`globe.gl`)** (Size: M)
- [ ] *Checkpoint: Complete web dashboard builds cleanly, runs live SSE streaming, and renders ECharts & 3D Globe.*

### Phase 6: End-to-End Integration, Micro-benchmarks & Verification
- [ ] **Task 57: Domain 6 End-to-End Telemetry Integration Tests & High-QPS Micro-benchmarks** (Size: M)
- [ ] *Checkpoint: Milestone 6 complete, all tests passing with `-race`, UI and data plane fully integrated in single binary.*

---

## Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **Ring Buffer Saturated Under DDoS** | **High** | Non-blocking ring buffer drops excess events when saturated and atomically records dropped count in Prometheus (`raiwall_telemetry_dropped_total`), ensuring proxy request latency is never impacted. |
| **PII / PCI-DSS Sensitive Data Leakage** | **Critical** | Multi-layer sanitization applied before event reaches ring buffer or storage. Header redaction, key name matching, credit card regex patterns, and context truncation to $2\text{ KB}$. |
| **SQLite WAL Lock Contention on Heavy Writes** | **Medium** | Batch transactions ($500\text{ ms}$ buffer flushes) to minimize commit frequency. WAL mode permits concurrent reads while batch writes are in progress. Pragmas tuned (`busy_timeout=5000`, `synchronous=NORMAL`). |
| **ChatOps Alert Flooding (Alert Fatigue)** | **High** | Sliding-window debouncer with per-rule and per-IP cooldown periods (e.g. 5 minutes). Burst alerts grouped into summary notifications. |
| **High Memory / CPU on 3D Attack Globe** | **Medium** | Throttle WebGL rendering when tab is hidden. Cap maximum concurrent arc particles rendered on the globe. |
| **Single Binary Size Inflation (>50 MB)** | **Medium** | Tree-shake frontend assets during Vite build, compress static assets with gzip/brotli, and verify binary size in CI. |

---

## Open Questions & Future Enhancements
- **1-Click Create Exception from UI:** The Live Inspector provides a "Create Exception" button that opens a pre-filled dialog with the exact Host, Path, Method, Location, and ParamName from the forensic record to suppress false positives instantly.
- **Dynamic Cluster Threat Sync (Domain 7):** Real-time forensic telemetry aggregation across multi-node clusters using Redis Pub/Sub or Kafka.
