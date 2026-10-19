# Tasks: Raiwall Domain 6 (Observability, Forensics & Real-Time Alerting)

## Completed Milestones
- [x] **Milestone 1: Domain 1 (Reverse Proxy & Gateway)** — Tasks 1 through 8 completed and verified.
- [x] **Milestone 2: Domain 2 (Semantic Threat Detection Engine)** — Tasks 9 through 17 completed and verified.
- [x] **Milestone 3: Domain 3 (Bot Mitigation & Active Defense)** — Tasks 18 through 27 completed and verified.
- [x] **Milestone 4: Domain 4 (DDoS, HTTP Flood & Rate Limiting)** — Tasks 28 through 36 completed and verified.
- [x] **Milestone 5: Domain 5 (Access Control & Zero-Trust Identity Gateway)** — Tasks 37 through 45 completed and verified.

---

## Phase 1: Telemetry Data Model, PII/PCI-DSS Sanitizer & High-Throughput Ring Buffer

### Task 46: Forensic Event Model & Multi-Layer PII/PCI-DSS Sanitizer
**Description:** Implement `pkg/telemetry/event.go`, `pkg/telemetry/sanitizer.go`, and test suite in `pkg/telemetry/sanitizer_test.go`. Define the canonical `ForensicEvent` structure capturing complete request metadata (`EventID`, `Timestamp`, `Host`, `Path`, `Method`, `ClientIP`, `JA4`, `GeoData`, `RuleID`, `Action`, `Severity`, `Headers`, `TruncatedPayload`, `Latency`, `StatusCode`). Implement an in-stream multi-layer sanitizer that redacts sensitive headers (`Authorization`, `Cookie`, `X-Auth-*`), blacklisted parameter keys (`password`, `token`, `secret`, `cvv`, `card`, `api_key`), applies regex scanning for 16-digit credit card numbers (PCI-DSS 4.0) and bearer tokens, and truncates raw payload snippets to $2\text{ KB}$.

**Acceptance criteria:**
- [ ] Define `ForensicEvent` struct with complete JSON tags and serialization helpers.
- [ ] Implement `Sanitize(event *ForensicEvent)` redacting sensitive headers and replacing sensitive key values with `[REDACTED]`.
- [ ] Scrub PCI-DSS credit card PANs and JWT/Bearer tokens in request bodies and query strings via regex pattern matching.
- [ ] Enforce hard context truncation cap of $2\text{ KB}$ on raw payload snippets to prevent memory bloat.
- [ ] Unit tests cover header redaction, query/body parameter scrubbing, card number patterns, and context truncation.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/telemetry/event.go`
- `pkg/telemetry/sanitizer.go`
- `pkg/telemetry/sanitizer_test.go`
**Estimated scope:** Medium (3 files)

---

### Task 47: Zero-Latency Non-Blocking In-Memory Ring Buffer & Flush Worker
**Description:** Implement `pkg/telemetry/ring_buffer.go` and `pkg/telemetry/ring_buffer_test.go`. Build a fixed-capacity, non-blocking ring buffer that receives `ForensicEvent` pointers with zero request thread blocking. If the ring buffer fills to capacity under heavy traffic, excess events are safely dropped while atomically incrementing a dropped-event counter. Implement a background worker that flushes batches to a configured sink every $500\text{ ms}$ or whenever a batch size threshold is reached.

**Acceptance criteria:**
- [ ] Implement non-blocking ring buffer with configurable capacity (default 10,000 events).
- [ ] Ingestion overhead $<1\text{ µs}$ per event on the hot path without mutex lock contention.
- [ ] Safe saturation policy: drop excess events and atomically record dropped count for Prometheus metrics.
- [ ] Background worker triggers batch flush at $500\text{ ms}$ intervals or when batch limit (e.g., 500 events) is met.
- [ ] Clean shutdown support draining remaining events before exit.
- [ ] Concurrent tests verify thread safety and race freedom under high QPS (`go test -race`).

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Benchmarks pass: `go test -bench=BenchmarkRingBuffer ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** Task 46
**Files likely touched:**
- `pkg/telemetry/ring_buffer.go`
- `pkg/telemetry/ring_buffer_test.go`
**Estimated scope:** Small (2 files)

---

## Checkpoint: Telemetry Ingestion & Sanitization
- [ ] Canonical `ForensicEvent` records all threat attributes without sensitive PII or raw secrets.
- [ ] Ring buffer delivers sub-microsecond non-blocking ingestion and timed batch flushing.
- [ ] Unit and benchmark tests pass cleanly with `-race`.

---

## Phase 2: Dual-Tier Forensic Storage (SQLite WAL & ClickHouse)

### Task 48: Pluggable ForensicStore Interface & Pure-Go SQLite WAL Implementation
**Description:** Implement `pkg/telemetry/storage.go`, `pkg/telemetry/sqlite.go`, and `pkg/telemetry/sqlite_test.go`. Define the `ForensicStore` interface (`SaveBatch`, `Query`, `QueryAggregates`, `Prune`, `Close`). Implement the default embedded SQLite driver using pure-Go `modernc.org/sqlite` in WAL mode (`PRAGMA journal_mode=WAL; PRAGMA synchronous=NORMAL;`). Create an optimized schema with composite indexes on `timestamp`, `client_ip`, `action`, and `rule_id`. Implement an automatic background retention pruning worker that deletes records exceeding max age (e.g., 30 days) or database size limit.

**Acceptance criteria:**
- [ ] Define abstract `ForensicStore` interface and `QueryParams` struct.
- [ ] Implement `SQLiteStore` with automatic table creation and composite indexing.
- [ ] Implement batch insert (`SaveBatch`) utilizing single-transaction prepared statements.
- [ ] Implement `Query` supporting filtering by time range, client IP, action, rule ID, and country code with pagination (`limit`, `offset`).
- [ ] Implement `QueryAggregates` returning time-bucketed counts (QPS, block ratio, top attacking countries, top rules).
- [ ] Automatic retention pruning cleans records older than configured TTL (e.g. 30 days).
- [ ] Unit tests verify batch insertion, filtered queries, pagination, aggregations, and pruning.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** Task 46, Task 47
**Files likely touched:**
- `pkg/telemetry/storage.go`
- `pkg/telemetry/sqlite.go`
- `pkg/telemetry/sqlite_test.go`
**Estimated scope:** Medium (3 files)

---

### Task 49: Enterprise Scaled ClickHouse Batch Storage Driver
**Description:** Implement `pkg/telemetry/clickhouse.go` and `pkg/telemetry/clickhouse_test.go`. Provide the enterprise columnar store driver implementing `ForensicStore` using `github.com/ClickHouse/clickhouse-go/v2`. Implement automated schema migration creating the `MergeTree` forensic events table partitioned by day with ZSTD compression. Implement high-throughput batch insertion, query pagination, and aggregation queries optimized for ClickHouse columnar layout.

**Acceptance criteria:**
- [ ] Implement `ClickHouseStore` adhering to the `ForensicStore` interface.
- [ ] Define ClickHouse table schema (`raiwall_forensic_events`) using `MergeTree()` ordered by `(timestamp, action, rule_id, client_ip)`.
- [ ] Implement high-performance batch insertion utilizing native protocol batching.
- [ ] Implement filtered queries and time-series aggregation queries.
- [ ] Handle connection loss gracefully with reconnect retries and error logging.
- [ ] Unit and mock tests verify query building, batch serialization, and schema definition.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** Task 48
**Files likely touched:**
- `pkg/telemetry/clickhouse.go`
- `pkg/telemetry/clickhouse_test.go`
**Estimated scope:** Medium (2 files)

---

## Checkpoint: Pluggable Forensic Storage
- [ ] `ForensicStore` provides consistent CRUD and analytics abstraction.
- [ ] SQLite WAL driver persists events with low write contention and automatic retention pruning.
- [ ] ClickHouse driver is ready for high-throughput enterprise batch archiving.
- [ ] All storage unit tests pass with `-race`.

---

## Phase 3: Real-Time Alerting (`containrrr/shoutrrr`) & Prometheus Metrics

### Task 50: Multi-Channel Alert Engine with Sliding-Window Debouncing & Rate Limiting
**Description:** Implement `pkg/telemetry/alert.go`, `pkg/telemetry/debouncer.go`, and test suite in `pkg/telemetry/alert_test.go`. Integrate `github.com/containrrr/shoutrrr` for push notifications across Slack, Discord, Telegram, Webhook, and Email. Implement a sliding-window debouncer and rate limiter to prevent alert fatigue: only send alerts for designated severities (`block`, `ban`, critical AST breakouts) with a per-rule and per-IP cooldown window (e.g. max 1 alert per target per 5 minutes) and group burst incidents into summary notifications.

**Acceptance criteria:**
- [ ] Integrate `containrrr/shoutrrr` to dispatch rich formatted incident alerts.
- [ ] Implement `AlertDebouncer` with sliding-window cache tracking recent alert keys (`IP + RuleID`).
- [ ] Enforce configurable cooldown period (e.g., 5 minutes) suppressing duplicate alerts for the same source.
- [ ] Format alerts with concise incident context (Timestamp, Client IP, GeoIP, Path, Threat Type, Action taken).
- [ ] Unit tests verify alert filtering, debouncing window suppression, and multi-channel URL parsing.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** Task 46
**Files likely touched:**
- `pkg/telemetry/alert.go`
- `pkg/telemetry/debouncer.go`
- `pkg/telemetry/alert_test.go`
**Estimated scope:** Medium (3 files)

---

### Task 51: Prometheus Metrics Exporter & Data Plane Instrumentation
**Description:** Implement `pkg/telemetry/metrics.go` and `pkg/telemetry/metrics_test.go`. Expose standard Prometheus metrics using `github.com/prometheus/client_golang` (`raiwall_requests_total`, `raiwall_blocked_total{reason, rule_id}`, `raiwall_request_duration_seconds`, `raiwall_telemetry_dropped_total`, `raiwall_active_connections`, `raiwall_banned_ips_total`). Provide an HTTP handler mounting `/metrics` on the internal management route.

**Acceptance criteria:**
- [ ] Register Prometheus counters, gauges, and histograms for all core WAF and gateway metrics.
- [ ] Instrument telemetry ring buffer to record dropped event count on saturation.
- [ ] Expose standard `/metrics` endpoint compatible with Prometheus and VictoriaMetrics scrapers.
- [ ] Unit tests verify metric incrementing, label correctness, and HTTP handler response.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** Task 46, Task 47
**Files likely touched:**
- `pkg/telemetry/metrics.go`
- `pkg/telemetry/metrics_test.go`
**Estimated scope:** Small (2 files)

---

## Checkpoint: Real-Time Alerts & Metrics
- [ ] Multi-channel notifications dispatch to Slack, Telegram, Discord, and Webhooks without alert fatigue.
- [ ] Prometheus metrics accurately track traffic volume, blocked threats, and ring buffer health.
- [ ] Tests pass cleanly with `-race`.

---

## Phase 4: Real-Time SSE Event Streamer, REST Query APIs & Caddy Middleware Integration

### Task 52: Server-Sent Events (SSE) Live Streamer & Forensic Query REST Endpoints
**Description:** Implement `pkg/telemetry/streamer.go`, `pkg/telemetry/api.go`, and `pkg/telemetry/api_test.go`. Build an HTTP Server-Sent Events (SSE) broadcaster streaming live `ForensicEvent` instances to connected browser clients (`/.raiwall/api/events/stream`) with real-time query parameter filtering (`?action=block&country=CN&min_severity=high`). Implement REST endpoints for paginated log queries (`GET /.raiwall/api/events`) and time-series / geographical aggregations (`GET /.raiwall/api/events/stats`).

**Acceptance criteria:**
- [ ] Implement SSE broadcaster supporting multiple concurrent browser subscribers with non-blocking fan-out.
- [ ] Support query filters on SSE stream (`action`, `rule_id`, `country`, `min_severity`).
- [ ] Implement REST endpoint `GET /.raiwall/api/events` returning paginated, filtered JSON logs.
- [ ] Implement REST endpoint `GET /.raiwall/api/events/stats` returning aggregated metrics for ECharts and 3D globe.
- [ ] Unit tests verify SSE connection management, broadcast delivery, subscriber disconnects, and REST API serialization.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/telemetry/...`
- [ ] Build succeeds: `go build ./pkg/telemetry/...`

**Dependencies:** Task 46, Task 47, Task 48
**Files likely touched:**
- `pkg/telemetry/streamer.go`
- `pkg/telemetry/api.go`
- `pkg/telemetry/api_test.go`
**Estimated scope:** Medium (3 files)

---

### Task 53: Caddyfile Directive Parsing (`telemetry`) & Pipeline Telemetry Interception
**Description:** Wire the telemetry pipeline into `pkg/proxy/middleware.go`, parse nested `telemetry { ... }` blocks in `pkg/proxy/caddyfile.go`, and update `examples/Caddyfile`. Ingest every inspected request into the ring buffer with verdict, matched rule ID, latency, and client metadata. Route internal paths (`/.raiwall/api/...` and `/.raiwall/metrics`) directly to telemetry handlers without upstream proxying.

**Acceptance criteria:**
- [ ] Capture request verdict, rule ID, latency, headers, and metadata in `ServeHTTP` and push to ring buffer.
- [ ] Parse nested `telemetry` Caddyfile block:
  - `telemetry { storage sqlite <path>; flush_interval 500ms; buffer_size 10000; retention 30d; alert <channel> <url> { events ...; cooldown 5m; } }`
- [ ] Intercept `/.raiwall/api/*` and `/.raiwall/metrics` routes internally.
- [ ] Update `examples/Caddyfile` showcasing complete Domain 6 telemetry and alerting configuration.
- [ ] Unit tests verify Caddyfile unmarshaling and telemetry pipeline lifecycle.

**Verification:**
- [ ] Tests pass: `go test -v -race ./pkg/proxy/...`
- [ ] Build succeeds: `go build ./cmd/raiwall`

**Dependencies:** Tasks 46–52
**Files likely touched:**
- `pkg/proxy/middleware.go`
- `pkg/proxy/caddyfile.go`
- `pkg/proxy/caddyfile_test.go`
- `examples/Caddyfile`
**Estimated scope:** Medium (4 files)

---

## Checkpoint: Data Plane Telemetry Interception
- [ ] Every request processed by Caddy WAF pushes sanitized telemetry to the async ring buffer.
- [ ] SSE streamer broadcasts live events to connected browser sessions.
- [ ] Caddyfile cleanly configures storage, flushing intervals, and alerting channels.

---

## Phase 5: Frontend Migration (`web/`), Live Inspector & Dashboard Visualizations

### Task 54: Frontend Project Migration (`web-draft` -> `web`) & Embedding Infrastructure
**Description:** Migrate the Vue 3 + TypeScript codebase from `web-draft/` to `web/` per project conventions. Install required visualization libraries (`echarts`, `vue-echarts`, `globe.gl`, `three`). Configure production Vite build to output to `web/dist/`. Implement `pkg/proxy/ui.go` to embed `web/dist` assets into the Go binary via `go:embed` and serve them under `/.raiwall/` with SPA HTML5 history fallback.

**Acceptance criteria:**
- [ ] Copy and configure Vue 3 project cleanly into `web/` directory.
- [ ] Add `echarts`, `globe.gl`, and `three` to `web/package.json` dependencies.
- [ ] Configure `vite.config.ts` with base path `/.raiwall/` and output directory `dist`.
- [ ] Embed `web/dist` in Go binary using `go:embed` in `pkg/proxy/ui.go`.
- [ ] Serve SPA assets under `/.raiwall/` with fallback to `index.html` for unknown subpaths.
- [ ] Frontend builds cleanly with `pnpm build` or `npm run build`.

**Verification:**
- [ ] Frontend build succeeds: `cd web && pnpm build`
- [ ] Go build succeeds with embedded assets: `go build ./cmd/raiwall`

**Dependencies:** Task 53
**Files likely touched:**
- `web/package.json`
- `web/vite.config.ts`
- `pkg/proxy/ui.go`
- `pkg/proxy/middleware.go`
**Estimated scope:** Medium (4 files)

---

### Task 55: Real-Time Live Inspector Table & SSE Composable
**Description:** Implement `web/src/composables/useEventStream.ts`, `web/src/components/LiveInspector.vue`, and unit test in `web/src/components/__tests__/LiveInspector.spec.ts`. Build the live streaming event inspector connecting to `/.raiwall/api/events/stream` via SSE with pause/resume controls, instant search/filtering (by client IP, rule ID, HTTP method, country), expandable JSON modal showing sanitized request details, and a 1-click "Create Exception" action that pre-fills exception dialogs.

**Acceptance criteria:**
- [ ] Implement `useEventStream` composable handling SSE connection lifecycle, auto-reconnect, and message buffering.
- [ ] Build `LiveInspector.vue` table displaying live events with colored action badges (`allow`, `block`, `challenge`, `ban`).
- [ ] Support pause/resume streaming, clear table, and local search filtering.
- [ ] Modal displays full sanitized forensic context (headers, payload snippet, JA4, rule ID).
- [ ] 1-Click "Create Exception" button emits event with Host, Path, Method, Location, and ParamName.
- [ ] Vitest unit tests verify SSE state handling and table rendering.

**Verification:**
- [ ] Frontend tests pass: `cd web && pnpm test`
- [ ] Manual check: open `/.raiwall/` and verify live events stream smoothly.

**Dependencies:** Task 54, Task 52
**Files likely touched:**
- `web/src/composables/useEventStream.ts`
- `web/src/components/LiveInspector.vue`
- `web/src/components/__tests__/LiveInspector.spec.ts`
**Estimated scope:** Medium (3 files)

---

### Task 56: Apache ECharts Analytics Dashboards & 3D Threat Globe (`globe.gl`)
**Description:** Implement `web/src/components/ThreatAnalytics.vue`, `web/src/components/AttackGlobe.vue`, and tests. Build reactive ECharts dashboards displaying real-time QPS, blocked threat distribution by category (SQLi, XSS, CmdI, Rate Limit, ACL), and top attacking IP/ASNs. Integrate `globe.gl` (Three.js) to render a 3D WebGL globe visualizing geolocated threat origin coordinates and animated attack arcs converging on protected gateway locations.

**Acceptance criteria:**
- [ ] Build `ThreatAnalytics.vue` using Apache ECharts with dark-mode theme matching Raiwall UI.
- [ ] Render real-time time-series charts (QPS and Blocked requests) updating from live SSE and REST stats.
- [ ] Build `AttackGlobe.vue` using `globe.gl` rendering interactive 3D globe with country borders and attack arcs.
- [ ] Throttle WebGL animation when container or browser tab is hidden to conserve GPU/CPU.
- [ ] Vitest component tests verify component mounting and props reactivity.

**Verification:**
- [ ] Frontend tests pass: `cd web && pnpm test`
- [ ] Frontend build succeeds: `cd web && pnpm build`

**Dependencies:** Task 54, Task 55
**Files likely touched:**
- `web/src/components/ThreatAnalytics.vue`
- `web/src/components/AttackGlobe.vue`
- `web/src/components/__tests__/ThreatAnalytics.spec.ts`
**Estimated scope:** Medium (3 files)

---

## Checkpoint: Frontend Visualizations & Single Binary
- [ ] Vue admin dashboard (`web/`) builds cleanly and embeds in the single Go binary.
- [ ] Live Inspector table renders real-time forensic events via SSE.
- [ ] ECharts analytics and 3D Attack Globe render geolocated threats smoothly.

---

## Phase 6: End-to-End Integration, Micro-benchmarks & Verification

### Task 57: Domain 6 End-to-End Telemetry Integration Tests & High-QPS Micro-benchmarks
**Description:** Implement `tests/e2e/telemetry_test.go` and `pkg/telemetry/benchmark_test.go`. Validate complete observability pipeline: HTTP request through Caddy WAF -> non-blocking ring buffer push -> PII sanitization -> SQLite WAL insertion -> SSE stream broadcast -> Shoutrrr alert debouncing. Benchmark ring buffer ingestion and query performance under concurrent load with `-race`, verifying binary size remains $<50\text{ MB}$.

**Acceptance criteria:**
- [ ] End-to-end integration tests verify:
  - WAF blocked attack produces sanitized record in SQLite WAL database.
  - Sensitive headers (`Authorization`, `Cookie`) and passwords are scrubbed in database.
  - SSE client receives live broadcast event within $500\text{ ms}$.
  - Shoutrrr debouncer suppresses duplicate alerts within cooldown window.
  - Prometheus `/metrics` increments blocked counters and tracks latency.
  - Embedded UI is accessible at `/.raiwall/` returning status 200 and index HTML.
- [ ] Benchmarks verify sub-microsecond ring buffer ingestion ($<1\text{ µs}$) with zero data plane blocking.
- [ ] Zero race conditions under high concurrent requests (`go test -race`).
- [ ] Single binary builds cleanly under 50 MB (`make build`).

**Verification:**
- [ ] Integration tests pass: `go test -v -race -tags=integration ./tests/e2e/...`
- [ ] Benchmarks pass: `go test -bench=. ./pkg/telemetry/...`
- [ ] Build succeeds: `make build`

**Dependencies:** Tasks 46–56
**Files likely touched:**
- `tests/e2e/telemetry_test.go`
- `pkg/telemetry/benchmark_test.go`
- `Makefile`
**Estimated scope:** Medium (3 files)

---

## Final Checkpoint: Milestone 6 (Domain 6) Completion
- [ ] All 12 tasks (Tasks 46–57) implemented and verified.
- [ ] Zero-latency async ring buffer and automated PII/PCI-DSS sanitizer active.
- [ ] Dual-tier storage (SQLite WAL default + ClickHouse driver) fully operational.
- [ ] Shoutrrr multi-channel alerting with sliding-window debouncing active.
- [ ] SSE Live Streamer and Prometheus metrics integrated into Caddy pipeline.
- [ ] Vue 3 dashboard migrated to `web/` with Live Inspector, ECharts, and 3D Attack Globe.
- [ ] Production web assets embedded via `go:embed` into single binary under 50MB.
- [ ] All unit, integration, and benchmark tests pass with `-race`.
