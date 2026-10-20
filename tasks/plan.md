# Implementation Plan: Raiwall Major Update (SafeLine v9.4.2 Parity & Enterprise Architecture)

## Executive Summary

This plan outlines the architecture, component relationships, and delivery strategy for the **Raiwall Major Update**. The primary objective is establishing **100% functional, operational, and UX parity with Chaitin SafeLine WAF v9.4.2 Pro** (as documented in [`docs/`](file:///Users/macbook/Code/raiwall/docs/README.md) and [`docs/comparative-analysis-raiwall.md`](file:///Users/macbook/Code/raiwall/docs/comparative-analysis-raiwall.md)) while preserving Raiwall's core architectural advantages:
1. **Pure Go single-binary execution** ($< 50\text{ MB}$, zero CGO, zero Docker/Postgres/Redis dependencies required for standalone mode).
2. **Sub-microsecond threat evaluation** ($< 2\ \mu\text{s}$ lexical triage, sub-15 ns bytecode ACL, sub-15 ns BART CIDR lookups).
3. **Native HTTP/3 (QUIC) and automated ACME** via Caddy v2.
4. **Anti-CGNAT composite rate limiting** (`IP + JA4 + Cookie`).
5. **Integrated Model Context Protocol (MCP)** server for autonomous AI security operations.

---

## Architectural Comparison & Parity Target

```
Current Raiwall Scope (Tasks 1-72 Complete)
├── Reverse Proxy: Static Caddyfile pipeline, weighted round-robin, hot-reload ConfigSnapshot
├── Threat Detection: 3 AST categories (SQLi, CmdI, XSS) via TiDB, mvdan/sh, tdewolff
├── Access Control: expr bytecode ACLs (< 15 ns), BART CIDR (< 15 ns)
├── Rate Limiting: 3-tier composite rate limiter (IP + JA4 + Cookie), Waiting Room (HTTP 503)
├── Bot Defense: Altcha/Anubis stateless PoW (HTTP 468), JA4 fingerprinting
└── Control Plane: Huma v2 OpenAPI 3.1 REST API, SQLite WAL, Vue 3 WafCommandCenter monolith

SafeLine v9.4.2 Target Scope (Major Update: Tasks 73-96)
├── Navigation Shell: Persistent 8-domain sidebar, RouterView in App.vue, query-param router
├── Forensic Inspector: Dual tabs (EVENTS vs LOGS), cURL generator, encoding switcher (UTF-8/GBK)
├── Semantic Matrix: 14 detection modules with 4 modes (Disabled/Audit/Balance/Strict)
├── Virtual Patching: 193 CVE inner rules with fast path URI prefix indexing
├── Microservices Gateway: Dynamic UpstreamPool dispatching, sub-path prefix forwarding rules
├── Proxy Settings: Per-site XFF rewrite, HSTS, SSE streaming, Gzip/Brotli, IPv6
├── API Auto-Discovery: Transit path sampler cataloging shadow APIs into SQLite
├── Volumetric Defense: Active banned IP table with "UNBLOCK ALL" emergency release
├── Waiting Room: Path targeting, live queue telemetry metrics, deterministic HTTP 465
├── Identity Gateway: 5,000 user directory, 2FA TOTP, LDAP + GitHub IdP, HTTP 467 challenge
├── IP Groups: Enhanced Malicious Group (5,000 IPs), Search Spiders, BART integration
└── Custom Templates: Visual code editor for deterministic codes (403, 404, 429, 465, 466, 467, 468, 502, 504)
```

---

## Strategic Architectural Decisions

### 1. Two-Stage Threat Funnel with Fast-Path CVE Indexing
Clean traffic ($> 98\%$ of requests) must never incur the overhead of all 14 semantic parsers and 193 CVE signatures.
- **Stage 1 (Recursive Normalization)**: Decodes URL, HTML entities, and Base64 recursively.
- **Stage 2 (Lexical Triage)**: Evaluates input in $< 2\ \mu\text{s}$ using `libinjection-go` and token character frequency analysis. Benign requests bypass deep parsers entirely.
- **Fast-Path CVE Rule Indexing**: The 193 CVE rules are indexed into an in-memory map keyed by HTTP method and URI prefix (e.g. `/.git` rules only execute on paths starting with `/.git`; Log4j checks only run if candidate tokens contain `${`).
- **Hard Bounds**: Strict 32 KB per-parameter cap and 5 ms timeout per evaluation guarantee ReDoS immunity.

### 2. Dynamic Upstream Dispatching Inside Caddy Middleware
Currently, `middleware.go` passes requests to `next.ServeHTTP`. To support dynamic upstreams and path-prefix forwarding configured via the REST API without reloading Caddy:
- When an `AppConfig` specifies custom upstreams or forwarding rules, `middleware.go` evaluates longest prefix match.
- Matching requests are dispatched directly to the site's `UpstreamPool` using a pooled `httputil.ReverseProxy` with customized director and transport, bypassing static Caddy downstreams.

### 3. Deterministic Custom HTTP Status Codes
Raiwall adopts deterministic status codes across the entire gateway:
- `HTTP 403`: Attack Blocked (Semantic AST / CVE Rule)
- `HTTP 429`: Rate Limit Exceeded (Volumetric throttle)
- `HTTP 465`: Virtual Waiting Room Queue (Updated from HTTP 503)
- `HTTP 466`: Upstream Application Offline (All backends unhealthy)
- `HTTP 467`: Pre-Application Identity Authentication Challenge
- `HTTP 468`: Anti-Bot Stateless Proof-of-Work Challenge

### 4. Dual-Model SQLite Persistence (Production WAL + In-Memory Driver)
Every schema alteration in `pkg/control/db/schema.sql` must be accompanied by an update to `pkg/control/db/driver.go` (`control_sqlite`). This guarantees that both production SQLite WAL files and in-memory test drivers execute flawlessly.

### 5. Frontend Architecture Decoupling (Vertical Slicing)
The navigation shell (`DashboardLayout.vue`) and `SimpleRouter` query-string parser are placed in **Phase 1 (Tasks 73-74)**. This ensures all subsequent views (`SemanticsView`, `SiteDetailView`, `HttpFloodView`, `AuthGatewayView`, `BlockPagesView`) can be mounted, navigated to with query params, and tested immediately upon creation.

---

## Dependency Graph

```
Phase 1: Frontend Architecture Foundation & Router Modernization
   │ (Tasks 73, 74)
   ├──> Phase 2: Forensic Inspector & Incident Telemetry Upgrades (Tasks 75, 76, 77)
   │
   ├──> Phase 3: Semantic Detection Matrix & Enhanced Vulnerability Rules (Tasks 78, 79, 80, 81, 82)
   │
   ├──> Phase 4: Dynamic Proxying, Sub-Path Forwarding & API Auto-Discovery (Tasks 83, 84, 85, 86)
   │
   ├──> Phase 5: Volumetric Defense, Active Ban Registry & Virtual Waiting Room (Tasks 87, 88, 89)
   │
   ├──> Phase 6: Pre-Application Zero-Trust Identity Gateway (HTTP 467) (Tasks 90, 91, 92, 93)
   │
   └──> Phase 7: IP Groups, Deterministic Templates & Production Verification (Tasks 94, 95, 96)
```

---

## Phase Breakdown

### Phase 1: Frontend Architecture Foundation & Router Modernization (Tasks 73-74)
- **Task 73**: `SimpleRouter` Query-Param & Route Param Engine + `App.vue` RouterView Wiring (Size: M)
- **Task 74**: `DashboardLayout.vue` Shell Overhaul (SafeLine 8-Domain Navigation) (Size: M)
- *Checkpoint 1: Router query parameters and persistent sidebar navigation verified.*

### Phase 2: Forensic Inspector & Incident Telemetry Upgrades (Tasks 75-77)
- **Task 75**: Backend Incident Aggregation & Rich Parameter Location Telemetry (Size: M)
- **Task 76**: Reproducible cURL Command Generator API (Size: S)
- **Task 77**: Frontend Forensic Drawer & Incident-Level UX (Size: M)
- *Checkpoint 2: Incident aggregation, cURL reproduction, and dual-tab drawer verified.*

### Phase 3: Semantic Threat Detection Matrix & Enhanced Vulnerability Rules (Tasks 78-82)
- **Task 78**: 14-Module Semantic Matrix & Sensitivity Policy Engine (Size: M)
- **Task 79**: Code Injection & Deserialization Semantic Detectors (Java, PHP, ASP, SSTI) (Size: M)
- **Task 80**: Web & Network Flaw Semantic Detectors (File Upload, LFI/RFI, SSRF, CSRF, Mal HTTP) (Size: M)
- **Task 81**: Enhanced Virtual Patching CVE Engine (`inner_rules`, 193 CVEs) (Size: M)
- **Task 82**: Frontend Semantic Matrix & Inner Rules Management Views (Size: M)
- *Checkpoint 3: 14 semantic modules and 193 CVE rules verified blocking exploits.*

### Phase 4: Dynamic Proxying, Sub-Path Forwarding & API Auto-Discovery (Tasks 83-86)
- **Task 83**: Dynamic Upstream Proxying & Path-Prefix Forwarding in Caddy Middleware (Size: M)
- **Task 84**: Advanced Proxy Settings Matrix (XFF, HSTS, SSE, compression, IPv6, HTTP redirect) (Size: M)
- **Task 85**: Passive Runtime API Auto-Discovery & Shadow API Inventory Engine (Size: M)
- **Task 86**: Frontend Application Detail Overhaul (4-tab Site Detail UX) (Size: L)
- *Checkpoint 4: Sub-path routing, proxy settings matrix, and API inventory verified.*

### Phase 5: Volumetric Defense, Active Ban Registry & Virtual Waiting Room (Tasks 87-89)
- **Task 87**: Active Banned IP Registry & Emergency "Unblock All" API (Size: M)
- **Task 88**: Virtual Waiting Room Path Targeting, Telemetry Metrics & HTTP 465 Status Code (Size: M)
- **Task 89**: Frontend HTTP Flood & Waiting Room Console View (Size: M)
- *Checkpoint 5: Ban registry, unblock-all, and Waiting Room HTTP 465 verified.*

### Phase 6: Pre-Application Zero-Trust Identity Gateway (HTTP 467) (Tasks 90-93)
- **Task 90**: SQLite Identity User Directory (5,000 Accounts, RBAC, 2FA TOTP Cryptography) (Size: M)
- **Task 91**: External Identity Provider Connectors (LDAP & GitHub OAuth2) (Size: M)
- **Task 92**: Per-App HTTP 467 Auth Challenge Gate, API Bypass & Unified SSO Session Token (Size: M)
- **Task 93**: Frontend Auth Gateway Management Console (User Directory, SSO Portal, IdP Settings) (Size: M)
- *Checkpoint 6: User directory, 2FA TOTP, external IdPs, and HTTP 467 challenge verified.*

### Phase 7: IP Groups, Deterministic Templates & Production Verification (Tasks 94-96)
- **Task 94**: Named IP Groups Engine with BART Integration (Size: M)
- **Task 95**: Custom HTML/CSS Response Template Manager & Visual Code Editor (Size: M)
- **Task 96**: End-to-End Enterprise Integration Suite, Single Binary Build & Performance Benchmark (Size: M)
- *Final Checkpoint: Complete SafeLine parity verified with single-binary build < 50 MB.*

---

## Production Constraints & Risk Mitigations

| Risk | Severity | Constraint | Mitigation |
| :--- | :--- | :--- | :--- |
| **AST ReDoS / CPU Exhaustion** | High | Attacker crafts nested payloads causing CPU lockup | Hard 32 KB per-parameter cap + 5 ms parser timeout. Fallback to audit logging on timeout. |
| **Clean-Traffic Latency Inflation** | High | Evaluating 14 parsers and 193 CVEs on every request | Two-stage funnel: Stage 2 lexical triage (< 2 µs) filters 98%+ of traffic. CVE rules indexed by method + URI prefix. |
| **Dynamic Routing Memory Leaks** | Medium | Runtime route additions leaking `httputil.ReverseProxy` transports | Pool reverse proxy transports per site ID; clean up transports on site deletion. |
| **OOM on Waiting Room Flash Crowds** | High | 100,000 concurrent queued connections exhausting memory | Stateless cryptographic queue cookies (`rw_waiting_room_queue_id`) with HTTP 465 polling; SSE pool capped at 5,000 concurrent listeners. |
| **B2B / Mobile API Challenge Breakage** | Critical | Non-browser clients crashing on interactive HTTP 467/468 | Route classifier bypasses bot challenges for `Authorization: Bearer`, `/api/*`, and `Accept: application/json`. |
| **Single-Binary Bloat** | Medium | Embedded web assets and CVE rules exceeding 50 MB | Minified and gzip-compressed assets; rules stored in compressed JSON format. |
