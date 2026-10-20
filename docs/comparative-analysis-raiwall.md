# Comparative Architecture Analysis: SafeLine WAF vs. Raiwall

> A strategic architectural and user-experience comparison between **Chaitin SafeLine WAF v9.4.2** and **Raiwall** (Go + Caddy v2 + Vue 3).

---

## 1. Executive Comparison Matrix

| Architectural Dimension | Chaitin SafeLine WAF (v9.4.2 Pro) | Raiwall Architecture (`AGENTS.md`) | Strategic Takeaway / Alignment |
| :--- | :--- | :--- | :--- |
| **Data Plane Core** | NGINX core with proprietary C/C++ inspection plugins (`safeline-detector`) | **Caddy v2** (`caddyserver/caddy/v2` v2.8.4) written in pure **Go 1.27+** with Strict Hexagonal Architecture (`internal/core`, `internal/adapters`) | Caddy provides native HTTP/3 (QUIC), zero-downtime hot reloads via `atomic.Pointer`, automated CertMagic ACME, and zero CGO dependencies. |
| **Control Plane Core** | Proprietary backend daemon with embedded SQLite & Cloud license check | **Huma v2** REST API (`danielgtaylor/huma/v2`) with OpenAPI 3.1 + pure Go **SQLite WAL** (`modernc.org/sqlite` + `sqlc`) | Raiwall provides an open, standard OpenAPI 3.1 schema natively consumable by external SDKs and automation. |
| **Admin Dashboard** | React 18 + Material-UI (MUI) + Vite + ECharts | **Vue 3** + **TypeScript** + **shadcn-vue** (Tailwind CSS) + Pinia + ECharts + **Globe.gl** | Modern, accessible, lightweight frontend embedded into the Go binary via `go:embed`. |
| **Threat Detection Engine** | Proprietary Semantic Analysis (14 modules) + 193 CVE inner rules | **Three-stage funnel**: Coraza recursive normalizer → pure-Go `libinjection-go` (< 2 µs) → bounded AST context verifiers (TiDB, mvdan/sh, tdewolff) | Raiwall eliminates CGO and guarantees ReDoS safety via strict **32 KB cap and 5 ms per-parameter timeout**. |
| **Client TLS Fingerprinting**| **JA4 / JA4+** database with Cloud sync and active threat hashes | **JA4+** (`exaring/ja4plus`) computed passively at TLS handshake | Direct architectural parity; JA4 is utilized across forensics, CGNAT rate limiting, and bot defense. |
| **Bot Mitigation** | Cloud Managed Challenge or Local Challenge (Sliding CAPTCHA, Anti-Replay, HTTP 468 PoW) | **Stateless SHA-256 Proof-of-Work (HTTP 468)** via Altcha / Anubis + HMAC clearance cookies | Raiwall implements API Fast-Path bypass (`Authorization: Bearer`, `/api/*`) to prevent breaking B2B mobile clients. |
| **Rate Limiting** | **Three-Tier Rate Limiting**: Access Limit (Tier 1), Attack Limit (Tier 2), Error Limit (Tier 3) | **Three-Tier Composite Rate Limiting**: Tier 1 (Velocity -> PoW), Tier 2 (Attack -> Ban), Tier 3 (403/404 Scanner Trap -> Ban) | Identical three-tier conceptual defense model. Raiwall adds **CGNAT protection** via composite keys (`IP + JA4 + Cookie`). |
| **Access Control (ACL)** | Multi-condition boolean rule builder with IP Groups | **expr** bytecode compiler (`expr-lang/expr`, < 15 ns) + **BART** CIDR routing table (`gaissmai/bart`, ~15 ns for 500K+ IPs) | Raiwall achieves sub-microsecond ACL evaluation in pure Go memory structures. |
| **Traffic Buffering** | **Waiting Room** queue (HTTP 465) with concurrency caps and position tracking | Reverse proxy buffering with `sync.Pool` buffer pooling | SafeLine's **Waiting Room** pattern is a high-value capability Raiwall can incorporate. |
| **API Inventory** | Active API discovery & cataloging under `Sites -> Detail -> Routings` | Planned OpenAPI contract compliance inspection | SafeLine's runtime endpoint discovery provides high visibility for microservices teams. |
| **Packaging & Distribution**| Multi-container Docker Compose deployment (Tengine, Detector, Web, Redis, Postgres) | **Single binary** (`bin/raiwall`) shipping Caddy, WAF engine, API, and embedded Vue UI | Drastically simpler operations, zero-dependency deployment, container image < 50 MB. |

---

## 2. Deep Dive: Architectural Synergies

SafeLine and Raiwall converge on several cutting-edge WAF design patterns:

### 2.1 The Three-Tiered Volumetric Defense Hierarchy

Both systems recognize that traditional single-counter rate limiting either triggers excessive false positives on human users or fails to stop slow distributed bots:

```
[Incoming Request]
       │
       ├── Tier 1: Access Velocity Check
       │   └── Trigger: Excessive requests in short window (e.g. 100 req / 10s)
       │   └── Resolution: Challenge with HTTP 468 Proof-of-Work (No hard ban)
       │
       ├── Tier 2: Attack Frequency Check
       │   └── Trigger: Client triggers WAF blocks repeatedly (e.g. 10 attacks / 60s)
       │   └── Resolution: Automatic hard IP ban (e.g. 30 minutes)
       │
       └── Tier 3: Scanner Trap (Error Rate Limiting)
           └── Trigger: Client provokes upstream 403 / 404 errors (e.g. 10 errors / 10s)
           └── Resolution: Automatic scanner IP ban (traps DirBuster, Gobuster, Nikto)
```

**Raiwall Advantage:** In Raiwall, Tier 3 bans use composite keys (`ClientIP + JA4 Hash + SessionCookie`) to prevent **CGNAT collateral damage**, ensuring legitimate mobile users sharing a cellular gateway IP are not banned when one device behaves maliciously.

---

### 2.2 Standardized Custom HTTP Response Codes

SafeLine pioneers deterministic status codes to signal specific gateway actions without conflating everything into a generic `403 Forbidden`:

| Status Code | SafeLine Meaning | Raiwall Equivalent |
| :--- | :--- | :--- |
| **HTTP 403** | Attack Blocked (WAF Semantic / Rule detection) | Attack Blocked (Semantic AST / Libinjection) |
| **HTTP 429** | Rate Limit Exceeded (Volumetric throttle) | Rate Limit Exceeded (Ristretto / Redis limiter) |
| **HTTP 465** | Virtual Waiting Room Queue | *Proposed for Raiwall Roadmap* |
| **HTTP 466** | Application Offline (All upstreams failed health checks) | 502/503 Service Unavailable |
| **HTTP 467** | Pre-Application Identity Authentication Challenge | Zero-Code SSO Pre-Auth Gate |
| **HTTP 468** | Stateless Proof-of-Work Bot Challenge | Altcha / Anubis HTTP 468 Challenge |

---

## 3. Recommended UX & Feature Enhancements for Raiwall

Based on this complete research of SafeLine v9.4.2, the following features represent immediate, high-impact opportunities for Raiwall:

### 3.1 Forensic Inspector UX Upgrades (`Attacks -> Detail`)

SafeLine's event detail modal provides an industry-leading experience for SOC analysts. Raiwall's Vue dashboard should incorporate:

1. **Parameter Location Tag**: Explicitly tagging where the payload was detected (`URLPATH`, `QUERY`, `HEADER`, `BODY`, `COOKIE`).
2. **One-Click "Copy as cURL"**: Generates a drop-in terminal command with headers, cookies, and payload for rapid curl verification.
3. **In-Place "Add to Whitelist" / "Add to IP Blacklist"**: Direct action buttons inside the forensic inspection drawer to remediate false positives or permanently ban attackers without navigating away.
4. **Character Encoding Selector**: Dropdown supporting `UTF-8`, `GBK`, and `ISO-8859-1` decoding for international payloads.

---

### 3.2 Virtual Waiting Room Queue (HTTP 465)

During flash sales or viral traffic events, upstream databases can be overwhelmed even by clean traffic.
- **Raiwall Implementation**: Implement a token-bucket queue in Caddy middleware returning `HTTP 465` with a lightweight, client-side polling or SSE widget that displays queue position and auto-redirects when an admission clearance cookie is granted.

---

### 3.3 Path-Prefix Forwarding Rules (`Sites -> Detail -> Forwarding Rules`)

Allows routing different sub-paths of a single domain to distinct internal backends (e.g. `/` -> Web Frontend, `/api/v1/` -> Go Microservice, `/ws/` -> WebSocket Server).
- **Raiwall Implementation**: Expose Caddy's native `handle_path` directives directly through Raiwall's Huma REST API and Vue UI.

---

### 3.4 Runtime API Discovery & Inventory (`Sites -> Detail -> Routings`)

Observing clean transit traffic and automatically recording API endpoints, HTTP methods, and content types gives teams an accurate, live inventory of shadow APIs.
- **Raiwall Implementation**: Use a ring buffer in the data plane to sample observed paths and push discovered endpoints asynchronously to SQLite.

---

### 3.5 Custom Response Page Template Editor (`Settings -> Blocking Pages`)

Allowing operators to customize HTML templates and corporate branding for HTTP `403`, `429`, `465`, `467`, and `468` responses directly within the admin dashboard.

---

## 4. Architectural Summary

| Feature | SafeLine v9.4.2 | Raiwall Goal State |
| :--- | :--- | :--- |
| **Deployment Footprint** | Multi-container Docker (Tengine, Detector, Web, Redis, PG) | **Single compiled Go binary (< 50MB image)** |
| **WAF Evaluation Latency**| ~1–3 ms (IPC to detector process) | **< 2 µs lexical triage + bounded AST (< 5 ms timeout)** |
| **ACME SSL Lifecycle** | Manual upload + partial ACME | **Automatic Zero-Config ACME via CertMagic** |
| **Community / Licensing** | Closed-source core with commercial Pro tiers | **100% Open Source (Enterprise-Grade)** |
