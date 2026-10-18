# Implementation Plan: Raiwall Domain 4 (DDoS, HTTP Flood & Three-Tiered Rate Limiting)

## Overview
Implement **Domain 4: DDoS, HTTP Flood & Three-Tiered Rate Limiting** for **Raiwall**: an enterprise-grade, high-throughput traffic control and anti-abuse architecture combining a three-tiered sliding-window / Generic Cell Rate Algorithm (GCRA) rate limiter, anti-CGNAT composite key tracking, scanner reconnaissance traps, and a bounded Server-Sent Events (SSE) Virtual Waiting Room.

The traffic defense pipeline operates across five coordinated layers:
1. **High-Performance GCRA Engine & Pluggable Storage:** Sub-microsecond ($<1\text{ µs}$) pure-Go GCRA engine supporting single-node in-memory storage (`dgraph-io/ristretto` / atomic structures) as default, plus an optional distributed Redis storage backend for cluster deployments.
2. **Tier 1 — Access Velocity (Flood Mitigation):** Evaluated at the front of the request pipeline. Exceeding velocity thresholds (e.g. $>100\text{ req}/10\text{s}$) triggers route-aware enforcement: unverified browser sessions receive an HTTP 468 Altcha PoW challenge, while API/machine routes receive standard HTTP 429 Too Many Requests with `Retry-After` and JSON error payloads.
3. **Tier 2 — Attack Frequency Limiter:** Incremented whenever the Semantic Threat Engine (Domain 2) or Bot Classifier blocks a malicious payload. Exceeding thresholds (e.g. 10 attacks in 60s) triggers an immediate auto-ban stored in a unified, thread-safe `BanManager` with composite `ClientIP + JA4` keys to prevent CGNAT collateral damage.
4. **Tier 3 — Scanner Trap (Anti-Reconnaissance):** Intercepts reverse proxy backend responses (`ModifyResponse`). Whenever the upstream server returns `404 Not Found` or `403 Forbidden`, the reconnaissance counter increments. Static asset requests (`.ico`, `.css`, `.png`, etc.) are filtered out to avoid false positives. Exceeding thresholds (e.g. $>20\text{ errors}/30\text{s}$) bans directory brute-forcers (`ffuf`, `gobuster`, `dirsearch`).
5. **Bounded Virtual Waiting Room:** During extreme traffic surges, excess users enter an SSE-powered waiting room with real-time queue position streaming. Queue depth is strictly capped (`max_queue_depth`) to prevent socket and file-descriptor exhaustion (`ulimit -n`), shedding excess requests with HTTP 503 + `Retry-After`.

---

## Architecture Decisions

- **Pluggable Storage Abstraction (`RateLimiter` & `RateStorage`):** Abstract storage interface allowing seamless switching between high-performance in-memory GCRA (zero CGO, zero GC overhead) and distributed Redis (`go-redis` or raw scripts) for clustered multi-node data planes.
- **Route-Aware Tier 1 Enforcement:** Preserves mobile apps and B2B API pipelines (`/api/*`, `Authorization: Bearer`, `Accept: application/json`) by issuing HTTP 429 + `Retry-After` rather than interactive browser PoW challenges.
- **Anti-CGNAT Composite Key Strategy:** Prevents accidental lockouts of university campuses, corporate egress proxies, or mobile carrier NATs by binding scanner traps and rate limits to composite keys: `ClientIP + JA4_Hash + SessionCookie` (with graceful fallback to `ClientIP + JA4` when unauthenticated).
- **Unified Ban Manager (`pkg/rate/ban.go`):** Harmonizes auto-ban state across Domain 3 (honeypot crawler bans) and Domain 4 (Tier 2 attack frequency & Tier 3 scanner bans) into a single, high-throughput in-memory TTL store evaluated on the sub-microsecond fast-path.
- **Bounded Virtual Waiting Room with Strict Concurrency Cap:** Prevents socket/file-descriptor exhaustion (`ulimit -n`) under massive DDoS floods by enforcing a strict `max_queue_depth`. Excess connections are shed immediately with HTTP 503 rather than holding open connections indefinitely.
- **Nested Caddyfile Directives:** Clean, intuitive operator configuration via nested `rate_limit { ... }` and `waiting_room { ... }` blocks.

---

## Dependency Graph

```
RateStorage Interface (Memory / Redis)
   │
   ├── Generic Cell Rate Algorithm (GCRA Engine)
   │       │
   │       ├── Composite Key Builder (IP + JA4 + Cookie)
   │       │       │
   │       │       ├── Tier 1 Velocity Limiter (PoW / 429)
   │       │       ├── Tier 2 Attack Frequency Limiter (BanManager)
   │       │       └── Tier 3 Scanner Trap (Upstream 403/404 Interceptor)
   │       │
   │       └── Bounded Virtual Waiting Room (SSE Streamer + Queue Cap)
   │
   └── Caddy Middleware Wiring & Caddyfile Parsing
           │
           └── End-to-End Tests & DDoS Benchmark Suite
```

---

## Task List Index

Tasks are tracked in `tasks/todo.md`:

### Phase 1: High-Performance Rate Limiter Engine & Pluggable Storage
- [x] **Task 28: Core Rate Limiter Abstraction & Pure-Go GCRA In-Memory Engine** (Size: M)
- [x] **Task 29: Distributed Redis Storage Backend & Composite Key Builder** (Size: M)
- [x] *Checkpoint: Core rate limiter engine, in-memory GCRA, Redis backend, and composite key builder verified.*

### Phase 2: Tier 1 (Access Velocity) & Tier 2 (Attack Frequency Limiter)
- [x] **Task 30: Tier 1 Access Velocity Limiter with Route-Aware Enforcement** (Size: M)
- [x] **Task 31: Tier 2 Attack Frequency Limiter & Unified Ban Store** (Size: M)
- [x] *Checkpoint: Tier 1 access velocity and Tier 2 attack frequency limiting with unified ban store verified.*

### Phase 3: Tier 3 Scanner Trap & Anti-Reconnaissance Engine
- [x] **Task 32: Tier 3 Scanner Trap with Upstream Response Interception** (Size: M)
- [x] *Checkpoint: Tier 3 scanner trap neutralizes directory fuzzers without false positives on static assets.*

### Phase 4: Bounded Virtual Waiting Room (SSE Streaming & Surge Protection)
- [x] **Task 33: Bounded Virtual Waiting Room Engine & SSE Queue Streamer** (Size: M)
- [x] **Task 34: Embedded Waiting Room UI & Client-Side Auto-Admit** (Size: S)
- [x] *Checkpoint: Virtual waiting room streams live SSE queue updates, admits users smoothly, and sheds excess traffic under extreme overload.*

### Phase 5: Caddy Middleware Wiring, Caddyfile Parsing & End-to-End Validation
- [x] **Task 35: Caddy Middleware Integration & Nested Caddyfile Directives** (Size: M)
- [x] **Task 36: Domain 4 End-to-End Integration Tests & DDoS Flood Benchmark Suite** (Size: M)
- [x] *Checkpoint: Milestone 4 complete, all tests passing with `-race`, single binary builds cleanly.*

---

## Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **CGNAT Collateral Damage from Shared IP Bans** | **High** | Evaluate composite rate limiting keys: `ClientIP + JA4_Hash + SessionCookie`. Allow individual browser sessions behind shared proxies to continue unhindered. |
| **Mobile / B2B Webhook Breakage on Rate Limit** | **High** | Intelligent Route Classifier steers machine traffic (`/api/*`, `Authorization: Bearer`, `Accept: application/json`) to HTTP 429 with `Retry-After` rather than HTML PoW challenges. |
| **Socket & FD Exhaustion during Waiting Room Surges** | **High** | Enforce a strict `max_queue_depth` cap on the SSE waiting room. Excess connections are shed immediately with HTTP 503 to preserve system stability (`ulimit -n`). |
| **Lock Contention on In-Memory Rate Limiter at High QPS** | **Medium** | Use partitioned/sharded locks or lock-free atomic CAS operations with Ristretto for sub-microsecond GCRA evaluations. |
| **False-Positive Scanner Bans on Missing Static Assets** | **Medium** | Exclude common static file extensions (`.ico`, `.css`, `.png`, `.jpg`, `.svg`, `.js`, etc.) from incrementing the Tier 3 404/403 counter. |

---

## Open Questions & Future Work
- **Cluster Redis Pub/Sub Synchronization (Domain 7):** When operating in Redis cluster mode, ban revocations and waiting room queue positions will sync across data plane nodes via Redis Pub/Sub.
- **Frontend Dashboard Real-Time Metrics (Domain 6):** Real-time rate limit drops, waiting room queue depths, and scanner trap bans will be streamed via SSE to the Vue 3 control plane dashboard.
