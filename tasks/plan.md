# Implementation Plan: Raiwall Domain 3 (Bot Mitigation & Dynamic Active Defense / Chaos Engine)

## Overview
Implement **Domain 3: Bot Mitigation & Dynamic Active Defense (Chaos Engine)** for **Raiwall**: an enterprise-grade, multi-layered bot defense architecture combining passive TLS/JA4 fingerprinting, intelligent route classification with an automated API fast-path, stateless client-side WebCrypto Proof-of-Work (PoW) challenges (HTTP 468), and a pure-Go streaming Chaos Engine for honeypot injection with SPA hydration safeguards.

The defense pipeline operates across five coordinated phases:
1. **Passive TLS & JA4 Fingerprinting:** Dual-mode fingerprinting captures TLS `ClientHello` structures (`exaring/ja4plus`) during direct TLS handshakes, with transparent fallback to upstream headers (`X-JA4-Fingerprint` / `JA4`) behind CDNs. Heuristic classification correlates JA4 signatures against client `User-Agent` strings to block spoofed tools (`curl`, `python-requests`, `sqlmap`, `Go-http-client`).
2. **Intelligent Route Classifier (API Fast-Path vs. Browser Gate):** Non-browser machine traffic (`/api/*`, `Authorization: Bearer`, `Accept: application/json`) is steered onto an automated fast-path that completely bypasses interactive challenges, preventing mobile and B2B webhook breakage.
3. **Stateless WebCrypto PoW & Clearance Gate (HTTP 468):** Unverified browser sessions (`Accept: text/html`) exceeding threat thresholds receive an embedded, self-contained HTTP 468 challenge page powered by `github.com/altcha-org/altcha-lib-go`. Solved challenges submitted to `/.raiwall/challenge/verify` issue an `HttpOnly` clearance cookie signed with `HMAC_SHA256(IP + JA4 + Timestamp, Secret)`.
4. **Chaos Engine (Dynamic Honeypot Injection & Auto-Ban):** Pure-Go streaming HTML rewriter injects hidden honeypot links into static HTML responses while automatically deactivating injection on React/Vue/Next.js pages to prevent SPA hydration mismatch crashes. Crawlers accessing honeypot links are immediately auto-banned (composite IP + JA4 key).
5. **HTTP/2 Frame Fingerprinting:** Connection-level inspection of HTTP/2 `SETTINGS` frames, window updates, and pseudo-header ordering to identify headless botnet clusters.

---

## Architecture Decisions

- **100% Pure-Go, CGO-Free Implementation:** All components (`exaring/ja4plus`, `altcha-org/altcha-lib-go`, pure-Go HTML streaming via `golang.org/x/net/html` or `tdewolff/parse/v2/html`) remain strictly CGO-free, preserving single-binary portability and Alpine compatibility.
- **Dual-Mode JA4 Fingerprinting:** Captures direct TLS handshakes via Caddy listener / `ClientHelloInfo` hook when terminating TLS, while allowing trusted upstream proxy headers (`X-JA4-Fingerprint`) for multi-tier edge deployments.
- **Strict Tiered Bot Action Matrix:** Obvious tool/browser spoofers (CLI JA4 masquerading as Chrome) are blocked outright with HTTP 403; suspicious or unverified browser sessions are challenged with HTTP 468 PoW. `ModeAudit` logs detections without blocking.
- **Dedicated Internal Endpoint (`/.raiwall/challenge/verify`):** Standardizes challenge submission, isolates challenge verification from upstream routing, and issues time-bounded HMAC clearance cookies (`rw_clearance`, default 2h TTL).
- **SPA Hydration Safety Guarantee:** Deactivates HTML mutation on modern SPA/SSR responses (detecting `id="__next"`, `id="app"`, `id="root"`, etc.) so frontends never experience DOM hydration mismatch errors.
- **Composite Key Auto-Ban:** Trapped crawlers are banned using `ClientIP + JA4` composite keys, preventing shared CGNAT collateral damage while neutralizing botnets.
- **Phased HTTP/2 Frame Fingerprinting:** JA4 TLS, Route Classification, PoW, and Honeypot traps form the core delivery (Phases 1–4), with HTTP/2 frame inspection delivered in Phase 5.

---

## Task List Index

Tasks are tracked in `tasks/todo.md`:

### Phase 1: TLS Fingerprinting (JA4) & Bot Lexical Scanner
- [x] **Task 18: JA4 TLS Fingerprinting Engine & Header Ingestion** (Size: S)
- [x] **Task 19: JA4-to-UA Bot Classifier & Spoofing Detector** (Size: S)
- [x] *Checkpoint: JA4 fingerprinting and UA-spoofing detection verified.*

### Phase 2: Intelligent Route Classifier & API Fast-Path
- [x] **Task 20: Intelligent Route Classifier (API Fast-Path vs Browser Gate)** (Size: S)
- [x] *Checkpoint: API fast-path bypasses challenges for Bearer/JSON/API routes.*

### Phase 3: Stateless Altcha PoW Engine & Clearance Cookie Gate
- [x] **Task 21: Stateless Proof-of-Work Engine via `altcha-lib-go` & HTTP 468 Challenge** (Size: M)
- [x] **Task 22: Clearance Cookie Verification & Internal Challenge Endpoint** (Size: M)
- [x] *Checkpoint: PoW challenge, verification endpoint, and stateless clearance cookie work end-to-end.*

### Phase 4: Chaos Engine: Pure-Go Honeypot Injection & SPA Hydration Safety
- [x] **Task 23: SPA Hydration-Safe HTML Honeypot Injector** (Size: M)
- [x] **Task 24: Chaos Trap Handler & Auto-Ban Controller** (Size: S)
- [x] *Checkpoint: Honeypot trap injection, hydration safety, and crawler auto-ban verified.*

### Phase 5: HTTP/2 Frame Fingerprinting, Caddy Wiring & End-to-End Validation
- [x] **Task 25: HTTP/2 Frame Fingerprinting Engine** (Size: M)
- [x] **Task 26: Caddy Middleware Integration & Caddyfile Directives for Domain 3** (Size: M)
- [x] **Task 27: Domain 3 End-to-End Integration & Bot Defense Benchmark Test Suite** (Size: M)
- [x] *Checkpoint: Milestone 3 complete, all tests passing with `-race`, single binary builds cleanly.*

---

## Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **Mobile / B2B Webhook Breakage on Interactive Challenges** | **High** | Intelligent Route Classifier unconditionally bypasses interactive challenges for `/api/*`, `Authorization: Bearer`, and `Accept: application/json`. |
| **SPA Client Hydration Mismatch Crashes** | **High** | DOM scanner detects React, Vue, Next.js root elements and deactivates honeypot rewriting on dynamic SPA pages. |
| **CGNAT Collateral Damage from Shared IP Bans** | **Medium** | Auto-ban and clearance cookies bind to composite keys: `ClientIP + JA4 Fingerprint + Cookie Hash`. |
| **PoW Challenge Replay & Verification Flooding** | **Medium** | Altcha HMAC challenge expiration, non-reusable salt tracking, and `Cache-Control: no-store` prevents CDN caching. |
| **CGO Portability & Cross-Compilation Overhead** | **High** | 100% pure-Go dependencies (`exaring/ja4plus`, `altcha-org/altcha-lib-go`, pure-Go HTML parsing). No Rust or C toolchain required. |

---

## Open Questions & Future Work
- **Cluster Sync for Auto-Ban State:** In multi-node deployments, auto-ban entries will synchronize via Redis Pub/Sub (Domain 7). Domain 3 implements single-node thread-safe in-memory caching with TTL expiration.
- **Frontend / Dashboard Integration (Domains 6 & 7):** Live bot challenge metrics, JA4 distributions, and honeypot trap hits will surface in the embedded Vue 3 admin dashboard.
