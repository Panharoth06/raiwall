# Tasks: Raiwall Domain 2 (Semantic Threat Detection Engine)

## Completed Milestones
- [x] **Milestone 1: Domain 1 (Reverse Proxy & Gateway)** — Tasks 1 through 8 completed and verified with automated tests.

---

## Phase 1: Stage 1 Normalization & Parameter Extraction

### Task 9: Recursive Normalization Engine via Coraza v3 Transformations
**Description:** Implement `pkg/engine/normalizer` using `corazawaf/coraza/v3` transformation plugins (`urlDecodeUni`, `htmlEntityDecode`, `jsDecode`, `cssDecode`, `cmdLine`, `removeComments`). Execute a recursive normalization loop that repeatedly transforms input until the string reaches a fixed point (stabilizes) or hits a hard limit of 10 iterations.

**Acceptance criteria:**
- [x] Implement `Normalize(input string) string` with multi-pass recursive decoding.
- [x] Decodes nested/multi-layered encodings (e.g., `%252e%252e%252f` -> `../`, HTML entities `&quot;`, Unicode `\u0027`, hex `0x27`).
- [x] Strips inline SQL and C-style comments (`/* ... */`) cleanly.
- [x] Halts within $\le 10$ iterations with zero infinite loop risk.
- [x] Unit tests verify decoding against multi-layered evasion vectors.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/engine/normalizer/...`
- [x] Build succeeds: `go build ./pkg/engine/normalizer/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/engine/normalizer/normalizer.go`
- `pkg/engine/normalizer/normalizer_test.go`
**Estimated scope:** Small (2 files)

---

### Task 10: Structured Body Extractors & Selective Multipart Streaming
**Description:** Implement extractors in `pkg/engine/normalizer` for query parameters, request paths, custom headers, JSON request bodies, URL-encoded forms, and Multipart form data. Enforce selective multipart parsing where file upload streams ($>1\text{ MB}$) pass directly to upstream and only form fields and text metadata enter inspection.

**Acceptance criteria:**
- [x] Define `Parameter` struct (`Name`, `Value`, `Location: Path|Query|Header|Body|JSON|Multipart`).
- [x] Extract parameters from JSON bodies (traversing keys and string values).
- [x] Parse `multipart/form-data`: inspect form text fields and file headers while skipping large binary file contents $>1\text{ MB}$.
- [x] Parse `application/x-www-form-urlencoded` bodies and URL query strings.
- [x] Unit tests cover JSON payloads, nested objects, and multipart forms.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/engine/normalizer/...`
- [x] Build succeeds: `go build ./pkg/engine/normalizer/...`

**Dependencies:** Task 9
**Files likely touched:**
- `pkg/engine/normalizer/extractor.go`
- `pkg/engine/normalizer/extractor_test.go`
**Estimated scope:** Medium (2–3 files)

---

## Checkpoint: Stage 1 Normalization & Extraction
- [x] Recursive normalizer decodes multi-pass evasions and strips comments.
- [x] Parameter extractor normalizes and surfaces all query, header, JSON, and form parameters.
- [x] Unit tests pass with `-race`.

---

## Phase 2: Stage 2 Fast Lexical Triage & Shell Metacharacter Scanner

### Task 11: Enhanced Lexical Triage with Shell Metacharacter Fast-Filter
**Description:** Enhance `pkg/engine/lexical.go` to perform sub-$2\text{ µs}$ lexical triage across normalized parameters. In addition to SQLi and XSS fingerprints via pure-Go `libinjection-go`, add an ultra-fast scanner for shell injection command metacharacters (`;&|`, backticks, `$()`) and command binaries (`curl`, `wget`, `sh`, `bash`, `python`, `nc`).

**Acceptance criteria:**
- [x] Classify normalized values into `TriageResult`: `Benign`, `SuspectSQLi`, `SuspectXSS`, `SuspectCmdI`.
- [x] Command injection scanner detects shell metacharacters and suspicious invocation tokens in $<1\text{ µs}$.
- [x] Fast-path allows benign parameters to bypass Stage 3 AST parsing completely.
- [x] Unit tests verify $<2\text{ µs}$ execution and detection accuracy for SQL, XSS, and command metacharacters.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/engine/...`
- [x] Benchmark: `go test -bench=BenchmarkLexicalTriage ./pkg/engine/...`
- [x] Build succeeds: `go build ./pkg/engine/...`

**Dependencies:** Task 9, Task 10
**Files likely touched:**
- `pkg/engine/lexical.go`
- `pkg/engine/lexical_test.go`
**Estimated scope:** Small (2 files)

---

## Checkpoint: Stage 2 Fast Triage
- [x] Lexical triage categorizes inputs in $<2\text{ µs}$ with zero allocations on benign paths.
- [x] Accurately routes benign inputs to pass and suspect inputs to Stage 3.

---

## Phase 3: Stage 3 Bounded AST Context Verification (SQL, Shell, XSS)

### Task 12: SQLChop: Bounded SQL AST Context Verification (`xwb1989/sqlparser`)
**Description:** Implement `SQLChop` in `pkg/engine/ast` using pure-Go `xwb1989/sqlparser`. Use multi-context synthetic grammar template probing (quoted string context `SELECT * FROM t WHERE c = '<INPUT>'`, unquoted context `SELECT * FROM t WHERE c = <INPUT>`). Detect semantic breakout (union operators, subqueries, unescaped boolean operators, stacked queries). Enforce $32\text{ KB}$ cap and $5\text{ ms}$ execution deadline per parameter.

**Acceptance criteria:**
- [x] Probe candidate inputs against synthetic SQL grammar templates.
- [x] Detect semantic breakout beyond literal node boundaries (e.g. `1' OR '1'='1`, `' UNION SELECT ...`).
- [x] Skip parameters $>32\text{ KB}$ and rely on Stage 2 lexical triage.
- [x] Enforce $5\text{ ms}$ timeout using `context.WithTimeout`, downgrading timeout to `ActionAudit` with reason `PARSER_TIMEOUT`.
- [x] Unit tests cover SQL injection vectors and verify timeout/cap boundaries.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/engine/ast/...`
- [x] Build succeeds: `go build ./pkg/engine/ast/...`

**Dependencies:** Task 11
**Files likely touched:**
- `pkg/engine/ast/sqlchop.go`
- `pkg/engine/ast/sqlchop_test.go`
**Estimated scope:** Medium (2–3 files)

---

### Task 13: CMDChop: Bounded Shell AST Context Verification (`mvdan/sh/v3/syntax`)
**Description:** Implement `CMDChop` in `pkg/engine/ast` using `mvdan/sh/v3/syntax`. Probe candidate inputs inside synthetic command contexts (`cmd <INPUT>`, `cmd "<INPUT>"`, `cmd '<INPUT>'`). Detect syntax breakout into command pipelines (`|`), chained commands (`&&`, `||`, `;`), command substitutions (`$(...)`, backticks), and file redirects (`>`, `<`). Enforce $32\text{ KB}$ cap and $5\text{ ms}$ timeout per parameter.

**Acceptance criteria:**
- [x] Parse synthetic shell command strings into POSIX/Bash syntax AST.
- [x] Flag breakout if AST contains multiple statements, `CmdSubst`, `Subshell`, binary command expressions, or redirects.
- [x] Skip parameters $>32\text{ KB}$ (fallback to lexical triage) and enforce $5\text{ ms}$ timeout (downgrades to `ActionAudit`).
- [x] Unit tests verify detection of command injection vectors (e.g. `; cat /etc/passwd`, `$(whoami)`, `| nc -e /bin/sh`).

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/engine/ast/...`
- [x] Build succeeds: `go build ./pkg/engine/ast/...`

**Dependencies:** Task 11
**Files likely touched:**
- `pkg/engine/ast/cmdchop.go`
- `pkg/engine/ast/cmdchop_test.go`
**Estimated scope:** Medium (2–3 files)

---

### Task 14: XSSChop: Bounded HTML/JS Context Verification (`tdewolff/parse/v2`)
**Description:** Implement `XSSChop` in `pkg/engine/ast` using `tdewolff/parse/v2`. Probe candidate inputs inside synthetic HTML contexts (attribute context `<div data-val="<INPUT>">`, element body context `<div><INPUT></div>`). Detect tag injection (`<script>`, `<iframe>`, `<img>`), attribute event handler breakout (`onerror=`, `onload=`), and script pseudo-protocols (`javascript:`). Enforce $32\text{ KB}$ cap and $5\text{ ms}$ timeout per parameter.

**Acceptance criteria:**
- [x] Parse synthetic HTML streams into tokens using `tdewolff/parse/v2/html`.
- [x] Detect quote breakout resulting in new HTML attributes, event handlers, or closing tags with nested executable tags.
- [x] Skip parameters $>32\text{ KB}$ and enforce $5\text{ ms}$ timeout with `ActionAudit` downgrade on timeout.
- [x] Unit tests cover reflected and attribute-based XSS vectors (`"><script>alert(1)</script>`, `" onerror=alert(1)`).

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/engine/ast/...`
- [x] Build succeeds: `go build ./pkg/engine/ast/...`

**Dependencies:** Task 11
**Files likely touched:**
- `pkg/engine/ast/xsschop.go`
- `pkg/engine/ast/xsschop_test.go`
**Estimated scope:** Medium (2–3 files)

---

## Checkpoint: Stage 3 AST Verifiers
- [x] SQLChop, CMDChop, and XSSChop detect breakouts across all test suites.
- [x] $32\text{ KB}$ cap and $5\text{ ms}$ execution deadline strictly respected across all three verifiers.
- [x] Zero race conditions (`go test -race ./pkg/engine/ast/...`).

---

## Phase 4: Funnel Orchestration, Caddy Middleware Wiring & End-to-End Validation

### Task 15: Semantic Engine Funnel Orchestrator
**Description:** Implement `SemanticEngine` in `pkg/engine/semantic.go` implementing the `WAFEngine` interface. Coordinate Stage 1 (Normalization & Extraction) $\to$ Stage 2 (Fast Lexical Triage) $\to$ Stage 3 (Bounded AST Verification). Short-circuit immediately on confirmed AST block verdicts or benign requests.

**Acceptance criteria:**
- [x] Implement `SemanticEngine` satisfying `WAFEngine` (`InspectRequest` and `InspectResponse`).
- [x] Chain Stage 1 (multi-pass decode & param extraction) $\to$ Stage 2 (lexical triage) $\to$ Stage 3 (AST verifiers).
- [x] Return `Verdict` with exact `RuleID` (e.g. `SEMANTIC_SQLI`, `SEMANTIC_CMDI`, `SEMANTIC_XSS`), matched parameter location, and reason.
- [x] Handle timeouts by emitting `ActionAudit` with `PARSER_TIMEOUT`.
- [x] Unit tests cover end-to-end request inspection across diverse payload combinations.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/engine/semantic_test.go`
- [x] Build succeeds: `go build ./pkg/engine/...`

**Dependencies:** Tasks 9–14
**Files likely touched:**
- `pkg/engine/semantic.go`
- `pkg/engine/semantic_test.go`
**Estimated scope:** Medium (2–3 files)

---

### Task 16: Caddy Middleware Integration & Caddyfile Directives
**Description:** Wire `SemanticEngine` into `pkg/proxy/middleware.go` as the default engine provisioned when `m.engine == nil`. Expose optional Caddyfile directives (`ast_timeout`, `max_param_size`) for operator tuning in `pkg/proxy/caddyfile.go`. Update `examples/Caddyfile`.

**Acceptance criteria:**
- [x] `Middleware.Provision` initializes `SemanticEngine` by default with zero-config defaults (5ms timeout, 32KB cap).
- [x] Caddyfile unmarshaler supports optional `ast_timeout <duration>` and `max_param_size <bytes>` blocks.
- [x] `examples/Caddyfile` showcases semantic WAF configuration options.
- [x] Unit tests verify Caddyfile parsing and middleware provisioning with `SemanticEngine`.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/proxy/...`
- [x] Build succeeds: `go build ./cmd/raiwall`

**Dependencies:** Task 15
**Files likely touched:**
- `pkg/proxy/middleware.go`
- `pkg/proxy/caddyfile.go`
- `pkg/proxy/caddyfile_test.go`
- `examples/Caddyfile`
**Estimated scope:** Small (3–4 files)

---

### Task 17: Comprehensive End-to-End WAF Benchmark & Evasion Test Suite
**Description:** Build comprehensive end-to-end integration and benchmark tests in `tests/e2e/semantic_waf_test.go` and `pkg/engine/benchmark_test.go`. Test against real-world CVE payloads, polyglots, nested encoding evasions, and benchmark overall throughput and latency ($p99 < 15\text{ ms}$).

**Acceptance criteria:**
- [x] Integration tests verify blocking of SQLi, Shell injection, and XSS across GET query, POST form, POST JSON, and headers through running Caddy instance.
- [x] Test evasion resilience: double URL encoding, mixed case, comments (`/**/`), Unicode entities.
- [x] Benchmark test confirms benign traffic passes in $<10\text{ µs}$ and suspect traffic in $<5\text{ ms}$, ensuring $p99 < 15\text{ ms}$.
- [x] Zero race conditions under concurrent requests (`go test -race`).

**Verification:**
- [x] Integration tests pass: `go test -v -race -tags=integration ./tests/e2e/...`
- [x] Benchmarks pass: `go test -bench=. ./pkg/engine/...`
- [x] Standalone build succeeds: `make build`

**Dependencies:** Tasks 9–16
**Files likely touched:**
- `tests/e2e/semantic_waf_test.go`
- `pkg/engine/benchmark_test.go`
**Estimated scope:** Medium (2 files)

---

## Final Checkpoint: Milestone 2 (Domain 2) Completion
- [x] All 9 tasks (Tasks 9–17) implemented and verified.
- [x] Recursive normalization, fast lexical triage, and bounded AST context verification (SQL, Shell, XSS) fully operational.
- [x] All unit, integration, and benchmark tests pass with `-race`.
- [x] Ready to proceed to Milestone 3 (Domain 3: Bot Mitigation & Dynamic Active Defense).


---

# Tasks: Raiwall Domain 3 (Bot Mitigation & Dynamic Active Defense / Chaos Engine)

## Phase 1: TLS Fingerprinting (JA4) & Bot Lexical Scanner

### Task 18: JA4 TLS Fingerprinting Engine & Header Ingestion
**Description:** Implement `pkg/bot/ja4.go` using `github.com/exaring/ja4plus` to extract JA4 TLS client fingerprints from `tls.ClientHelloInfo`. Support dual-mode capture: direct TLS handshake extraction in Caddy and upstream header fallback (`X-JA4-Fingerprint` or `JA4`) when deployed behind edge CDNs or external proxies. Propagate JA4 onto `RequestContext` and `http.Request` context.

**Acceptance criteria:**
- [x] Implement `ComputeJA4(hello *tls.ClientHelloInfo) string` via `ja4plus.JA4`.
- [x] Implement `ExtractJA4(r *http.Request) string` with upstream header fallback (`X-JA4-Fingerprint`, `JA4`).
- [x] Add `JA4` field to `engine.RequestContext` and context helper functions (`WithJA4`, `GetJA4`).
- [x] Unit tests verify fingerprint calculation across TLS 1.2 / TLS 1.3 ClientHello fixtures and header extraction fallbacks.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/bot/ja4.go`
- `pkg/bot/ja4_test.go`
- `pkg/engine/types.go`
**Estimated scope:** Small (2–3 files)

---

### Task 19: JA4-to-UA Bot Classifier & Spoofing Detector
**Description:** Implement `pkg/bot/classifier.go` to detect anomalous and spoofed clients by comparing client `User-Agent` strings against JA4 fingerprints. Identify automated CLI tools (`python-requests`, `curl`, `sqlmap`, `Go-http-client`, `headless Chrome`) and detect spoofing when a non-browser JA4 signature presents a browser User-Agent header.

**Acceptance criteria:**
- [x] Maintain a known signature catalog/heuristics for common CLI tools and libraries.
- [x] Detect User-Agent spoofing (e.g. `curl` or `python` JA4 hash claiming `Mozilla/5.0 ... Chrome`).
- [x] Return `BotVerdict` (`IsBot`, `IsSpoofed`, `BotCategory`, `Confidence`, `Action`).
- [x] Enforce immediate `ActionBlock` (HTTP 403) for confirmed spoofed clients in `ModeDefense`.
- [x] Unit tests cover known tool signatures, spoofed browser requests, and legitimate browser fingerprints.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** Task 18
**Files likely touched:**
- `pkg/bot/classifier.go`
- `pkg/bot/classifier_test.go`
- `pkg/bot/signatures.go`
**Estimated scope:** Small (2–3 files)

---

## Checkpoint: TLS & JA4 Bot Triage
- [x] JA4 fingerprint computed from ClientHello and fallback headers cleanly.
- [x] Spoofed CLI/library clients accurately classified and blocked.
- [x] Unit tests pass with `-race`.

---

## Phase 2: Intelligent Route Classifier & API Fast-Path

### Task 20: Intelligent Route Classifier (API Fast-Path vs Browser Gate)
**Description:** Implement `pkg/bot/route.go` to categorize incoming requests into `RouteAPI`, `RouteBrowser`, or `RouteStatic`. Provide an automated machine fast-path for API endpoints (`/api/*`, `Authorization: Bearer`, `Accept: application/json`) that guarantees zero interactive challenges, protecting mobile apps and B2B webhooks from breakage.

**Acceptance criteria:**
- [x] Classify requests into `RouteAPI`, `RouteBrowser`, `RouteStatic`.
- [x] Bypass interactive bot challenges unconditionally for `RouteAPI`.
- [x] Support custom API path prefixes and custom bypass headers configurable per app.
- [x] Unit tests verify classification across diverse paths, Accept headers, Authorization tokens, and file extensions.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** None
**Files likely touched:**
- `pkg/bot/route.go`
- `pkg/bot/route_test.go`
**Estimated scope:** Small (2 files)

---

## Checkpoint: Route Classifier
- [x] Machine and API traffic cleanly routed to fast-path without interactive challenge interference.
- [x] Browser routes correctly targeted for threat inspection and challenge eligibility.

---

## Phase 3: Stateless Altcha PoW Engine & Clearance Cookie Gate

### Task 21: Stateless Proof-of-Work Engine via `altcha-lib-go` & HTTP 468 Challenge
**Description:** Implement `pkg/bot/pow.go` using `github.com/altcha-org/altcha-lib-go` to generate and verify stateless SHA-256 WebCrypto Proof-of-Work challenges. Implement self-contained embedded HTML/JS challenge page served on HTTP 468 with `Cache-Control: no-store` and dark mode / responsive styling, requiring zero external CDNs or third-party scripts.

**Acceptance criteria:**
- [x] Integrate `altcha-lib-go` for challenge creation with HMAC signature and configurable complexity.
- [x] Render embedded self-contained HTTP 468 HTML challenge page containing inline WebCrypto solver widget.
- [x] Set `Cache-Control: no-store, no-cache, must-revalidate` and `Content-Type: text/html; charset=utf-8`.
- [x] Unit tests verify challenge creation, serialization, and WebCrypto payload structure.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** Task 20
**Files likely touched:**
- `pkg/bot/pow.go`
- `pkg/bot/templates.go`
- `pkg/bot/pow_test.go`
**Estimated scope:** Medium (3 files)

---

### Task 22: Clearance Cookie Verification & Internal Challenge Endpoint
**Description:** Implement `pkg/bot/clearance.go` to handle challenge verification at `/.raiwall/challenge/verify`. Validate solved PoW payloads, issue `HttpOnly` clearance cookies (`rw_clearance`) signed with `HMAC_SHA256(ClientIP + JA4 + Expiration, Secret)`, and redirect to the original URL. Inspect `rw_clearance` on incoming requests to admit cleared browser sessions.

**Acceptance criteria:**
- [x] Implement `HandleChallengeVerify(w http.ResponseWriter, r *http.Request)` endpoint at `/.raiwall/challenge/verify`.
- [x] Validate Altcha solution against server secret.
- [x] Issue `rw_clearance` cookie with `HttpOnly`, `SameSite=Lax`, `Secure`, and configurable TTL (default 2h).
- [x] Validate `rw_clearance` on subsequent requests; verify signature, expiration, and binding to `ClientIP + JA4`.
- [x] Unit tests cover full issue-validate-expire lifecycle, tampered signatures, and IP/JA4 mismatch invalidation.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** Task 21
**Files likely touched:**
- `pkg/bot/clearance.go`
- `pkg/bot/clearance_test.go`
**Estimated scope:** Medium (2 files)

---

## Checkpoint: PoW Engine & Clearance Cookie
- [x] Stateless PoW challenge renders on HTTP 468 with zero third-party assets.
- [x] Solved challenge at `/.raiwall/challenge/verify` issues tamper-proof HMAC clearance cookie.
- [x] Valid clearance cookie admits subsequent browser requests seamlessly.

---

## Phase 4: Chaos Engine: Pure-Go Honeypot Injection & SPA Hydration Safety

### Task 23: SPA Hydration-Safe HTML Honeypot Injector
**Description:** Implement `pkg/bot/honeypot.go` to dynamically inject hidden honeypot links into static HTML responses using a pure-Go streaming tokenizer (`golang.org/x/net/html` or `tdewolff/parse/v2/html`). Detect modern SPA/SSR framework signatures (`id="__next"`, `id="app"`, `id="root"`, hydration markers) and automatically deactivate injection on SPA routes to prevent hydration mismatch crashes.

**Acceptance criteria:**
- [x] Parse HTML response streams in pure Go without buffering entire documents when possible.
- [x] Detect SPA framework signatures; leave SPA/SSR HTML completely unmodified.
- [x] Inject hidden honeypot anchor tag `<a href="/.raiwall/trap/<token>" style="display:none" rel="nofollow" aria-hidden="true">` before `</body>` on static HTML.
- [x] Unit tests verify correct injection in static HTML and confirm zero mutation on React/Next/Vue HTML.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** Task 20
**Files likely touched:**
- `pkg/bot/honeypot.go`
- `pkg/bot/honeypot_test.go`
**Estimated scope:** Medium (2 files)

---

### Task 24: Chaos Trap Handler & Auto-Ban Controller
**Description:** Implement `pkg/bot/trap.go` to handle requests to `/.raiwall/trap/*`. Offending crawlers that follow hidden honeypot links are immediately banned using a composite `ClientIP + JA4` key in an in-memory TTL cache for a configurable duration (default 24h) and returned HTTP 403 Forbidden.

**Acceptance criteria:**
- [x] Intercept requests targeting `/.raiwall/trap/*`.
- [x] Record offending client in thread-safe memory ban store with 24h TTL.
- [x] Fast-path block returning HTTP 403 for all subsequent requests from banned `ClientIP + JA4`.
- [x] Emit structured security log and metric for honeypot trap trip.
- [x] Unit tests verify trap trip, immediate auto-ban, and TTL expiration.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** Task 23
**Files likely touched:**
- `pkg/bot/trap.go`
- `pkg/bot/trap_test.go`
**Estimated scope:** Small (2 files)

---

## Checkpoint: Chaos Engine & Honeypot Traps
- [x] Honeypot links injected safely into static HTML with zero SPA hydration disruption.
- [x] Crawler accessing trap URL is immediately banned with composite IP + JA4 key.
- [x] Unit tests pass with `-race`.

---

## Phase 5: HTTP/2 Frame Fingerprinting, Caddy Wiring & End-to-End Validation

### Task 25: HTTP/2 Frame Fingerprinting Engine
**Description:** Implement `pkg/bot/h2fingerprint.go` to inspect HTTP/2 connection parameters (`SETTINGS` frame parameter ordering/values, window update sizes, pseudo-header ordering). Calculate HTTP/2 fingerprint and correlate with JA4 and User-Agent to detect headless browser clusters and automated botnets.

**Acceptance criteria:**
- [x] Extract HTTP/2 frame attributes from HTTP/2 connections.
- [x] Generate standardized HTTP/2 fingerprint hash.
- [x] Integrate HTTP/2 fingerprint into bot evaluation heuristics alongside JA4.
- [x] Unit tests verify HTTP/2 fingerprinting and correlation with JA4.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/bot/...`
- [x] Build succeeds: `go build ./pkg/bot/...`

**Dependencies:** Task 19
**Files likely touched:**
- `pkg/bot/h2fingerprint.go`
- `pkg/bot/h2fingerprint_test.go`
**Estimated scope:** Medium (2 files)

---

### Task 26: Caddy Middleware Integration & Caddyfile Directives for Domain 3
**Description:** Integrate `pkg/bot` into Caddy `Middleware` in `pkg/proxy/middleware.go` and TLS ClientHello hooks. Expose Caddyfile directives (`bot_defense`, `pow_difficulty`, `clearance_ttl`, `honeypot_trap`) in `pkg/proxy/caddyfile.go`. Update `examples/Caddyfile`.

**Acceptance criteria:**
- [x] Wire JA4 extraction, route classification, clearance check, and honeypot trap into `ServeHTTP`.
- [x] Implement Caddyfile parsing for `bot_defense <mode>`, `pow_difficulty <int>`, `clearance_ttl <duration>`, and `honeypot <bool>`.
- [x] Update `examples/Caddyfile` with bot defense configurations.
- [x] Unit tests verify Caddyfile unmarshaling and middleware integration.

**Verification:**
- [x] Tests pass: `go test -v -race ./pkg/proxy/...`
- [x] Build succeeds: `go build ./cmd/raiwall`

**Dependencies:** Tasks 18–25
**Files likely touched:**
- `pkg/proxy/middleware.go`
- `pkg/proxy/caddyfile.go`
- `pkg/proxy/caddyfile_test.go`
- `examples/Caddyfile`
**Estimated scope:** Medium (3–4 files)

---

### Task 27: Domain 3 End-to-End Integration & Bot Defense Benchmark Test Suite
**Description:** Build end-to-end integration tests in `tests/e2e/bot_defense_test.go` and benchmarks in `pkg/bot/benchmark_test.go`. Verify full defense flows against real-world bot scenarios, API fast-path latency (<1 µs overhead), PoW verification, and crawler honeypot bans under concurrent load with `-race`.

**Acceptance criteria:**
- [x] Integration tests verify:
  - API requests (`/api/*`, Bearer token) pass directly without challenge.
  - Suspicious browser request receives HTTP 468 PoW challenge.
  - Solving challenge grants access with `rw_clearance` cookie.
  - User-Agent spoofing (curl JA4 with Chrome UA) is blocked with HTTP 403.
  - Honeypot trap visit auto-bans client.
  - SPA HTML responses are unmodified.
- [x] Benchmarks confirm sub-microsecond classification and zero memory leak.
- [x] Standalone build succeeds (`make build`).

**Verification:**
- [x] Integration tests pass: `go test -v -race -tags=integration ./tests/e2e/...`
- [x] Benchmarks pass: `go test -bench=. ./pkg/bot/...`
- [x] Build succeeds: `make build`

**Dependencies:** Tasks 18–26
**Files likely touched:**
- `tests/e2e/bot_defense_test.go`
- `pkg/bot/benchmark_test.go`
**Estimated scope:** Medium (2 files)

---

## Final Checkpoint: Milestone 3 (Domain 3) Completion
- [x] All 10 tasks (Tasks 18–27) implemented and verified.
- [x] Passive JA4 TLS fingerprinting, route classification, stateless Altcha PoW (HTTP 468), clearance cookies, and Chaos honeypot engine fully operational.
- [x] All unit, integration, and benchmark tests pass with `-race`.
- [x] Single binary builds cleanly under 50MB.
