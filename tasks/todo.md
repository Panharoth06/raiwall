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
