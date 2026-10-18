# Implementation Plan: Raiwall Domain 2 (Semantic Threat Detection Engine)

## Overview
Implement the **Semantic Threat Detection Engine (Core WAF)** for **Raiwall**: a SafeLine-grade, high-throughput, three-stage inspection funnel designed to eliminate false positives and stop sophisticated injection attacks with sub-microsecond lexical triage and bounded AST context verification.

The engine executes in three sequential stages:
1. **Stage 1 — Recursive Normalization & Parameter Extraction:** Multi-pass decoding of multi-layered encodings (URL, HTML entity, Base64 probe, Unicode `\uXXXX`, hex) and SQL/script comment stripping (`/**/`) via Coraza transformations until the string stabilizes. Structured extraction of JSON, multipart form text fields, and URL-encoded query/body parameters. File uploads $>1\text{ MB}$ stream directly to upstream backends.
2. **Stage 2 — Fast Lexical Triage (`libinjection-go` + Shell Metacharacters):** Pure-Go lexical token scanning in $<2\text{ µs}$ with zero CGO. Benign requests without command metacharacters pass directly to the reverse proxy. Suspicious tokens trigger Stage 3.
3. **Stage 3 — Conditional AST Context Verification (Bounded):** Inputs flagged in Stage 2 undergo multi-context synthetic grammar probing:
   - **SQLChop (`xwb1989/sqlparser`):** Synthesizes SQL statements (quoted/unquoted contexts) to detect semantic breakout (unions, stacked queries, unescaped boolean operators).
   - **CMDChop (`mvdan/sh/v3/syntax`):** Synthesizes shell commands to detect command pipelines, command substitutions (`$(...)`, backticks), and redirects.
   - **XSSChop (`tdewolff/parse/v2`):** Synthesizes HTML attributes and tag contexts to detect DOM breakout, `<script>` tags, and executable event handlers (`onerror=`).
   - **Safeguards:** Hard $32\text{ KB}$ cap per parameter (skips AST to fast lexical triage) and strict $5\text{ ms}$ parser timeout per parameter (downgrades to `ActionAudit` with reason `PARSER_TIMEOUT` to guarantee $p99 < 15\text{ ms}$).

---

## Architecture Decisions
- **Three-Stage Funnel:** Short-circuits $>90\%$ of traffic in Stage 1 & 2 ($<2\text{ µs}$), invoking heavier AST verification only for suspect parameters.
- **Pure-Go Dependencies:** All parsers (`corazawaf/libinjection-go`, `xwb1989/sqlparser`, `mvdan/sh/v3/syntax`, `tdewolff/parse/v2`, `corazawaf/coraza/v3`) are pure Go with zero CGO dependencies.
- **Multi-Context Synthetic Probing:** Injects suspect input into standard syntactic positions (quoted literal, unquoted expression, shell argument, HTML attribute) to detect whether AST node boundaries expand into executable subtrees.
- **Strict CPU Starvation Safeguards:** Hard parameter size limit ($32\text{ KB}$) and per-parameter execution deadline ($5\text{ ms}$) prevent WAF DoS / parser ReDoS. Timeouts fail-open to `ActionAudit` with log telemetry to maintain upstream SLA.
- **Seamless Caddy Provisioning:** `SemanticEngine` becomes the default engine wired into `pkg/proxy/middleware.go`, with optional Caddyfile directives (`ast_timeout`, `max_param_size`) for operator tuning.

---

## Task List Index
Tasks are tracked in `tasks/todo.md`:
- **Phase 1: Stage 1 Normalization & Parameter Extraction**
  - [x] Task 9: Recursive Normalization Engine via Coraza v3 Transformations (Size: S)
  - [x] Task 10: Structured Body Extractors & Selective Multipart Streaming (Size: M)
  - [x] *Checkpoint: Normalizer and extractors decode multi-layered evasions cleanly.*
- **Phase 2: Stage 2 Fast Lexical Triage & Shell Metacharacter Scanner**
  - [x] Task 11: Enhanced Lexical Triage with Shell Metacharacter Fast-Filter (Size: S)
  - [x] *Checkpoint: Lexical triage completes in $<2\text{ µs}$ and categorizes suspect parameters.*
- **Phase 3: Stage 3 Bounded AST Context Verification (SQL, Shell, XSS)**
  - [x] Task 12: SQLChop: Bounded SQL AST Context Verification (`xwb1989/sqlparser`) (Size: M)
  - [x] Task 13: CMDChop: Bounded Shell AST Context Verification (`mvdan/sh/v3/syntax`) (Size: M)
  - [x] Task 14: XSSChop: Bounded HTML/JS Context Verification (`tdewolff/parse/v2`) (Size: M)
  - [x] *Checkpoint: SQLChop, CMDChop, and XSSChop detect breakouts and enforce 32KB/5ms bounds.*
- **Phase 4: Funnel Orchestration, Caddy Middleware Wiring & End-to-End Validation**
  - [x] Task 15: Semantic Engine Funnel Orchestrator (Size: M)
  - [x] Task 16: Caddy Middleware Integration & Caddyfile Directives (Size: S)
  - [x] Task 17: Comprehensive End-to-End WAF Benchmark & Evasion Test Suite (Size: M)
  - [x] *Checkpoint: Domain 2 test suite passes with zero race conditions and $p99 < 15\text{ ms}$.*

---

## Risks and Mitigations
| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **AST Parser ReDoS / CPU Lockup** | **High** | Hard $32\text{ KB}$ per-param cap and $5\text{ ms}$ execution context deadline; fallback to `ActionAudit`. |
| **False Positives on Complex SQL/JSON in API Payloads** | **Medium** | AST context verification checks for breakout outside literal nodes rather than blocking raw keywords. |
| **High Memory Allocation during Recursive Normalization** | **Medium** | Max 10 normalization passes; reuse string buffers and skip decoding when string stabilizes. |
| **Streaming Disruption on Large File Uploads** | **High** | Payloads $>1\text{ MB}$ stream directly to upstream; multipart parsing inspects only non-file text form fields. |

---

## Open Questions & Future Work
- **Frontend & Control Plane Phase (Domains 6 & 7):** Per alignment decision, the Control Plane (Huma v2 OpenAPI 3.1 REST API + SQLite WAL via sqlc) and embedded Frontend Dashboard (`web/` in Vue 3, TypeScript, Vite, Tailwind CSS, shadcn-vue, Pinia, ECharts, Globe.gl embedded via `go:embed`) will be scaffolded immediately following Domain 2 completion, binding directly to the stable threat detection engine.
- **Domain 3 Hand-off:** Active Bot Defense (JA4 TLS fingerprinting, HTTP 468 PoW challenges, Altcha/Anubis, and API fast-path bypass).
