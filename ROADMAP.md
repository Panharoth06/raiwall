# Raiwall Enterprise Roadmap

Living document. Last updated: **2026-10-31** (commit `c4af3e8`).

This is the authoritative roadmap for turning Raiwall into an enterprise-grade,
self-hosted WAF. It records the current capability matrix, the gap-closure
phases, architecture decisions, and the verification gates each phase must pass.
The actionable checklist lives in [`TASKS.md`](TASKS.md).

> `tasks/plan.md` and `tasks/todo.md` are historical SafeLine-parity planning
> notes and no longer describe the repository. Use this file and `TASKS.md`.

---

## 1. Context and Goals

Raiwall is a Caddy v2 data plane plus an embedded Vue control plane, shipped as
one binary. The request-inspection core is real, but the marketed scope is
ahead of what ships, and several gaps block enterprise deployment.

Goals, in confirmed priority order:

1. **Detection & rule engine** — production-grade rules, OWASP CRS
   compatibility, anomaly scoring, response inspection.
2. **Observability & compliance** — SIEM export, audit trail, retention,
   compliance reports, PII controls.
3. **Deployment** — single-node Docker and Kubernetes HA.
4. **Truthfulness** — documentation and claims must match the code.

### Status legend

| Status | Meaning |
| :--- | :--- |
| **Full** | Production-wired and covered by tests |
| **Partial** | Works with material limits |
| **Stub** | Scaffolding or dead configuration |
| **Absent** | Not implemented |

Size: **S** days, **M** 1–3 weeks, **L** 3–6 weeks, **XL** 6+ weeks.
Priority: **P0** blocks enterprise use, **P1** major capability, **P2** maturity.

---

## 2. Current State (commit `c4af3e8`)

### Implemented

- Caddy hot-swap snapshots, SQLite/PostgreSQL control stores with versioned
  migrations, encrypted certificate store, draft/apply/rollback.
- Custom semantic WAF: multi-pass normalizer, libinjection triage, bounded
  SQL/shell/HTML verification, 14-module matrix, 87 CVE virtual patches,
  parameter-level exceptions.
- **OWASP CRS 4.30 via Coraza** for inbound request rules: PL1–4, anomaly
  scoring, audit/block modes, matched-rule and score telemetry.
- Three-tier rate limiting, waiting room, PoW (HTTP 468), BART CIDR and `expr`
  ACLs, GeoIP, honeypot.
- Forensic ring buffer, PII masking, SSE telemetry, Prometheus metrics,
  Slack/Discord/Telegram/webhook alerts.
- Envoy `ext_proc` sidecar (wire format corrected), MCP server, rule-test API,
  Docker Compose, Helm chart.
- Phase 0 security batch: authenticated telemetry/metrics/SSE, bounded-prefix
  body inspection with gzip/deflate/brotli decoding, trusted-proxy client IP
  handling, per-site auth bypass closed.

### Hard blockers still open

1. Distributed bans are not hydrated/enforced across replicas; cluster status
   is hardcoded (`rate/ban.go`, `http/handlers_system.go`).
2. Configuration changes do not propagate to other replicas.
3. ClickHouse telemetry is non-functional (no schema init, no pruning, missing
   columns, broken event lookup).
4. Response inspection is a no-op; CRS response rules are disabled until paired
   request/response transactions exist.
5. Upstream health checks never start; WebSocket/gRPC upstream proxying and
   PROXY protocol are incomplete.
6. JA4 is header-derived, not captured from the TLS handshake.
7. Operator identity is password-only: no SSO/MFA, admin user CRUD, session
   revocation, CSRF, or login lockout.
8. No administrative audit log, SIEM export, compliance reports, backup/restore,
   or license.
9. Documentation still claims Coraza normalization, TiDB/mvdan/tdewolff ASTs,
   Huma, Shoutrrr, Ristretto, 193 CVEs, and HA that the code does not provide.
10. The documented `/api/v1` base is not routed in production; only
    `/.raiwall/api/...` reaches the control plane. The chi aliases exist but are
    unreachable through the Caddy dispatcher.

---

## 3. Enterprise Feature Matrix

### 3.1 Detection & Rule Engine (priority 1)

| Feature | Status | Priority | Gap |
|---|---|---|---|
| libinjection lexical triage | Full | — | — |
| Semantic detectors (SQLi, XSS, CmdI, LFI, SSTI, SSRF, deser, code inj, CSRF) | Partial | P1 | Custom heuristics, not full parsers |
| Bounded AST verification | Partial | P1 | Hand-written tokenizers; no TiDB/mvdan/tdewolff |
| Recursive normalizer | Partial | P1 | No Base64/XML normalization; decompression now handled at body intake |
| **OWASP CRS / SecRule compatibility** | **Partial** | **P0** | Inbound request rules PL1–4 work; response rules, per-app policy, exclusions, and go-ftw parity pending |
| **Anomaly scoring + paranoia levels** | **Partial** | **P0** | Engine + telemetry done; per-app policy and UI pending |
| Custom operator signatures | Absent | P1 | Only bundled CRS/CVE rules can be toggled |
| CVE virtual patches | Partial | P1 | 87 rules; `Signature.Prefix` unused; method index bug |
| Rule catalog / test playground | Partial | P1 | `/rules/test` API done; catalog, UI, go-ftw harness pending |
| False-positive exceptions | Partial | P1 | Semantic rules only; CRS exclusion translation pending |
| Response inspection / DLP | Absent | P1 | `InspectResponse` always allows |
| XML/XXE, GraphQL, OpenAPI schema validation | Absent | P1 | Not implemented |
| Request decompression / Base64 normalization | Partial | P1 | gzip/deflate/br inspection done; Base64 normalization pending |
| Multipart content/magic/AV inspection | Partial | P1 | Extension checks only |
| HTTP smuggling / protocol validation | Stub | P1 | Go `net/http` normalizes before the detector |
| WebSocket / gRPC upstream proxying | Stub | P1 | No hijack/trailers/h2c |
| PROXY protocol v1/v2 | Absent | P2 | — |
| mTLS / client certificates | Absent | P1 | — |
| TLS policy / scheduled renewal | Partial | P1 | Min version only; renewal at startup/deploy |
| Upstream LB | Full | — | SWRR, least_conn, ip_hash, primary/backup |
| Active health checks, retries, failover | Stub | P0 | `StartHealthChecks` has no production caller |
| Client IP trust | Partial | P0 | Fixed: socket default + `trusted_proxies`; handshake JA4/PROXY pending |
| JA4 / JA4H / HTTP/2 fingerprinting | Stub | P0 | Client-supplied headers; handshake capture unwired |

### 3.2 API Security

| Feature | Status | Priority | Gap |
|---|---|---|---|
| API vs browser route classification | Full | — | — |
| API inventory / discovery | Partial | P2 | Passive catalog only |
| JWT / bearer validation at the gateway | Absent | P1 | Only app-gate OIDC |
| OpenAPI schema enforcement (BOLA/BFLA) | Absent | P1 | — |
| Per-consumer/API-key rate limits | Absent | P1 | — |
| GraphQL depth/complexity | Absent | P1 | — |
| Control-plane API key scopes | Partial | P1 | Role validated now; scopes/tenant pending |

### 3.3 Bot, DDoS & Rate Limiting

| Feature | Status | Priority | Gap |
|---|---|---|---|
| PoW (Altcha, 468), clearance cookie, honeypot | Full | — | — |
| Bot classification (UA + JA4) | Partial | P1 | JA4 spoofable; some signature keys invalid |
| Verified bots / CAPTCHA providers | Absent | P2 | — |
| Behavioral/ML bot detection | Absent | P2 | — |
| Three-tier rate limiting | Partial | P1 | Global config; Tier 2 misses ACL/feed blocks |
| Per-host rate/bot policies | Stub | P1 | Compiled but unused |
| Waiting room | Partial | P1 | Single-node; capacity policy ignored |
| Distributed bans | Absent | P0 | Local-only `IsBanned`; no hydration/pub-sub |
| Threat feeds / IP reputation | Partial | P1 | File CIDR lists only |
| Adaptive rate limiting | Absent | P2 | — |
| Slowloris/connection limits | Partial | P2 | Relies on Caddy timeouts |

### 3.4 Observability (priority 2)

| Feature | Status | Priority | Gap |
|---|---|---|---|
| Prometheus metrics | Partial | P0 | Six metrics, now authenticated; no per-site/rule labels |
| SSE + forensic search + incidents + cURL replay | Partial | P0 | Now authenticated; full mode/score/rule metadata persisted |
| Alerting | Partial | P1 | Slack/Discord/Telegram/webhook; no CRUD/test/history/retry |
| OpenTelemetry tracing | Absent | P1 | — |
| Syslog RFC5424 / CEF / LEEF | Absent | P1 | — |
| SIEM connectors (Splunk/Sentinel/Elastic) | Absent | P1 | — |
| ClickHouse analytics / retention | Partial | P0 | Schema init, retention worker, full columns and direct lookup repaired; live cluster integration pending |
| SQLite/PG retention | Full | — | — |
| Dashboards / attack map | Full | — | — |
| Per-site/rule/upstream metrics | Absent | P1 | — |

### 3.5 Compliance, Audit & Data Protection (priority 2)

| Feature | Status | Priority | Gap |
|---|---|---|---|
| Administrative audit log | Absent | P1 | Only app end-user auth events |
| Tamper-evident log / hash chain | Absent | P1 | — |
| WORM export / legal hold | Absent | P1 | — |
| Compliance reports (PCI/SOC2/GDPR) | Absent | P1 | — |
| PII/PCI masking | Partial | P1 | Request + response data now sanitized; audit/export pending |
| Secrets management (Vault/KMS/HSM) | Absent | P1 | Cert key co-located with ciphertext |
| IdP secret redaction | Absent | P0 | Viewers can read provider secrets |
| Retention UI / per-tenant policy | Absent | P2 | — |
| SBOM / image signing / CVE scan | Absent | P1 | No CI |
| LICENSE / notices | Absent | P0 | README contradiction |
| Docs truthfulness / status matrix | Partial | P0 | This roadmap; README/AGENTS de-claim still pending |

### 3.6 Identity, RBAC & Multi-Tenancy

| Feature | Status | Priority | Gap |
|---|---|---|---|
| Local operator login | Full | — | Default `admin/admin` still shipped |
| Operator SSO (OIDC/SAML/SCIM) | Absent | P1 | App end-users only |
| Operator MFA/TOTP | Absent | P1 | — |
| Admin user CRUD / session revoke | Absent | P1 | — |
| Session security (Secure, CSRF, revocation, idle expiry) | Partial | P0 | Stateless HMAC cookie |
| Login rate limit / lockout | Absent | P0 | — |
| RBAC roles/permissions/scopes | Partial | P1 | admin/viewer only; method-based |
| Multi-tenancy | Absent | P1 | No tenant model |
| Admin listener isolation (mTLS/IP allowlist) | Absent | P1 | Admin UI/API on public listeners |
| Secret keyring / rotation | Absent | P1 | — |

### 3.7 HA, Operations & Deployment

| Feature | Status | Priority | Gap |
|---|---|---|---|
| Config snapshots/apply/rollback | Full | — | Auto-apply on save (opt-out); shallow diff; rollback not audited |
| Multi-replica config propagation | Absent | P0 | Publisher only in tests |
| Cluster status/health | Stub | P0 | Hardcoded standalone |
| Redis client AUTH/TLS/Sentinel/Cluster | Absent | P1 | Hand-rolled RESP |
| Leader election / apply lock | Absent | P1 | — |
| Shared certificate storage | Absent | P1 | File-system, RWO PVC |
| Distributed rate limiting | Partial | P1 | Redis Lua path exists |
| Distributed waiting room | Absent | P2 | — |
| Backup / restore / DR | Absent | P1 | — |
| Version/upgrade surface | Partial | P1 | CLI version only |
| Helm HA (HPA, PDB, anti-affinity, NetworkPolicy) | Partial | P1 | Replica 1, PDB off |
| Air-gapped install | Absent | P2 | Dashboard loads Google Fonts |
| CI/CD, SBOM, signing | Absent | P1 | — |
| Single-node Docker | Full | — | — |

### 3.8 Ecosystem & Integrations

| Feature | Status | Priority | Gap |
|---|---|---|---|
| Envoy `ext_proc/v3` sidecar | Partial | P0 | Wire format fixed; conformance test pending |
| MCP tools | Partial | P2 | One tool returns fake events |
| Webhooks / SOAR | Partial | P1 | Generic alert webhook only |
| SIEM/SOAR connectors | Absent | P1 | — |
| STIX/TAXII threat feeds | Absent | P2 | — |
| Terraform provider / K8s operator | Absent | P2 | — |
| SAML / SCIM | Absent | P2 | — |

---

## 4. Roadmap

### Phase 0 — Stop the Bleeding (2–3 weeks, ~8–10 EW)

| ID | Deliverable | Targets | Size | Status |
|---|---|---|---|---|
| 0.1 | Authenticate telemetry/metrics/SSE/incidents/cURL; remove wildcard CORS and query-string credentials | `caddy/stage_routes.go`, `http/telemetry_api.go`, `http/streamer.go`, `http/middleware.go` | M | **Done** `13e8678` |
| 0.2 | Bounded-prefix body inspection, gzip/deflate/brotli decode with bomb cap, pooled-buffer race fix, sidecar parity | `caddy/body_inspector.go`, `caddy/stage_waf.go`, `grpc/processor.go`, `core/waf/bodyinspect` | L | **Done** `13e8678` |
| 0.3 | HA state: ban hydration, OnBan publish, snapshot propagation + poll, real cluster status, Redis AUTH/TLS | `core/rate/ban*.go`, `storage/redis/*`, `http/snapshots_apply.go`, `http/handlers_system.go` | L | **Done** (in-process two-replica convergence; live Sentinel/Cluster in 4.1) |
| 0.4 | ClickHouse: InitSchema, pruning, full columns (incl. CRS metadata), indexed event lookup | `storage/clickhouse/*`, `storage/registry.go` | M | **Done** (unit-tested; add live cluster integration in Phase 4) |
| 0.5 | Envoy ext_proc field numbers + wire-format regression test | `grpc/proto_types.go` | M | **Done** `13e8678` |
| 0.6 | Close per-site auth bypass; validate bearer/API-key claims | `core/auth/appgate.go`, `caddy/stage_auth_gate.go` | M | **Done** `13e8678` |
| 0.7 | Client IP trust, trusted proxies, handshake JA4, PROXY protocol | `caddy/client_ip.go`, `core/bot/ja4.go`, new listener | M/L | **Partial** (`13e8678`: client IP; JA4/PROXY pending) |
| 0.8 | Start health checks, retries/timeouts/failover, WebSocket-capable proxy | `caddy/upstream.go`, `caddy/forwarding.go`, `caddy/proxy.go` | M | **Partial** (gRPC trailers deferred to 1B.5) |
| 0.9 | Audit verdicts reach telemetry; response data sanitization | `caddy/stage_waf.go`, `caddy/stage_response.go`, `core/telemetry/sanitizer.go` | S/M | **Done** `13e8678` |
| 0.10 | Secure/revocable sessions, login lockout, default-credential refusal, docs de-claim, LICENSE/SECURITY/CI | `http/auth.go`, `README.md`, `.github/` | M | **Partial** (sessions/lockout/defaults/docs done; LICENSE/SECURITY/CI pending) |

**Exit gate:** every P0 security test passes; no unauthenticated telemetry;
oversize/gzip/chunked tests pass under `-race`; two replicas converge on bans
and config; ClickHouse schema/query tests pass; Envoy blocks/continues real
traffic; app-auth bypass tests pass; audit-mode events appear; docs match code.

### Phase 1 — Detection & Rule Engine (16–20 weeks, ~40–50 EW; priority 1)

#### 1A CRS core (6–8 weeks)

| ID | Deliverable | Targets | Size | Status |
|---|---|---|---|---|
| 1A.1 | Embed Coraza v3 + OWASP CRS 4.x behind `WAFEnginePort`; compiled policy cache | `core/waf/crs/*`, `core/waf/ports.go` | XL | **Done** `aaa12f3` |
| 1A.2 | Composite engine + extended verdict + event schema/storage | `core/waf/composite.go`, `core/telemetry/event.go`, SQLite/PG/CH schemas | M | **Done** (`aaa12f3`, `34ea459`, `5d14d49`) |
| 1A.3 | Per-site detection policy: CRS off/audit/block, PL1–4, thresholds; API + UI + runtime selection | `core/control/models.go`, `compiler.go`, `http/detector.go`, `caddy/provision_crs_policies.go`, `web/` | M | **Done** (`8557bf7` API/UI; runtime cache now) |
| 1A.4 | Exception → CRS exclusion translation; rule catalog/tags/severity; dry-run effects | `core/acl/exception.go`, `core/waf/crs/exceptions.go`, `http/exceptions_test_run.go` | M | **Done** |
| 1A.5 | Rule test playground + go-ftw harness | `http/rules.go`, `tests/crs/` | M | **Done** (`34ea459` API, `5d14d49` UI; harness + CI gate now) |
| 1A.6 | Performance: semantic-first, static exclusions, body pre-caps, benchmarks | `caddy/stage_waf.go`, `core/waf/benchmark_test.go` | M | **Pending** |

#### 1B Detection depth (10–12 weeks)

| ID | Deliverable | Targets | Size | Status |
|---|---|---|---|---|
| 1B.1 | Response inspection + DLP/redaction | `caddy/stage_response.go`, `core/waf/response/dlp.go` | L | **Pending** |
| 1B.2 | Base64/hex/JSON-in-JSON normalization; body-prefix policy | `core/waf/normalizer/*`, `caddy/body_inspector.go` | M | **Pending** |
| 1B.3 | XML/XXE, GraphQL depth/complexity, OpenAPI schema validation | new `core/waf/{xmlinspect,graphql}.go`, `core/api/openapi_validate.go` | L | **Pending** |
| 1B.4 | Multipart magic-byte/polyglot + AV hook (ClamAV/ICAP) | `core/waf/detectors_http.go`, `adapters/outbound/av` | M | **Pending** |
| 1B.5 | Raw-front smuggling, WebSocket/gRPC upstreams, client mTLS, PROXY protocol | `caddy/forwarding.go`, listeners, `grpc/` | L | **Pending** |
| 1B.6 | Activate per-host rate/bot policies, complete CVE rules to 193, fix prefix/method index, threat feeds, JA4 reputation | `core/rate/*`, `core/bot/*`, `core/waf/cve/*` | L | **Pending** |

**Exit gate:** go-ftw thresholds (100% applicable PL1 critical, ≥95% overall,
documented skips); anomaly/PL golden tests; DLP block/redact; XML/GraphQL/OpenAPI
corpora; WS/gRPC/PROXY/mTLS; no uninspected body path; CRS PL1 p99 ≤ 1.5 ms for
1 KB bodies.

### Phase 2 — Observability & Compliance (10–14 weeks, ~25–30 EW; priority 2)

| ID | Deliverable | Targets | Size |
|---|---|---|---|
| 2.1 | OTel traces (request, WAF phases, upstream, response), OTLP export, sampling | `core/observability/tracing.go`, `caddy/pipeline.go` | M |
| 2.2 | SIEM pipeline: RFC5424, CEF, LEEF, Splunk HEC, Sentinel DCR, Elastic, spool/retry | `adapters/outbound/siem/*` | L |
| 2.3 | Admin audit log: append-only, hash chain, Ed25519 anchors, verify API, server-derived actor | `core/control/audit_*.go`, `storage/*/control_audit*.go`, migration `0014`/`0015` | L | **Done** (hash chain + retention floor + Ed25519 anchors + `/audit/verify` + UI) |
| 2.4 | Retention, legal hold, WORM (S3 Object Lock), prune UI, ClickHouse TTL | `storage/*`, `adapters/outbound/audit/s3worm.go` | L | **Partial** (snapshot/session/audit retention worker; UI/hold/WORM pending) |
| 2.5 | Reports: CSV/JSON, printable HTML, PCI/SOC2/GDPR evidence mappings | `core/reports/*`, `http/reports.go` | L |
| 2.6 | Alerting: CRUD, test-send, delivery history, retry/backoff, dedupe | `adapters/outbound/alerts/*`, `web/` | M |
| 2.7 | Telemetry/DLP completeness, ClickHouse dashboards, per-site/rule metrics | `core/telemetry/*`, `web/` | M |

**Exit gate:** OTel end-to-end trace; SIEM outage/replay; audit tamper detection;
legal-hold/WORM/prune drill; report reconciliation; alert retry/history.

### Phase 3 — Enterprise Control Plane (8–12 weeks, ~22–26 EW)

| ID | Deliverable | Targets | Size |
|---|---|---|---|
| 3.1 | DB-backed sessions, idle/absolute expiry, revocation, CSRF, `__Host-` cookie, lockout | `core/control/sessions.go`, `http/auth.go` | M | **Done** |
| 3.2 | Operator OIDC (state/nonce/PKCE, group→role) + TOTP/recovery codes | `http/auth_oidc.go`, `auth_totp.go` | M |
| 3.3 | Permission-based RBAC (admin/operator/analyst/viewer/auditor), scoped API keys, user CRUD/UI | `http/rbac.go`, `web/` | L | **Partial** (operator CRUD/UI done; five-role matrix and scoped keys pending) |
| 3.4 | Secret keyring (AES-GCM key IDs, Vault Transit, cloud KMS), write-only fields | `core/crypto/keyring.go`, `adapters/outbound/secrets/*` | M |
| 3.5 | Multi-tenancy: `tenant_id` row scoping, tenant stores, quotas, migrate to `default` | all stores, `http/tenants.go` | L |
| 3.6 | Separate admin listener with mTLS/IP allowlist | `caddy/stage_routes.go`, Helm | S/M | **Partial** (CIDR allowlist + public_url redirect gate; split listener pending) |

**Exit gate:** five-role authz matrix; OIDC/TOTP e2e; session/CSRF/lockout;
scoped keys; tenant isolation; no plaintext secrets; admin mTLS.

### Phase 4 — HA & Kubernetes (10–12 weeks, ~22–27 EW)

| ID | Deliverable | Targets | Size |
|---|---|---|---|
| 4.1 | Replace hand-rolled RESP with `go-redis/v9`; AUTH/TLS/Sentinel/Cluster | `storage/redis/*` | M |
| 4.2 | Leader election/apply lock (PG advisory lock or fenced Redis lease) + convergence | `http/snapshots_apply.go`, `core/control/*` | M |
| 4.3 | Shared certificate storage (S3/Consul), KMS-wrapped certs, startup guard | `caddy/tls_provider.go` | M |
| 4.4 | Distributed waiting room (Redis Lua, stateless signed tokens) | `core/rate/waitingroom*.go` | M |
| 4.5 | Helm HA: 3 replicas, PDB, topology spread, HPA, NetworkPolicy, migration Job, probes | `deploy/helm/raiwall/*` | L |
| 4.6 | Backup/restore CLI + CronJob, documented RTO/RPO and drill | `cmd/raiwall/backup.go`, Helm | L |
| 4.7 | Version/upgrade surface, migration preflight, N-1 upgrade/rollback | `cmd/raiwall`, `http/handlers_system.go` | M |
| 4.8 | K8s e2e/chaos: leader kill, Redis failover, node drain, partition | `tests/k8s`, CI | M |

**Exit gate:** three-replica convergence <5 s; no split-brain apply; shared cert
issuance; failover during apply; restore drill; zero-downtime rolling upgrade.

### Phase 5 — Ecosystem & Distribution (6–8 weeks, ~14–20 EW)

| ID | Deliverable | Targets | Size |
|---|---|---|---|
| 5.1 | CI/CD: lint, gosec, govulncheck, race, integration, CRS, web, kind e2e, release | `.github/workflows/*` | M |
| 5.2 | Supply chain: Syft SBOM, cosign, SLSA provenance, Trivy, distroless | `Dockerfile*`, release workflow | M |
| 5.3 | Air-gap: self-hosted fonts, signed CRS/GeoIP bundles, offline validation | `web/index.html`, `scripts/` | S/M |
| 5.4 | Docs/API truth: `STATUS.md`, architecture/ops/security/upgrade docs, 84/84 OpenAPI | `docs/*`, `http/openapi.go` | M |
| 5.5 | License decision + notices (Apache-2.0 recommended) | `LICENSE`, `NOTICE` | S |
| 5.6 | Optional: SAML/SCIM, SOAR webhooks, Terraform provider | new adapters | L |

**Exit gate:** required CI green; SBOM/signature verification documented;
air-gap install with egress blocked; docs review sign-off.

---

## 5. Architecture Decisions

### ADR-1 — CRS compatibility: embed Coraza
Add `github.com/corazawaf/coraza/v3` and embed OWASP CRS. Implement `crs`
behind `WAFEnginePort` and compose it with the semantic engine. Semantic runs
first; CRS runs only if semantic allows. Any block wins; audit verdicts surface.
CRS performs its own transformations — do not pre-normalize its input. Compile
one WAF instance per unique policy (PL, thresholds, exclusions). Rejected:
in-house SecRule interpreter, CGO ModSecurity, per-request external Coraza.

### ADR-2 — Response inspection & DLP
Buffer inspectable responses to 1 MiB (hard cap 8 MiB); always inspect headers;
skip SSE/101/204/304/media and compressed bodies unless decompression is on.
Block only before the first flush; after flush, downgrade to audit. DLP uses
Luhn PAN, secrets, JWT/private-key scanners; actions block/redact/audit; never
store raw secrets. Implement in `stage_response.go` before `interceptor.Finish()`.

### ADR-3 — Observability, SIEM, audit
OTel SDK with OTLP exporters; spans for request/WAF/upstream/response; W3C
propagation; sampling forced for blocked/errored requests. SIEM adapters for
RFC5424, CEF, LEEF, Splunk HEC, Sentinel DCR, Elastic with bounded spool and
at-least-once retry keyed by `event_id`. Audit log is separate from forensics:
append-only with `seq`, server-derived actor, before/after hashes, `prev_hash`,
`entry_hash`, and Ed25519 anchors; export to S3 Object Lock. Reports are
snapshots whose hash is recorded in the audit log.

### ADR-4 — HA state
PostgreSQL is the source of truth. On apply: commit a monotonic version + hash,
publish, subscribers fetch/verify/swap, with a 10–15 s DB poll fallback and
stale-version rejection. PG advisory lock (or fenced Redis lease) for apply.
Hydrate bans from Redis at startup, publish ban/unban, reconcile periodically.
Shared cert storage (S3/Consul) with distributed locking; fail fast if
`replicas > 1` without shared storage. Distributed waiting room via Redis Lua
and stateless signed tokens. SQLite remains single-node.

### ADR-5 — Identity, RBAC, tenancy
Opaque 256-bit sessions stored hashed, idle/absolute expiry, revocation,
`__Host-` Secure HttpOnly cookie, rotation on login/privilege change,
double-submit CSRF. Operator OIDC + TOTP. Permissions as `resource:verb` with
five roles; API keys carry scopes, expiry, tenant, validated role. Keyring with
AES-GCM key IDs and Vault/KMS providers; secret fields write-only. Row-scoped
`tenant_id`; no schema-per-tenant. Separate admin listener with mTLS/IP allowlist.

---

## 6. Verification & Acceptance

### Per-phase gates

| Phase | Must pass |
|---|---|
| 0 | Telemetry/metrics/SSE/curl authz; no wildcard CORS; spoofed IP/JA4 rejected; oversize/gzip/chunked `-race`; 2-replica ban/config convergence; ClickHouse schema/query; Envoy block/continue e2e; app-auth bypass tests; audit events; docs match code |
| 1 | go-ftw thresholds; anomaly/PL golden tests; exceptions; response DLP; XML/GraphQL/OpenAPI corpora; WS/gRPC/PROXY/mTLS; smuggling; CVE count/index; perf gates |
| 2 | OTel trace; SIEM encoders/outage replay; audit tamper detection; legal-hold/WORM/prune; report reconciliation; alert retry/history |
| 3 | Five-role authz matrix; OIDC/TOTP e2e; session/CSRF/lockout; scoped keys; tenant isolation; no plaintext secrets; admin mTLS |
| 4 | 3-replica convergence; leader kill during apply; Redis failover; shared certs; waiting room; N-1 upgrade; restore drill |
| 5 | Required CI; SBOM/signature verification; Trivy no critical; air-gap egress-blocked install; docs/API completeness; license/notices |

### CRS harness
`tests/crs/` runs go-ftw against a Compose fixture with Raiwall in front of the
CRS test backend. Nightly + on rule/config change. Thresholds: 100% of
applicable PL1 critical tests, ≥95% overall, every skip documented. Add golden
tests at PL1/PL2/PL4 and `/api/v1/rules/test` (done).

### Security suite
Telemetry authz; untrusted forwarded headers/JA4 ignored; oversize/gzip/chunked
bodies under `-race`; Base64 SQLi; app-auth bypass vectors; admin authz
(CSRF/session revoke/key scope/tenant crossover); audit chain tamper; IdP
secrets never returned.

### Performance gates
Semantic p99 regression ≤5%; CRS PL1 incremental p99 ≤1.5 ms for 1 KB bodies;
no per-request rule compilation; body memory bounded (concurrency × cap),
1k RPS × 1 MB for 1 h with no growth; response inspection ≤0.5 ms skipped and
≤2 ms for 1 MB HTML; 24 h soak with no goroutine/heap growth.

### Enterprise definition of done
No unauthenticated data-plane/admin surface; no client-trusted identity; secrets
KMS/Vault-backed; signed images + SBOM; CRS thresholds met; OpenAPI complete;
N-1 upgrade tested; 3-replica HA with failover and restore drill; OTel/SIEM/
audit/alerts operational; hash-chained audit + WORM + legal hold + compliance
reports; RBAC/access review; `STATUS.md` matches code and all de-claimed items
removed.

---

## 7. Risks, Non-Goals & De-Claiming

### Top risks

| Risk | Mitigation |
|---|---|
| Coraza conflicts with Caddy's pinned deps | Replaces removed; upgrade Caddy if needed; external ext_proc fallback |
| CRS false positives | PL1 audit default, exception workflow, per-site PL, staged enforcement |
| Response buffering latency/memory | Caps, content-type allowlist, streaming skips, load tests |
| Redis becomes a SPOF | Local ban/rate fallback, Sentinel, timeouts/circuit breaker |
| Multi-tenancy schema churn | Add `tenant_id` early in Phase 1 migrations |
| Fail-closed body limits break uploads | Configurable max, per-site overrides, 413 + docs, deprecation window |
| Auth hardening breaks scripts | Migration guide, token provisioning UI, dev-only legacy mode |
| SafeLine parity/trademark claims | Remove parity claims; describe Raiwall behavior only |

### Non-goals (current)
In-house SecRule interpreter; full SIEM/UEBA; L3/L4 scrubbing; antivirus
engine (integrate ClamAV/ICAP); multi-region active-active; SQLite HA;
schema-per-tenant; SAML/SCIM before Phase 5; PDF before CSV/JSON/HTML; Windows
containers; raw HTTP/2 frame smuggling beyond the front proxy.

### Documentation de-claim list (Phase 0/5)
| Current claim | Reality | Action |
|---|---|---|
| Coraza normalizer / Coraza stack | CRS now real; normalization remains custom | State Coraza for CRS rules only |
| TiDB / `mvdan/sh` / `tdewolff/parse` ASTs | Hand-written tokenizers | Say “custom bounded tokenizers” |
| 193 CVE inner rules | 87 | Correct now; complete in 1B.6 |
| Huma OpenAPI 3.1 | chi + hand-written partial spec | Say “OpenAPI 3.1 (partial)” |
| Shoutrrr alerts | Native Slack/Discord/Telegram/webhook sender | Describe native sender |
| Ristretto rate limiter | Not used | Remove |
| Redis cluster sync | Wired (0.3) | Live Sentinel/Cluster in 4.1 |
| Globe.gl / shadcn-vue | Custom router / radix-vue | Correct |
| JA4 TLS fingerprinting | Header-derived | Mark planned until 0.7 |
| Enterprise-grade / HA | Replica 1, PDB off, RWO | Publish `STATUS.md`; pre-GA language |
| SafeLine parity | Research only | Remove trademark/parity claims |
| Zero-trust app auth | Fixed in `13e8678` | Publish advisory in release notes |

### Backward compatibility
Additive JSON/DB fields first; forward-only migrations with backup; keep old API
paths. Legacy unauthenticated telemetry/CORS become dev-only flags with warnings
and are removed after one minor release. Oversized bodies default to 413 with a
temporary `inspect_prefix` mode. Preserve `SEMANTIC_*`/`CVE-*` rule IDs; new CRS
IDs use `CRS:<id>`. Semantic engine stays as a secondary engine. SQLite remains
single-node; multi-replica requires PostgreSQL + Redis + shared cert storage.

---

## 8. Progress Log

| Commit | Scope |
|---|---|
| `035a822` | WAF hardening: comment truncation/fusion, overlong UTF-8, tokenizer DoS, Windows binaries |
| `68e40b4` | Strong SSTI/SSRF/deserialization signals, unquoted tautology, raw-text XSS |
| `13e8678` | Phase 0 security: telemetry auth, body prefix/decompression, Envoy wire format, app-auth bypass, client IP/trusted proxies, audit telemetry, response sanitization |
| `aaa12f3` | Phase 1A.1: Coraza + OWASP CRS 4.30, composite engine, CRS config |
| `34ea459` | Phase 1A.2/1A.5: CRS event metadata (SQLite/PG), rule-test playground, matched-rule filtering |
| `5d14d49` | ClickHouse repair (schema/retention/columns/lookup), Rule Tester UI, CRS metadata in the forensic drawer, viewer write-action guard, mock Command Center removed |
| `e671812` | Instant configuration apply: `control.auto_apply`, server-side snapshot commit after mutations with buffered failure responses, cluster version publish, `GET /status` flag, Deployments UI notice/retry, full E2E suite re-aligned |

## 9. Change Control

- Update this file whenever phase scope or status changes; keep `TASKS.md` in sync.
- Every completed task must reference its commit and the gate evidence.
- Do not mark a phase complete until its exit gate is satisfied end-to-end
  (Docker + Kubernetes where applicable).
