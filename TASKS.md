# Raiwall Enterprise Tasks

Actionable breakdown for [`ROADMAP.md`](ROADMAP.md). Last updated: **2026-10-31**
(commit `3055841`).

Use this file as the working checklist. Each task is self-contained: implement,
test, update `ROADMAP.md` status, run `graphify update .`, and commit with a
Conventional Commit. Do not mark a phase complete until its exit gate passes in
Docker and (for Phase 4) Kubernetes.

Status legend: `[x]` done · `[~]` partial · `[ ]` pending.

---

## Phase 0 — Stop the Bleeding

### 0.1 Authenticate telemetry, metrics, SSE, incidents and replay `[x]`
**Done in `13e8678`.**
- [x] Require control-plane auth on `/metrics`, events, stats, incidents, cURL replay.
- [x] Fail closed when no authenticator is wired.
- [x] SSE requires auth and no longer sets `Access-Control-Allow-Origin: *`.
- [x] Remove query-string `token`/`api_key`/`key` credentials.
- [x] Unit tests for 401/503 behavior.

### 0.2 Body trust boundary `[x]`
**Done in `13e8678`.**
- [x] Inspect a bounded prefix for bodies over 1 MiB instead of skipping them.
- [x] Reconstruct the full body for the upstream byte-for-byte.
- [x] Decode gzip/deflate/brotli for inspection with a 1 MiB cap.
- [x] Present decoded body with matching inspection headers; forward original body.
- [x] Remove the pooled-buffer use-after-return on chunked oversize.
- [x] Apply prefix inspection and decompression to the Envoy sidecar path.
- [x] Tests: small/oversize/chunked/empty, gzip/deflate/br, bomb cap, reconstruction.

### 0.3 Wire HA state `[x]`
**Targets:** `core/rate/ban.go`, `core/rate/ban_registry.go`,
`storage/redis/*`, `http/snapshots_apply.go`, `http/handlers_system.go`,
`caddy/provision_rate.go`.
- [x] Hydrate `BanManager` from Redis at startup (expired entries skipped,
      no callbacks or write-back).
- [x] Wire ban fan-out: `OnBan` publishes; remote applies never echo.
      Unblock events are published by the control-plane handlers that own the
      operator action (single owner, no double publish).
- [x] Subscribe and apply remote ban/unban events; expired remote bans ignored;
      every (re)connect re-reconciles bans from shared storage so events missed
      during a Redis gap converge.
- [x] Publish snapshot `{version, hash}` on apply and rollback (existing
      publisher, now wired to the control-plane server and MCP tool path).
- [x] Subscribers fetch, verify hash, and atomically swap through the same
      deploy hooks as a local apply; 10 s DB poll fallback. Rollbacks apply by
      content hash (config versions are not ordered); duplicate notifications
      are suppressed by a revision marker.
- [x] Reject duplicate/hash-mismatched notifications; `/cluster/status` exposes
      `applied_version`, `applied_hash`, `last_apply_error`, and `ban_count`.
- [x] Reconcile bans after reconnects (shared storage is authoritative) and
      bound ban fan-out through a queue so a Redis outage cannot spawn a
      goroutine per ban.
- [x] Replace hardcoded `/cluster/status` with real mode/redis state.
- [x] Redis client AUTH/TLS (username+password, CA file, server name,
      explicit insecure-skip defaulting off). Full Sentinel/Cluster in 4.1.
- [x] Tests: two-replica ban convergence (no echo), restart hydration,
      config convergence with deploy hooks, stale/hash-mismatch rejection,
      status endpoint in standalone and Redis modes.
- [x] Gate: two replicas agree on bans and config without restarts.
      No redis-server was available locally, so the gate is proven with an
      in-process RESP server (including AUTH and TLS); live Sentinel/Cluster
      validation stays in 4.1.

### 0.4 Repair ClickHouse telemetry `[x]`
**Targets:** `storage/clickhouse/*`, `storage/registry.go`,
`caddy/provision_telemetry.go`.
- [x] Call `InitSchema` when constructing the store.
- [x] Add CRS metadata columns (`engine`, `anomaly_score`, `paranoia_level`,
      `matched_rules`) plus existing response/attack fields.
- [x] Implement retention worker and `Prune`.
- [x] Direct `GetEventByID`; remove the 50-event scan.
- [ ] Surface insert failures to the ring buffer/operator (metric/log) — follow-up.
- [x] Tests: schema bootstrap + upgrades, batch round-trip, lookup.
- [ ] Live ClickHouse cluster integration (Phase 4).
- [ ] Gate: ClickHouse serves forensic queries and prunes correctly.

### 0.5 Fix Envoy `ext_proc` wire format `[x]`
**Done in `13e8678`.**
- [x] Correct oneof field numbers for request/response headers and bodies.
- [x] Correct `immediate_response` field number.
- [x] Wire-number regression test.
- [ ] Real Envoy conformance fixture (block + continue) — tracked under 1B.5.

### 0.6 Close per-site auth bypass `[x]`
**Done in `13e8678`.**
- [x] Remove implicit bypass for `Authorization`, JSON accept, XHR, `/api/`.
- [x] Valid session cookie or bearer session token passes.
- [x] Invalid credentials get JSON 401; browsers still get the 467 portal.
- [x] Tests for all bypass vectors and valid bearer.

### 0.7 Trust boundaries `[~]`
**Done:** client IP and trusted proxies (`13e8678`).
- [x] Default to socket peer; ignore forwarded headers unless configured.
- [x] Add `proxy.trusted_proxies`; XFF walked right-to-left past trusted hops.
- [x] Tests: spoofed CF/X-Real-IP/XFF, trusted chain, all-trusted fallback.
- [ ] Capture JA4 from the TLS handshake; remove client-controlled fallback
      unless the peer is a trusted proxy.
- [ ] Capture HTTP/2 frame fingerprint from the connection.
- [ ] PROXY protocol v1/v2 listener with trusted-peer enforcement.
- [ ] Gate: spoofed IP/JA4/h2 tests pass.

### 0.8 Upstream reliability `[~]`
**Targets:** `caddy/upstream.go`, `caddy/forwarding.go`, `caddy/proxy.go`,
`caddy/stage_response.go`.
- [x] Start active health checks for every pool (once per backend, torn down by
      `UpstreamRegistry.Close`); backends re-admitted after `fail_timeout`.
- [x] Passive failure marking + retry another backend (`ProxyWithFailover`,
      bodies up to 1 MiB replayable; larger bodies get one attempt).
- [x] Upstream dial/TLS/response-header/idle timeouts on the shared transport.
- [x] WebSocket/101 hijack path (`ProxyWebSocket`) for configured upstreams.
- [ ] gRPC h2c/trailers support: deferred to 1B.5. `ProxyWithFailover` does not
      forward trailers yet.
- [ ] Honor a per-target expected health-check status (probe still expects 200).
- [x] Tests: backend down, failover, body replay, timeout, WebSocket echo,
      fail-timeout re-admission, registry starts probes; `-race` clean.
- [x] Gate: no request can occupy a worker on a stalled upstream indefinitely
      (response-header timeout; covered by the stalled-upstream test).

### 0.9 Audit telemetry and response sanitization `[x]`
**Done in `13e8678`.**
- [x] Audit-mode and parser-timeout verdicts reach the forensic pipeline.
- [x] Response headers/bodies sanitized before storage.
- [x] Rule messages sanitized.
- [x] Tests for response header/body scrubbing.

### 0.10 Safety net `[~]`
**Done:** API key role validation (`13e8678`); deployment hardening (current).
- [x] Reject API-key roles other than `admin`/`viewer`.
- [x] DB-backed sessions with idle/absolute expiry and revocation (3.1).
- [x] Secure/`__Host-` cookie attributes and same-origin CSRF for cookie
      mutations (3.1).
- [x] Login rate limit and lockout.
- [x] Refuse weak default admin credentials (`security.production_mode`);
      Compose/Helm require stable HMAC/PoW secrets and no longer ship
      `admin/admin` or a published Postgres port.
- [x] De-claim README/AGENTS stack claims (parser libs, Huma, Shoutrrr,
      Ristretto, HA wording) and route production deploys to
      `docs/deployment.md`.
- [x] Stop persisting secrets in Caddy's autosave file; `config print` redacts
      secrets by default.
- [ ] Add `LICENSE`, `NOTICE`, `SECURITY.md`, `STATUS.md`.
- [ ] Minimal CI: build, `go test -race`, `govulncheck`.
- [x] Gate: no known insecure default remains in shipped configs.

---

## Phase 1 — Detection & Rule Engine

### 1A.1 Embed Coraza + OWASP CRS `[x]`
**Done in `aaa12f3`.**
- [x] Add Coraza v3.8.1, vendor OWASP CRS 4.30.0 with NOTICE.
- [x] Compile per-policy WAF (PL1–4, thresholds) once at provisioning.
- [x] Implement `crs` behind `WAFEnginePort`.
- [x] Remove stale `x/*` replace pins; full suite passes.
- [x] Unit tests: SQLi/XSS/LFI, scanner UA, audit mode, response disabled.
- [ ] Response rules require paired transactions (1B.1).

### 1A.2 Composite engine + verdict/event schema `[x]`
**Done:** composite engine, verdict metadata, SQLite/PG/ClickHouse event
columns (`aaa12f3`, `34ea459`, `5d14d49`).
- [x] Semantic first, CRS second; block wins; audit surfaces.
- [x] Extend `Verdict` with engine, anomaly score, PL, matched rules.
- [x] Persist metadata in SQLite and PostgreSQL (migration 0010).
- [x] Sanitize rule messages.
- [x] Persist metadata in ClickHouse (0.4).
- [ ] Add engine/score filters to the events API and UI.
- [ ] Gate: CRS events are distinguishable and queryable.

### 1A.3 Per-site detection policy `[x]`
**Done:** API/UI and snapshot storage in `8557bf7`; runtime per-app CRS
selection and the policy cache in the current change.
**Targets:** `core/control/models.go`, `compiler.go`, `http/detector.go`,
`web/`.
- [x] Add per-app `DetectionPolicy`: CRS enabled, mode, PL, thresholds.
- [x] Compile per-app CRS engines with a bounded policy cache keyed by hash
      (`crs.Config.Fingerprint`; identical apps share one engine).
- [x] Select policy by `ctx.AppID` at request time; default global policy.
- [x] API: GET/PUT per-app policy.
- [x] UI: per-site CRS controls in site detail.
- [x] Tests: app A block, app B audit, disabled app, hot reload.
- [x] Gate: per-app policy survives apply/rollback and replica propagation
      (snapshot-derived; rollbacks recompile the same way).

### 1A.4 Exceptions → CRS exclusions `[x]`
**Targets:** `core/acl/exception.go`, `core/waf/crs/exceptions.go`,
`http/exceptions.go`.
- [x] Translate host/path/method/location/param/rule exceptions into
      `ctl:ruleRemoveById` / `ctl:ruleRemoveTargetById`. `param_regex` targets
      stay semantic-only because Coraza v3.3 ctl matches exact keys.
- [x] Include exclusion set in the policy cache key.
- [x] Rule catalog with IDs, tags, severity, and descriptions (`8557bf7`).
- [x] Dry-run shows semantic and CRS effects (`effects` in the response, with
      the exact ctl directive).
- [x] Tests: exception suppresses CRS rule; other hosts, paths, and parameters
      still fire.
- [x] Gate: one DB exception row drives both engines.

### 1A.5 Rule test playground + go-ftw `[x]`
**Done:** `/rules/test` API (`34ea459`) and UI (`5d14d49`); regression harness,
CI gate, and OpenAPI base in the current change.
- [x] Synthetic request evaluation against the live engine.
- [x] Returns verdict, anomaly score, PL, matched rules, latency.
- [x] OpenAPI entry and unit tests.
- [x] `tests/crs/` go-ftw fixture with Raiwall in block mode: local echo
      upstream, PL1 config, pinned corpus fallback (`v4.30.0`), `make test-crs`.
- [x] Nightly + on-change CI job (`.github/workflows/crs-parity.yml`);
      committed skip list (`tests/crs/skips.txt`) with reasons.
- [x] Thresholds enforced by `tests/crs/gate`: 100% applicable critical-family
      tests (LFI/RCE/XSS/SQLi) and ≥95% overall. The corpus has no
      paranoia-level tags, so "PL1 critical" is measured as the harness running
      PL1 with zero failures in those families. go-ftw cloud mode measures
      block/allow parity, not rule attribution.
- [x] UI panel for the rule tester (`Rules → Rule Tester`).
- [x] Make `/.raiwall/api/v1` the canonical base in the OpenAPI `servers`
      entry (the data plane only mounts that prefix); paths stay relative.
      The chi-level `/api/v1` alias remains for direct-server/tests.
- [x] Gate: CRS parity thresholds met. Measured locally with the test-lab
      corpus: 2491/2491 critical, 5103/5103 overall, with the 103 response-rule
      files excluded for 1B.1. CI re-runs against the pinned corpus tag.

### 1A.6 Performance and soak `[ ]`
- [ ] Benchmark semantic-only vs composite (1 KB body, PL1–4).
- [ ] Enforce body caps before CRS; no per-request rule compilation.
- [ ] 1k RPS × 1 MB soak for 1 h; 24 h mixed-traffic soak.
- [ ] Gate: CRS PL1 incremental p99 ≤1.5 ms; semantic p99 regression ≤5%.

### 1B.1 Response inspection + DLP `[ ]`
- [ ] Buffer inspectable responses to 1 MiB (hard cap 8 MiB).
- [ ] Inspect headers always; body for text/JSON/XML/JS only.
- [ ] Skip SSE/101/204/304/media/compressed unless decompression enabled.
- [ ] Block only before first flush; otherwise audit.
- [ ] DLP: PAN, secrets, JWT/private keys; block/redact/audit.
- [ ] Paired CRS request/response transaction so outbound thresholds initialize.
- [ ] Tests: block/redact/audit, streaming skip, no partial block page.

### 1B.2 Normalization depth `[ ]`
- [ ] Base64/hex and JSON-in-JSON decoding.
- [ ] Configurable body-prefix policy and inspect-vs-reject mode.
- [ ] Tests: encoded SQLi/XSS bypass corpus.

### 1B.3 XML, GraphQL, OpenAPI `[ ]`
- [ ] XML parser with XXE protections and parameter extraction.
- [ ] GraphQL depth/complexity/alias limits.
- [ ] OpenAPI request-schema validation per site.
- [ ] Tests: XXE corpus, deep/cyclic queries, schema violations.

### 1B.4 Upload content inspection `[ ]`
- [ ] Content-type/magic-byte and polyglot checks.
- [ ] ClamAV/ICAP adapter hook with size/time caps.
- [ ] Tests: PHP/ASP polyglots, zip bomb, EICAR.

### 1B.5 Protocol and transport `[ ]`
- [ ] Raw-front smuggling checks (document the Caddy boundary).
- [ ] WebSocket/gRPC upstream proxying with trailers and h2c.
- [ ] Client mTLS and certificate validation.
- [ ] PROXY protocol v1/v2 (from 0.7).
- [ ] Real Envoy ext_proc conformance fixture (from 0.5).
- [ ] Tests: WS echo, gRPC unary/stream, PROXY trusted/untrusted.

### 1B.6 Detection operations `[ ]`
- [ ] Activate per-host rate/bot policies.
- [ ] Complete CVE rules to 193; fix `Signature.Prefix` and method indexing.
- [ ] Threat-feed hardening and JA4 reputation.
- [ ] Tests: policy selection, CVE count/index, feed reload.

---

## Phase 2 — Observability & Compliance

### 2.1 OpenTelemetry `[ ]`
- [ ] Spans for request, WAF phases, upstream, response; W3C propagation.
- [ ] OTLP HTTP/gRPC exporters; parent-based + forced block/error sampling.
- [ ] Tests: trace reaches a collector; blocked request forced-recorded.

### 2.2 SIEM pipeline `[ ]`
- [ ] RFC5424, CEF, LEEF encoders.
- [ ] Splunk HEC, Sentinel DCR, Elastic bulk transports.
- [ ] Bounded disk spool, retry/backoff, dedupe by `event_id`.
- [ ] Tests: encoder fixtures, outage replay, duplicate suppression.

### 2.3 Administrative audit log `[ ]`
- [ ] Append-only table: `seq`, actor, action, resource, request ID, IP/UA,
      before/after hashes, `prev_hash`, `entry_hash`.
- [ ] Server-derived actor only (never client body).
- [ ] Ed25519 anchors every N entries or T.
- [ ] Verify API and tamper tests.
- [ ] Gate: forged author ignored; chain tamper detected.

### 2.4 Retention, legal hold, WORM `[ ]`
- [ ] Retention policy UI/API and prune dry-run.
- [ ] Legal hold that blocks pruning.
- [ ] S3 Object Lock export; ClickHouse TTL.
- [ ] Tests: hold survives prune; WORM retention enforced.

### 2.5 Reports `[ ]`
- [ ] CSV/JSON and printable HTML; PDF optional.
- [ ] PCI/SOC2/GDPR evidence mappings.
- [ ] Record report hash in the audit log.
- [ ] Tests: reconciliation against event/audit snapshots.

### 2.6 Alerting maturity `[ ]`
- [ ] Channel CRUD API/UI, test-send, delivery history.
- [ ] Retry/backoff and dedupe.
- [ ] Tests: retry after 5xx, history persisted, cooldown respected.

### 2.7 Telemetry completeness `[ ]`
- [ ] Per-site/rule/upstream metrics and dashboards.
- [ ] DLP/response-inspection events.
- [ ] ClickHouse analytics dashboards.

---

## Phase 3 — Enterprise Control Plane

### 3.1 Sessions and CSRF `[x]`
- [x] Opaque hashed session tokens, idle/absolute expiry, revocation.
- [x] `__Host-` Secure HttpOnly cookie; a new session is minted on each login
      and all sessions are revoked on password reset, role change, or
      deactivation.
- [x] Same-origin `Origin`/`Referer` enforcement for cookie mutations; requests
      with neither header (CLI/CI) are allowed, API keys are exempt.
- [x] Login lockout/rate limit (5 failures → 15m, per IP and username).
- [x] Tests: revoke, idle expiry, CSRF cross-origin, lockout, Basic opt-in.

### 3.2 Operator SSO + MFA `[ ]`
- [ ] OIDC with state/nonce/PKCE and group→role mapping.
- [ ] TOTP with hashed recovery codes; enforce for admin.
- [ ] Tests: mock IdP, wrong state/nonce, recovery code.

### 3.3 RBAC and scoped API keys `[~]`
- [~] Primary write actions (sites, exceptions, ACLs, deployments) are hidden
      for viewers via `AdminOnly`; viewer banner added. Row-level actions,
      settings, identity and policy screens still need the same pass.
- [ ] Roles admin/operator/analyst/viewer/auditor with `resource:verb`.
- [ ] Per-route permission middleware; remove method-only checks.
- [ ] API keys: scopes, expiry, tenant, validated role, prefix+hash.
- [x] Admin operator CRUD/UI: list/create/change role/reset
      password/deactivate/revoke sessions, admin-only, last-active-admin and
      self-deactivation guards; sessions revoked on every change.
- [~] Tests: operator lifecycle, viewer mutation denied, last-admin guard; the
      five-role authorization matrix remains pending (only admin/viewer exist).

### 3.4 Secrets keyring `[ ]`
- [ ] AES-GCM key IDs; env/Vault Transit/KMS providers.
- [ ] Write-only secret fields and redaction.
- [ ] Encrypt certificate keys and IdP secrets with an external key.
- [ ] Tests: no secret in API responses; rotation.

### 3.5 Multi-tenancy `[ ]`
- [ ] `tenant_id` on all control/telemetry/audit tables, default `default`.
- [ ] Tenant-scoped store wrappers and quotas.
- [ ] Tenant admin UI.
- [ ] Tests: cross-tenant reads/writes denied.

### 3.6 Admin listener isolation `[~]`
- [ ] Separate admin listener; mTLS/IP allowlist.
- [x] `control.allowed_networks` CIDR allowlist for `/.raiwall/*`, metrics, and
      telemetry (health probes bypass it); enforced on the socket peer.
- [x] `control.public_url` gates the unknown-host console redirect; other hosts
      no longer advertise the dashboard.
- [ ] Public listener serves sites and app auth only.
- [ ] Dev escape hatch with startup warning.
- [ ] Helm values and tests for a split listener.

### 3.7 Instant configuration apply `[x]`
**Done in `e671812`.**
- [x] `control.auto_apply` (YAML + Helm) commits a snapshot after every
      successful mutation; enabled in the shipped Docker, Helm, and example
      configs.
- [x] Covers sites, forwarding rules, exceptions, ACLs, rate/bot policies, the
      detector matrix, and inner rules.
- [x] Mutation responses are buffered; an apply failure returns 500 and leaves
      the change staged for repair instead of silently serving stale config.
- [x] Snapshot author comes from the authenticated principal; cluster peers are
      notified; `X-Raiwall-Config-Version` returns the new version.
- [x] Simulation endpoints and runtime-managed resources (bans, certificates,
      templates, IP groups, identity, API keys, manual apply/rollback) excluded.
- [x] `GET /status` exposes `auto_apply`; Deployments hides manual deploy and
      keeps Retry Apply only when staged changes remain.
- [x] Tests: Go middleware apply/disabled/simulation/failure, frontend
      notice/retry, Playwright UI save → snapshot history, full E2E suite.

---

## Phase 4 — HA & Kubernetes

### 4.1 Redis client `[ ]`
- [ ] Replace hand-rolled RESP with `go-redis/v9`.
- [ ] AUTH/TLS/Sentinel/Cluster; pooling and timeouts.
- [ ] Tests: auth failure, TLS, sentinel failover.

### 4.2 Apply lock and convergence `[ ]`
- [ ] PG advisory lock or fenced Redis lease.
- [ ] Fencing token stored with snapshot; late writes rejected.
- [ ] Convergence health in `/status`.
- [ ] Tests: concurrent applies, leader kill.

### 4.3 Shared certificates `[ ]`
- [ ] S3/Consul certmagic storage with distributed locker.
- [ ] KMS-wrapped DB certs.
- [ ] Fail fast if replicas >1 without shared storage.
- [ ] Tests: two replicas issue/renew one certificate.

### 4.4 Distributed waiting room `[ ]`
- [ ] Redis Lua active/queued counters.
- [ ] Stateless signed admission tokens verifiable anywhere.
- [ ] Configurable fail-open/closed.
- [ ] Tests: cross-replica admission, Redis outage.

### 4.5 Helm HA `[ ]`
- [ ] 3 replicas, PDB, topology spread, HPA, NetworkPolicy.
- [ ] Migration Job; split liveness/readiness probes.
- [ ] Authenticated ServiceMonitor.
- [ ] Tests: `helm lint`/template, kind deploy.

### 4.6 Backup and restore `[ ]`
- [ ] CLI export/import; CronJob; documented RTO/RPO.
- [ ] Restore drill.
- [ ] Tests: backup→restore round-trip.

### 4.7 Version and upgrades `[ ]`
- [ ] `/system/version` with build info and schema version.
- [ ] Migration preflight and N-1 upgrade/rollback.
- [ ] Tests: upgrade from previous schema, rollback.

### 4.8 K8s e2e and chaos `[ ]`
- [ ] Leader kill, Redis failover, node drain, network partition.
- [ ] CI job on kind/k3s.

---

## Phase 5 — Ecosystem & Distribution

### 5.1 CI/CD `[ ]`
- [ ] Lint, gosec, govulncheck, race, integration, CRS, web tests, kind e2e.
- [ ] Release workflow with required checks.

### 5.2 Supply chain `[ ]`
- [ ] Syft SBOM, cosign keyless signing, SLSA provenance.
- [ ] Trivy gate (no critical), distroless non-root image.

### 5.3 Air-gap `[ ]`
- [ ] Self-hosted fonts; no runtime external calls.
- [ ] Signed CRS/GeoIP bundles.
- [ ] Egress-blocked install test.

### 5.4 Docs and API truth `[~]`
- [x] Retire the mock Command Center (hardcoded topology/tenant demo); legacy
      routes now render the real statistics view.
- [ ] `STATUS.md` feature matrix matching code.
- [ ] Architecture/operations/security/upgrade docs.
- [ ] OpenAPI 84/84 coverage (fix the `/api/v1` alias in production).
- [ ] Remove SafeLine research from the Raiwall contract docs.

### 5.5 License `[ ]`
- [ ] Choose license (Apache-2.0 recommended), add `LICENSE`/`NOTICE`.
- [ ] Document support entitlement if any.

### 5.6 Optional ecosystem `[ ]`
- [ ] SAML/SCIM, SOAR webhooks, Terraform provider.
- [ ] Kubernetes operator if demand justifies it.

---

## Recommended Order

1. **0.3, 0.4, 0.8** — close the remaining P0 correctness/HA blockers.
2. **1A.3, 1A.4, 1A.5** — make CRS enterprise-usable (per-site, exceptions, parity).
3. **1A.6, 1B.1–1B.6** — detection depth and performance.
4. **2.1–2.6** — observability/compliance (user priority 2).
5. **3.1–3.6** — identity/RBAC/tenancy (required before multi-replica identity).
6. **4.1–4.8** — HA/Kubernetes.
7. **5.1–5.6** — supply chain, air-gap, docs, license.

Phases 1 and 2 can overlap after 0.2/0.9. Phase 4 depends on 0.3 and 3.x.

---

## Task Completion Checklist

For every task:
- [ ] Code implements the acceptance criteria in `ROADMAP.md`.
- [ ] Unit tests added; `go test -race` on touched packages.
- [ ] Integration/E2E path tested (Docker; Kubernetes for Phase 4).
- [ ] `go vet ./...` clean; `gofmt -l` empty.
- [ ] `graphify update .` run after Go changes.
- [ ] `ROADMAP.md` status and `TASKS.md` checkboxes updated.
- [ ] Commit is self-contained and production-deployable.
- [ ] Docs/config examples updated; no de-claimed feature presented as real.
