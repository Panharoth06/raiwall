# End-to-End (E2E) Testing & Docker Verification Specification

> **Mandatory Rule for Coding Agents:** Raiwall is an enterprise-grade cybersecurity gateway. All implementations—including backend proxy pipelines, control plane REST APIs, authentication layers, and frontend dashboard components—**must be tested end-to-end after implementation**. Never conclude a task or mark an item complete without running the entire application in Docker, executing Playwright/Chrome tests across desktop and responsive mobile viewports, and validating API operations with HTTP Basic Auth (`admin:admin`).

---

## Table of Contents

- [1. Core Principle: Test After Implementation](#1-core-principle-test-after-implementation)
- [2. Containerized Application Execution (Docker)](#2-containerized-application-execution-docker)
- [3. Frontend UI & Responsive Verification (Playwright / Chrome)](#3-frontend-ui--responsive-verification-playwright--chrome)
- [4. Control Plane REST API Testing (HTTP Basic Auth)](#4-control-plane-rest-api-testing-http-basic-auth)
- [5. Exhaustive Endpoint Verification (All Endpoints Must Work Properly)](#5-exhaustive-endpoint-verification-all-endpoints-must-work-properly)
- [6. WAF Data Plane Threat Block Validation](#6-waf-data-plane-threat-block-validation)
- [7. Post-Implementation Verification Checklist (Finish Gate)](#7-post-implementation-verification-checklist-finish-gate)

---

## 1. Core Principle: Test After Implementation

AI agents frequently fall into the trap of assuming code works after editing files, or relying solely on isolated in-memory unit tests. In Raiwall:

1. **Unit tests are necessary, but insufficient.** A passing unit test does not prove that Caddy middleware binds correctly, that embedded assets load under `/.raiwall/`, that database migrations run in Docker, or that mobile navigation drawers adapt properly.
2. **Execution Timing:** All end-to-end tests must be executed **after** complete code implementation, never prematurely.
3. **Zero Assumptions:** If Docker fails to build, if an API returns 401/500, or if Playwright detects layout overflow on mobile screens, the task is **not done**.

---

## 2. Containerized Application Execution (Docker)

All full E2E verifications must run against the unified containerized application to validate production parity:

### 2.1 Container Stack Requirements
- **Unified Binary:** The Go backend, Caddy data plane, SQLite/PostgreSQL storage drivers, and embedded Vue 3 SPA are packaged together inside the Docker container (`Dockerfile`).
- **Mock Upstream Backend:** A lightweight upstream service running in the same Docker network to verify reverse proxying and traffic forwarding.
- **Port Mapping:** Port `8080` (HTTP Gateway + Admin Console) and `8443` (HTTPS Gateway) accessible on localhost.

### 2.2 Healthcheck & Readiness
Before launching UI or API test runners, the agent must wait for the container to become healthy:
```bash
# Verify container readiness
curl -f http://localhost:8080/.raiwall/api/openapi.json
```
- Ensure HTTP `200 OK` is returned with valid OpenAPI JSON before executing test suites.
- Container logs must be checked for panics, startup fatal errors, or migration failures (`docker logs <container>`).

---

## 3. Frontend UI & Responsive Verification (Playwright / Chrome)

The Vue 3 dashboard must be validated using **Playwright** or **Chrome DevTools** against the live containerized instance (`http://localhost:8080/.raiwall/`).

### 3.1 Mandatory Multi-Viewport Matrix
Every UI view must be verified across three distinct viewport tiers:

| Viewport | Dimensions | Target Device | Mandatory Verification Criteria |
| :--- | :--- | :--- | :--- |
| **Desktop** | `1440 × 900` or `1920 × 1080` | Workstation / SOC Display | Full horizontal navigation sidebar, dense telemetry tables with tabular numbers, 3D Attack Globe / Canvas rendering, multi-column metric cards, action modal dialogs. |
| **Tablet** | `768 × 1024` | iPad / Tablet Landscape/Portrait | Adaptive layout collapse, table horizontal scrolling with frozen header/action column, responsive grid wrapping, chart container auto-resizing. |
| **Mobile** | `390 × 844` | Modern Smartphone (iPhone/Pixel) | Collapsible hamburger/sheet drawer navigation, stacked single-column metric cards, zero horizontal body scrollbar bleed (`overflow-x: hidden`), touch targets $\ge 44\text{px}$, string truncation on long hostnames and URLs. |

### 3.2 Visual & Runtime Inspection Rules
1. **Console Logs:** Zero unhandled JavaScript errors (`page.on('console', msg => msg.type() === 'error')`).
2. **Network Failures:** Zero unhandled `4xx`/`5xx` network calls (except intentional negative auth or threat tests).
3. **Empty & Loading States:** Skeletons appear during data fetch; clean empty states display when tables have 0 rows.
4. **Form Controls:** Inputs, selects, and toggle switches must retain focus rings and respond with $\le 150\text{ms}$ transitions.
5. **Theme Consistency:** UI must adhere to semantic design tokens (`bg-background`, `text-foreground`, `border-border`) in both Light and Dark themes. Arbitrary hex colors are strictly prohibited.

---

## 4. Control Plane REST API Testing (HTTP Basic Auth)

All REST API endpoints (`/api/v1/*` and `/.raiwall/api/v1/*`) must be tested using standard **HTTP Basic Authentication**:

### 4.1 Authentication Credentials & Header
- **Username:** `admin`
- **Password:** `admin`
- **Header:** `Authorization: Basic YWRtaW46YWRtaW4=` (`base64("admin:admin")`)

### 4.2 Lifecycle Verification Scope
Automated API tests must verify the complete administrative lifecycle under Basic Auth:
1. **Read Endpoints:**
   - `GET /.raiwall/api/v1/sites` (List protected sites)
   - `GET /.raiwall/api/v1/rules/acls` (List custom ACL bytecode rules)
   - `GET /.raiwall/api/v1/rules/exceptions` (List false-positive exceptions)
   - `GET /.raiwall/api/v1/telemetry/events` (Query forensic attack records)
   - `GET /.raiwall/api/v1/system/status` (Health and engine state)
2. **Mutation Endpoints (Admin RBAC):**
   - `POST /.raiwall/api/v1/sites` (Create new site)
   - `POST /.raiwall/api/v1/rules/exceptions` (Add parameter-level bypass)
   - `POST /.raiwall/api/v1/snapshots/apply` (Atomic snapshot swap)
   - `POST /.raiwall/api/v1/bans/unblock-all` (Flush active IP bans)
3. **Negative Verification:**
   - Requests with missing or invalid credentials (e.g. `admin:wrongpassword`) must receive `HTTP 401 Unauthorized`.
   - Read-only or viewer roles must receive `HTTP 403 Forbidden` on mutating endpoints (`POST`, `PUT`, `DELETE`).

---

## 5. Exhaustive Endpoint Verification (All Endpoints Must Work Properly)

> **Mandatory Contract Rule:** Every single endpoint registered in Raiwall—spanning data plane gateway hooks, internal administration paths, embedded UI bundles, documentation specs, and every control plane REST API route—**must work properly as expected**. No route may return an unhandled 500 error, unexpected 404, empty response body, or unformatted panic.

### 5.1 Endpoint Catalog & Expected Behaviors

| Endpoint Category | Paths / Patterns | Method(s) | Expected Behavior & Success Criteria |
| :--- | :--- | :--- | :--- |
| **OpenAPI & Docs** | `/.raiwall/api/openapi.json`, `/.raiwall/api/docs`, `/.raiwall/api/swagger` | `GET` | Returns HTTP `200 OK` with valid OpenAPI 3.1 JSON; Scalar/Swagger UIs render interactively without JavaScript console errors. |
| **Embedded Admin UI** | `/.raiwall/`, `/.raiwall/*` | `GET` | Serves `index.html` with HTTP `200 OK`; all embedded assets (`.js`, `.css`, fonts) load with `200`; HTML5 history router fallback works on refresh. |
| **Health & Probes** | `/healthz`, `/.well-known/*` | `GET` | Returns HTTP `200 OK` with health status indicator; never blocked by rate limiting or bot challenges. |
| **Bot Traps & PoW** | `/.raiwall/trap/honeypot`, `/.raiwall/challenge/*` | `GET`, `POST` | Honeypot triggers instant Tier 2 IP ban; PoW challenge issues valid cryptographic puzzle with HTTP `468` and verifies token clearance. |
| **Session & Auth** | `/api/v1/auth/login`, `/auth/logout`, `/auth/me` | `POST`, `GET` | Valid credentials issue `raiwall_session` cookie; `/auth/me` returns current user principal (`username`, `role`); `/auth/logout` clears session. |
| **Protected Sites** | `/api/v1/sites`, `/sites/{id}` | `GET`, `POST`, `PUT`, `DELETE` | Full CRUD operations persist correctly; lists return structured JSON array; site deletion cascades or unbinds child routes cleanly. |
| **Forwarding & Resources** | `/api/v1/sites/{id}/forwarding-rules`, `/sites/{id}/resources` | `GET`, `POST`, `PUT`, `DELETE` | Path-prefix forwarding rules route correctly; auto-discovered API resource catalog updates dynamically and permits deletion. |
| **Rule Exceptions** | `/api/v1/exceptions`, `/exceptions/{id}` | `GET`, `POST`, `PUT`, `DELETE` | Parameter-level bypass rules persist; dry-run testing (`/exceptions/test`, `/exceptions/dry-run`) accurately verifies pattern matches. |
| **Custom ACLs** | `/api/v1/acls`, `/acls/{id}` | `GET`, `POST`, `PUT`, `DELETE` | Compiled `expr` bytecode rules validate expressions; dry-run (`/acls/test`, `/acls/dry-run`) reports boolean evaluation result without modifying state. |
| **Unified & Rate Policies** | `/api/v1/policies`, `/policies/rate`, `/policies/rate/{id}` | `GET`, `POST`, `PUT`, `DELETE` | Updates global volumetric thresholds (Tiers 1–3); creates site-scoped rate limiting rules with valid burst and window configurations. |
| **Active IP Ban Management**| `/api/v1/rate/bans`, `/rate/bans/release`, `/rate/bans/release-all` | `GET`, `POST` | Lists all currently banned IP records; targeted release unbans specific client; release-all flushes entire ban table immediately. |
| **Virtual Waiting Room** | `/api/v1/waiting-room/metrics` | `GET` | Returns active queue depth, concurrency count, and admission rates; updates in real-time. |
| **Bot Defense Policies** | `/api/v1/policies/bot`, `/policies/bot/{id}` | `GET`, `POST`, `PUT`, `DELETE` | Manages JA4 fingerprinting toggles, PoW difficulty parameters, and API bypass path lists. |
| **Staged Deployments** | `/api/v1/config/draft/diff`, `/config/apply`, `/config/rollback/{version}` | `GET`, `POST` | Draft diff highlights pending staged changes; apply executes atomic swap with zero downtime; rollback reverts cleanly to previous version. |
| **API Keys Management** | `/api/v1/apikeys`, `/apikeys/{id}` | `GET`, `POST`, `DELETE` | Generates secure API key with role; returns plaintext key only once on creation; SHA-256 hash stored in database; revocation is immediate. |
| **Telemetry & Events** | `/api/v1/telemetry/events`, `/api/v1/telemetry/stream` | `GET` | Returns paginated attack records with sanitized payloads; SSE stream emits live events to connected UI listeners. |
| **System & Cluster** | `/api/v1/status`, `/cluster/status` | `GET` | Returns engine uptime, memory usage, active rule counts, and Redis Pub/Sub cluster connection state. |

### 5.2 Strict HTTP Contract & Status Code Matrix

Every endpoint must respond with the correct standard HTTP status code under all conditions:

- **`200 OK`**: Successful `GET`, `PUT`, or non-resource-creating `POST`.
- **`201 Created`**: Successful resource creation (`POST /sites`, `POST /exceptions`, etc.) with newly created object in body.
- **`204 No Content`**: Successful resource deletion where no body is returned.
- **`400 Bad Request`**: Validation failure or malformed JSON payload (MUST return structured JSON: `{"error": "descriptive explanation"}`). **Never crash or panic with 500 on invalid user input.**
- **`401 Unauthorized`**: Missing, invalid, or expired authentication token, cookie, or Basic Auth credentials.
- **`403 Forbidden`**: Operation blocked by WAF threat detection, or user lacks required RBAC role (e.g. viewer trying to mutate site).
- **`404 Not Found`**: Request for a non-existent site ID, rule ID, or unmapped path (MUST return clean JSON `{"error": "not found"}`).
- **`405 Method Not Allowed`**: Request using an unsupported HTTP method (e.g. `POST` on `/api/openapi.json`).
- **`500 Internal Server Error`**: **STRICTLY FORBIDDEN**. Any 500 error represents a bug, unhandled error, or unhandled nil pointer that must be fixed immediately.

---

## 6. WAF Data Plane Threat Block Validation

End-to-end testing requires probing the live WAF proxy running in Docker with attack vectors:

### 6.1 Semantic Threat Detection
Execute requests through port `8080` targeting protected host routes:
- **SQL Injection:**
  ```bash
  curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/search?q=' OR '1'='1"
  # Expected: 403 Forbidden
  ```
- **Cross-Site Scripting (XSS):**
  ```bash
  curl -s -o /dev/null -w "%{http_code}" -X POST "http://localhost:8080/submit" \
    -d "comment=<script>alert('xss')</script>"
  # Expected: 403 Forbidden
  ```
- **Command Injection (CmdI):**
  ```bash
  curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/exec?cmd=;cat /etc/passwd"
  # Expected: 403 Forbidden
  ```

### 6.2 Benign Traffic Passthrough
- Verify that legitimate requests pass to upstream backends without disruption:
  ```bash
  curl -s -o /dev/null -w "%{http_code}" "http://localhost:8080/products?category=electronics&page=2"
  # Expected: 200 OK
  ```

### 6.3 Forensic Telemetry Ingestion
- Immediately after firing attack payloads, query the telemetry API:
  ```bash
  curl -u admin:admin "http://localhost:8080/.raiwall/api/v1/telemetry/events?limit=5"
  ```
- Verify that the attack events are captured with correct rule IDs (`SEMANTIC_SQLI`, `SEMANTIC_XSS`), client IP, and sanitized payload metadata.

---

## 7. Post-Implementation Verification Checklist (Finish Gate)

Before finalizing any task, submitting work, or concluding an agent turn, execute and pass every item in this checklist:

- [ ] **Implementation Complete:** All Go code, frontend components, and configurations are saved and pass static analysis (`go vet`, `npm run lint`).
- [ ] **Docker Deployment Running:** Application container starts cleanly with zero crashloops; healthcheck endpoint (`/api/openapi.json`) responds with `200 OK`.
- [ ] **All Endpoints Verified:** Every registered data plane route, UI asset path, and REST API endpoint behaves properly as expected with correct HTTP status codes (zero unexpected 404s, zero 500 errors).
- [ ] **API Basic Auth Verified:** API endpoints respond with `200`/`201` when authenticated with `admin:admin`, and `401` on invalid credentials.
- [ ] **Desktop Viewport Verified (1440×900):** Dashboard sidebar, tables, telemetry charts, and modals render crisply with zero console errors.
- [ ] **Tablet Viewport Verified (768×1024):** Layout adapts, tables scroll horizontally without breaking container, metrics stack properly.
- [ ] **Mobile Viewport Verified (390×844):** Navigation collapses to drawer/sheet, touch targets $\ge 44\text{px}$, zero horizontal layout bleed, text truncates cleanly.
- [ ] **Threat Blocking Verified:** SQLi/XSS requests return `403 Forbidden`; benign requests return `200 OK`.
- [ ] **Forensics Verified:** Blocked events are ingested into the database and visible in telemetry logs.
- [ ] **Clean Teardown:** Test containers and ephemeral test fixtures are cleaned up after test completion.
