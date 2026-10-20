# SafeLine WAF — OpenAPI & REST API Specification Catalog

> Extracted from SafeLine WAF v9.4.2 Swagger OpenAPI Schema (`/swagger/doc.json`)  
> Base Path: `/api`  
> Authentication: Bearer Token (`Authorization: Bearer <API_TOKEN>`) or Session Cookie (`sl-session`, `sl_jwt_session`)

---

## 1. API Architecture & Standard Conventions

SafeLine structures its REST API into distinct namespace domains:
- `/api/open/*`: Core control plane and configuration management endpoints.
- `/api/stat/*`: High-frequency metrics, time-series telemetry, and aggregations.
- `/api/commercial/*`: Enterprise features (Syslog forwarding, custom alarms, license synchronization, multi-node cluster sync).
- `/api/business/*`: Anti-tamper, compliance reporting, frontend customization, and account security.

### Standard Response Envelope

```json
{
  "code": 0,
  "message": "success",
  "data": { ... }
}
```

*Error Codes:* Non-zero integers indicate errors (e.g. `1001: Invalid Parameter`, `2001: Authentication Required`, `3001: License Limit Exceeded`).

---

## 2. API Route Catalog by Feature Domain

### 2.1 Applications & Reverse Proxy Gateway (`/api/open/site*`)

| Method | Endpoint | Query / Path Parameters | Request Body / Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/open/site` | `page`, `page_size`, `stat_enabled` | Lists all protected applications with today's traffic stats. |
| `POST` | `/open/site` | — | **Create Application**: Domain, ports, protocols, SSL cert ID, access method (reverse proxy, static, redirect), upstreams, app name. |
| `GET` | `/open/site/{id}` | `id` (Site ID) | Retrieves full site configuration. |
| `PUT` | `/open/site/{id}` | `id` (Site ID) | Updates an existing application configuration. |
| `DELETE`| `/open/site/{id}` | `id` (Site ID) | Removes the application and releases bound listening ports. |
| `GET` | `/open/site/{id}/basic_info` | `id` | Fetches core metadata, ports, and upstream health status. |
| `POST`| `/open/site/defense` | — | Batch toggles defense mode (`defense`, `audit`, `bypass`). |
| `POST`| `/open/site/mode` | — | Switches proxy execution mode. |
| `GET` | `/open/site/healthcheck` | — | Queries active upstream health check states across all sites. |
| `GET` | `/open/site/{id}/proxy` | `id` | Retrieves advanced proxy settings (XFF rewrite, HSTS, SSE, compression). |
| `POST`| `/open/site/{id}/proxy` | `id` | Updates advanced proxy settings. |
| `GET` | `/open/site/{id}/forwarding_rules` | `id` | Lists all path-prefix forwarding rules for the site. |
| `POST`| `/open/site/{id}/forwarding_rules` | `id` | Adds a path-prefix forwarding rule (`prefix`, `upstreams`, `comment`). |
| `PUT` | `/open/site/{id}/forwarding_rules/{rule_id}` | `id`, `rule_id` | Modifies an existing path-prefix forwarding rule. |
| `DELETE`| `/open/site/{id}/forwarding_rules/{rule_id}`| `id`, `rule_id` | Deletes a forwarding rule. |
| `POST`| `/open/site/{id}/forwarding_rules/{rule_id}/switch` | `id`, `rule_id` | Toggles forwarding rule enable/disable state. |
| `GET` | `/open/site/{id}/resources` | `id` | **API Discovery**: Returns auto-discovered API endpoints, methods, and access counts. |
| `DELETE`| `/open/site/{id}/resources`| `id`, `resource_id` | Prunes obsolete or removed discovered endpoints. |
| `GET` | `/open/site/{id}/nginx_config`| `id` | Fetches custom NGINX raw config snippet. |
| `POST`| `/open/site/{id}/nginx_config`| `id` | Saves and validates custom NGINX raw directives. |

---

### 2.2 Attack Forensics & Events (`/api/open/events`, `/api/open/records*`)

| Method | Endpoint | Query Parameters | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/open/events` | `page`, `size`, `ip`, `host`, `port`, `start`, `end` | Lists aggregated attack events grouped by incident. |
| `GET` | `/open/records` | `page`, `size`, `ip`, `host`, `port`, `action`, `attackTypes`, `start`, `end` | Lists granular per-request attack logs. |
| `GET` | `/open/record/:id` | `id` (Event UUID) | **Forensic Inspector**: Fetches raw request line, headers, body, extracted payload, JA4 hash, and raw response. |
| `GET` | `/open/records/acl` | `page`, `size`, `ip`, `start`, `end` | Logs of requests matching custom ACL rules. |
| `GET` | `/open/records/challenge`| `page`, `size`, `ip`, `start`, `end` | Logs of bot challenges issued and verification outcomes. |
| `GET` | `/open/records/waiting` | `page`, `size`, `site_id`, `start`, `end` | Telemetry logs from Waiting Room queue sessions. |
| `GET` | `/open/records/auth_defense` | `page`, `size`, `account`, `status` | Authentication attempt audit logs. |
| `POST`| `/commercial/record/export` | `format` (`csv`, `json`), filters | Exports filtered attack records for external SIEM / offline review. |

---

### 2.3 Semantic Analysis & Enhanced Rules (`/api/open/detector`, `/api/open/skynet*`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/open/detector` | Fetches current global semantic analysis matrix across all 14 detection modules. |
| `POST`| `/open/detector` | Updates policy modes (`0: Disabled`, `1: Audit`, `2: Balance`, `3: Strict`) per semantic module. |
| `GET` | `/open/site/{id}/semantics` | Fetches application-specific semantic overrides. |
| `POST`| `/open/site/{id}/semantics` | Sets application-specific semantic overrides. |
| `GET` | `/open/skynet/rule` | Lists all 193 Enhanced Virtual Patching CVE rules with states and attack categories. |
| `POST`| `/open/skynet/rule/switch` | Toggles individual or batch enable/disable state for Enhanced Rules. |

---

### 2.4 Allow & Deny (ACL & Policy Rules) (`/api/open/policy*`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/open/policy` | Lists all active custom ACL rules (Whitelists and Blacklists). |
| `POST`| `/open/policy` | **Create ACL Rule**: Action (`allow`, `deny`), Name, Condition Groups (`match_target`, `operator`, `content`), and `continue_detect` flag. |
| `GET` | `/open/policy/detail` | Fetches full rule condition hierarchy for an individual rule. |
| `PUT` | `/open/policy` | Updates rule conditions or priority order. |
| `DELETE`| `/open/policy` | Deletes an ACL rule. |
| `POST`| `/open/policy/switch` | Toggles rule active status. |
| `POST`| `/open/policy/order` | Re-orders evaluation sequence of rule list. |
| `GET` | `/open/ipgroup` | Lists defined IP Groups (CIDRs, search spiders, threat intelligence lists). |
| `POST`| `/open/ipgroup` | Creates a new named IP Group. |
| `POST`| `/open/ipgroup/append` | Appends single IP or CIDR subnet to existing group (used by "Add to IP Group" in forensics). |

---

### 2.5 DDoS, Rate Limiting & Waiting Room (`/api/acl/relieve`, `/api/open/site/:id/waiting`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `POST`| `/acl/relieve` | **Unblock IP**: Immediately releases an IP from active rate-limiting or scanner trap bans (`ip`, `site_id`). |
| `POST`| `/open/site/challenge` | Configures 3-tier limits: Basic Access Limit, Basic Attack Limit, Basic Error Limit. |
| `GET` | `/open/site/:id/waiting` | Retrieves Waiting Room status and capacity configuration for a site. |
| `POST`| `/open/site/:id/waiting` | Updates Waiting Room concurrency limits, queue depth, and target queuing URL paths. |

---

### 2.6 Anti-Bot Defense (`/api/open/challenge*`, `/api/open/ja4`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/open/challenge/config` | Retrieves bot challenge settings (Cloud Challenge vs. Local Challenge). |
| `POST`| `/open/challenge/config` | Toggles `local_challenge: true/false`. |
| `GET` | `/open/ja4` | Retrieves JA4 database status, active malicious fingerprint hashes, and updates. |
| `POST`| `/open/share_fingerprint` | Manages voluntary anonymous JA4 fingerprint intelligence exchange. |

---

### 2.7 Identity Authentication & SSO (`/api/open/auth_defense*`, `/api/open/portal*`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/open/auth_defense/user` | Lists user directory accounts with bound apps, 2FA status, and login timestamps. |
| `POST`| `/open/auth_defense/user` | Creates a new user account with assigned application permissions. |
| `PUT` | `/open/auth_defense/user/{user_id}` | Updates user account details or password. |
| `DELETE`| `/open/auth_defense/user/{user_id}`| Removes a user account. |
| `POST`| `/open/auth_defense/user/{user_id}/reset_totp` | Resets 2FA Two-Factor Authentication TOTP secret for a user. |
| `GET` | `/open/auth_defense/source` | Lists configured Identity Providers (Local DB, GitHub, OIDC, LDAP). |
| `POST`| `/open/auth_defense/source` | Configures new external IdP connection (e.g. OIDC Client ID/Secret, LDAP Bind DN). |
| `GET` | `/open/portal` | Fetches Centralized SSO Portal configuration. |
| `POST`| `/open/portal` | Toggles Unified SSO mode. |
| `GET` | `/open/portal/style` | Customizes login portal visual branding, logo, and title. |

---

### 2.8 Statistics & Live Telemetry (`/api/stat/*`)

| Method | Endpoint | Query Parameters | Description |
| :--- | :--- | :--- | :--- |
| `GET` | `/stat/qps` | `count` (default: 35) | Real-time 1-second interval QPS array for live dashboard area chart. |
| `GET` | `/stat/advance/location` | `begin_time`, `end_time`, `global`, `action` | Geographical distribution of requests/blocks by country. |
| `GET` | `/stat/advance/access` | `begin_time`, `end_time` | Total requests, PV, UV, and unique client IP aggregates. |
| `GET` | `/stat/advance/attack` | `begin_time`, `end_time` | Attack count aggregates and unique attacking IP counts. |
| `GET` | `/stat/advance/client` | `begin_time`, `end_time`, `page`, `size` | Ranked breakdown of Operating Systems and Browsers. |
| `GET` | `/stat/advance/status_code` | `begin_time`, `end_time`, `upstream` | Status code distribution (2xx, 3xx, 4xx, 5xx) on edge vs. upstream. |
| `GET` | `/stat/advance/error_status_code`| `begin_time`, `end_time`, `upstream` | Error rate metrics for 4xx and 5xx responses. |
| `GET` | `/stat/advance/domain` | `begin_time`, `end_time`, `refer` | Top visited applications (or top referring applications). |
| `GET` | `/stat/advance/page` | `begin_time`, `end_time`, `refer` | Top hit URI pages (or top referring pages). |
| `GET` | `/stat/advance/trend/access` | `begin_time`, `end_time` | Access traffic time-series curve. |
| `GET` | `/stat/advance/trend/intercept`| `begin_time`, `end_time` | Attack intercept time-series curve. |

---

### 2.9 System Settings, Certificates, Alerts, HA (`/api/open/system*`, `/api/commercial/*`)

| Method | Endpoint | Description |
| :--- | :--- | :--- |
| `GET` | `/open/cert` | Lists stored SSL/TLS certificates with validity and domain bindings. |
| `POST`| `/open/cert` | Uploads new certificate PEM + private key or requests Let's Encrypt / ACME cert. |
| `DELETE`| `/open/cert/{id}` | Deletes a certificate. |
| `GET` | `/open/block_page` | Lists custom blocking page templates for 403, 404, 429, 465, 467, 468, 502, 504. |
| `POST`| `/open/block_page` | Saves custom HTML error page templates and CSS styling. |
| `GET` | `/commercial/alarm` | Fetches notification push channels (Telegram, Discord, Webhooks). |
| `POST`| `/commercial/alarm` | Configures webhook URLs, bot tokens, and notification events. |
| `POST`| `/commercial/alarm/test`| Dispatches a test alert ping across configured channels. |
| `GET` | `/commercial/syslog` | Retrieves remote SIEM syslog destination host and port. |
| `POST`| `/commercial/syslog` | Configures and tests remote syslog forwarding. |
| `GET` | `/open/global/log_clean`| Retrieves data retention policies for attack logs and statistics. |
| `POST`| `/open/global/log_clean`| Updates auto-prune retention periods (1d, 3d, 7d, 15d, 30d, none). |
| `GET` | `/open/global/mode` | Returns engine execution mode (Single-thread vs Multi-thread). |
| `POST`| `/open/global/mode` | Sets engine thread concurrency model. |
| `GET` | `/open/audit_log` | Fetches paginated administrative audit trail of all console modifications. |
| `POST`| `/open/auth/token` | Generates long-lived OpenAPI bearer authentication token. |
| `GET` | `/open/system/license/status`| Queries active license status, edition (Pro/Community), and expiration days remaining. |
