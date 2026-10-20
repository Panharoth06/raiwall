# SafeLine WAF — Detailed Module Deep Dive

This document provides a granular functional breakdown of every module, tab, configuration field, and backend operational logic in SafeLine WAF v9.4.2.

---

## Module 1: Statistics & Threat Intelligence Dashboard (`/statistics`)

The Statistics dashboard provides macro operational visibility across two dedicated tabs: **Traffic Analysis** and **Security Posture**.

### 1.1 Traffic Analysis (`/statistics`)

A high-performance operational metrics center tracking client access patterns, protocol distributions, and status codes.

| Section / Component | Visual / Data Type | Data Source & Description |
| :--- | :--- | :--- |
| **Global Scope Filter** | Dropdowns | • **Application**: Filter across *All applications* or individual site.<br/>• **Time Window**: Presets (`1 hour`, `24 hours`, `7 days`, `30 days`) or custom datetime picker. |
| **KPI Headline Cards** | Numeric Cards | • **Requests**: Total incoming HTTP/HTTPS requests processed.<br/>• **Page Views (PV)**: Total HTML document views.<br/>• **Unique Visitors (UV)**: Distinct visitor count identified via session cookies/fingerprints.<br/>• **Unique IP**: Distinct client IP count.<br/>• **Blocked**: Total malicious/unauthorized requests terminated.<br/>• **IP Addr**: Count of unique offending IP addresses.<br/>• **4xx Errors & Error Rate**: Total upstream/client 4xx errors and percentage ratio.<br/>• **4xx Blocked & Blocked Rate**: Requests terminated by WAF with 4xx codes.<br/>• **5xx Errors & Error Rate**: Backend gateway/server failure count and percentage. |
| **Geo Location Map** | 3D Globe & 2D Flat Map (Three.js / ECharts) | • Toggleable between **3D Globe** (WebGL) and **2D Map**.<br/>• Toggleable between **REQUESTS** (general access) and **BLOCKED** (threat origins).<br/>• Ranked country breakdown (e.g. China, United States, Belgium, United Kingdom, Indonesia, Netherlands, Germany). |
| **QPS Real-Time Graph** | Time-series Area Chart | Live Query-Per-Second (QPS) telemetry sampling at 1-second intervals via `/api/stat/qps?count=35`. |
| **Requests Status Trend** | Time-series Stacked Chart | Access trend over time categorized by HTTP status classifications (2xx, 3xx, 4xx, 5xx). |
| **Blocking Status Trend** | Time-series Stacked Chart | Blocked request velocity grouped by enforcement module (Semantic WAF, Rate Limiting, ACL, Bot Challenge). |
| **User Clients Breakdown** | Doughnut / Horizontal Bar | • **Operating Systems**: macOS, Windows, Linux, Android, iOS, Unknown.<br/>• **Browsers**: Chrome, Firefox, Safari, Edge, Mozilla, Spider, Unknown. |
| **Response Status Distribution** | Bar / List with "MORE" Modal | Breakdown of every observed HTTP status code: `200`, `400`, `403`, `404`, `405`, `429`, `467`, `468`, `502`. |
| **Top Referrers & Destinations** | Ranked Data Tables | • **Referring Application & Page**: Upstream referrers directing traffic.<br/>• **Popular Application & Page**: Most frequently hit domain hosts and URI paths. |

---

### 1.2 Security Posture (`/statistics/security`)

Focuses purely on security enforcement metrics, active threat trends, and incident telemetry.

| Section / Component | Visual / Data Type | Data Source & Description |
| :--- | :--- | :--- |
| **Security KPI Row** | Metric Counter Badges | Aggregated counts for: **Attacks**, **Allow & Deny**, **Rate Limiting**, **Waiting Room**, **Anti-Bot**, and **Auth**. |
| **Attacks Trends & Top IPs** | Time-series + Top 5 IP List | Attack frequency over time + top attacking IP addresses with country tags and request counts; includes **"MORE"** modal for full list. |
| **Allow & Deny Trends** | Time-series + Top IP List | Hit rates on custom ACL blacklists and whitelists over time. |
| **Rate Limiting Trends** | Time-series + Top IP List | Volumetric rate-limiting interventions triggered per source IP. |
| **Anti-Bot Trends** | Time-series + Top IP List | Challenge-failed source IPs unable to complete Proof-of-Work or CAPTCHA challenges. |
| **Waiting Room Trends** | Area Chart | Queue size and concurrency throttling over time. |
| **Auth Trends** | Area Chart | Authentication successes vs. failed login attempts. |
| **Real-Time Events Feed** | Live Scrolling Stream | Chronological stream of incoming enforcement events with timestamp, rule category, and application name: e.g. `09:30:37 Ratelimit Dashboard Proxy`, `09:00:46 Anti-Bot CAPTCHA Slide Challenge Demo`. |
| **Web Attack Categories** | Horizontal Bar / Tag Cloud | Categorical breakdown of blocked attacks:<br/>• **Leaking** (Information Disclosure)<br/>• **Code Inj** (Code Execution)<br/>• **Cmd Inj** (Command Injection)<br/>• **SQL Inj** (SQL Injection)<br/>• **File Include** (LFI/RFI)<br/>• **XSS** (Cross-Site Scripting) |
| **Top Attacked Pages** | Ranked URI Table | Most heavily targeted endpoints (e.g. `/php-cgi/php-cgi.exe`, `/.git/config`, `/hello.html`). |

---

## Module 2: Applications & Reverse Proxy Gateway (`/sites`)

This module manages all protected web applications, SSL/TLS certificates, load balancing upstreams, and reverse proxy behaviors.

### 2.1 Application Inventory View

- **Filter Bar**: Search applications by name or domain; toggle between Card view and Table view.
- **Application Card Metrics**:
  - **App Name & Host**: e.g., `Dashboard Proxy` (`Match All Host`).
  - **Ports & Protocol**: Displays bound ports and encryption status (e.g. `8000/HTTPS`, `80/HTTP`, `443/HTTPS`).
  - **Today's Telemetry**: `RQS TD` (Requests Today) and `BLK TD` (Blocked Today).
  - **Mode Badge**: `DEFENSE MODE` (Active blocking), `AUDIT MODE` (Monitor only), `BYPASS` (Passthrough).
  - **Shortcut Actions**: Direct jumps to `HTTP FLOOD`, `BOT PROTECT`, `AUTH`, `ATTACKS`.

---

### 2.2 Add Application Dialog

The creation workflow allows defining an entry point in under 30 seconds:

| Field Name | Type | Options / Behavior | Description |
| :--- | :--- | :--- | :--- |
| **Domain** | Text / Wildcard | Supports FQDN (`example.com`), Subdomains (`*.example.com`), or `*` (Match All Hosts). | Defines the Host header matching condition. |
| **Listening Ports** | Multi-row Input | Port number + Toggle (`HTTP` vs. `HTTPS`). Multiple ports can be added via **"ADD LISTENING PORT"**. | Default prepopulates with Port `80` (HTTP) and `443` (HTTPS). |
| **SSL Cert** | Dropdown / Upload | Select from stored certificates or upload new PEM certificate + private key. | Required if any listening port has HTTPS enabled. |
| **Access Method** | Radio Group | • `Reverse Proxy` (Default)<br/>• `Static Files`<br/>• `Redirect` | Determines how the gateway dispatches clean requests. |
| **Upstream Servers** | Dynamic List | Supports `http://` or `https://` + IP/Hostname + Port. Add multiple upstreams via **"ADD UPSTREAM"**. | SafeLine automatically applies weighted round-robin load balancing and health checks across upstreams. |
| **Application Name** | Text Input | Alphanumeric friendly label (e.g. "Customer Portal"). | Internal label displayed across logs and analytics. |

---

### 2.3 Application Detail (`/sites/detail?id=:id`)

Configured across four tabs:

#### Tab 1: Basic Information (`&tab=basicInfo`)
- Displays core metadata, port bindings, access method, upstream targets, and defense mode toggle.
- Direct quick links to site-specific access logs and error logs.

#### Tab 2: Forwarding Rules (`&tab=forwardingRule`)
- Microservices route dispatcher within a single application domain.
- Allows defining **Path Prefixes** (e.g. `/api/v1/auth`, `/static/`, `/upload/`) that route to designated, distinct upstream server pools without altering security posture.

#### Tab 3: Advanced Settings (`&tab=proxyConfig`)
Provides granular HTTP/TLS proxy tuning:

```
Advanced Configuration Matrix
├── Client IP Extraction
│   ├── Socket Connection (Default TCP remote address)
│   ├── X-Forwarded-For (XFF)
│   └── Custom Header (e.g. X-Real-IP, CF-Connecting-IP)
│   └── Scope: [USE GLOBAL] or [CUSTOMIZE]
│
├── Protocol & Redirection
│   ├── Listen IPv6 (Enable dual-stack IPv4/IPv6 socket binding)
│   ├── Redirect HTTP to HTTPS (Automatic 301 when both 80 and 443 are listened)
│   └── Enable HSTS (Strict-Transport-Security header injection)
│
├── Header Manipulation
│   ├── Modify Host Header (Default $http_host; customizable to upstream host)
│   ├── Pass X-Forwarded-Host & X-Forwarded-Proto to upstream
│   ├── Clear and rewrite X-Forwarded-For (Prevents client spoofing by overwriting outer XFF)
│   └── Custom HTTP Header Operations (Add, remove, or modify request/response headers)
│
├── Performance & Compression
│   ├── Gzip Compression (Server-side text compression)
│   ├── Brotli Compression (High-ratio web asset compression)
│   └── SSE Streaming (Disable buffering for Server-Sent Events / LLM AI streams)
│
├── Security & Cryptography
│   ├── Enable NTLM Authentication (Proxies Windows domain NTLM handshakes)
│   ├── SSL Protocols (Selectable TLSv1.2, TLSv1.3)
│   └── SSL Ciphers (Custom cipher suite specification)
│
└── Engine Raw Config
    └── Custom NGINX Config Block (Direct injection of arbitrary location/server directives)
```

#### Tab 4: Routings / API Inventory (`&tab=resource`)
- **Automated API Discovery**: SafeLine observes clean traffic and compiles an active catalog of upstream API endpoints.
- Displays: HTTP Method (`GET`, `POST`, `PUT`, `DELETE`), Path, Content-Type (`application/json`, `text/html`), 24-Hour Access Volume, and Last Seen Date.
- Operator can configure discovery sampling via **"COLLECTION CONFIG"** or prune decommissioned routes with **"REMOVE"**.

---

## Module 3: Attacks & Threat Detection Engine (`/attact_events`)

SafeLine's core threat mitigation system operates a dual-view forensic console supported by two configuration sub-engines: **Semantic Analysis** and **Enhanced Rules**.

### 3.1 Events vs. Logs Views

1. **`EVENTS` View**: Incident aggregation grouping repeated attack requests from the same source IP against a target domain within a sliding time window (e.g. `182.11.1.196 | https://demo.waf.chaitin.com:10084/ | 6 requests blocked | 4 minutes`).
2. **`LOGS` View**: Atomic, per-request log records with fields:
   - **Action**: `Blocked` (Enforced) or `Monitored` (Audit mode).
   - **URL**: Full requested URI including encoded query strings.
   - **Attack Type**: Classification tag (SQL Inj, XSS, File Include, etc.).
   - **Source IP & GeoIP**: IP address and resolved country/region.
   - **Timestamp**: High-precision execution time.
   - **Detail Button**: Opens the Forensic Inspector Modal.

---

### 3.2 Forensic Payload Inspector Modal

Clicking **"Detail"** opens a full-screen analysis drawer designed for incident response:

- **Threat Classification Badge**: e.g., `SQL Inj`, `Cmd Inj`, `XSS`.
- **Target URL**: Full URL with malicious query strings highlighted.
- **Source Context**: IP address, Country, **"Add to IP Group"** shortcut, and **"IP Info"** lookup.
- **Client TLS Fingerprint**: Full **JA4 Fingerprint** string (e.g., `t13d1519h2_8daaf6152771_2a491754129e`) with a **"Check JA4 Fingerprint"** verification link.
- **Payload Diagnostics**:
  - **Location**: Parameter context where the attack was identified (`URLPATH`, `QUERY`, `HEADER`, `BODY`, `COOKIE`).
  - **Malicious Token**: The parsed malicious syntax string isolated by the AST lexer (e.g. `1 and 1=1`, `<script>alert()</script>`, `../../etc/passwd`).
- **Detection Module**: Identifies the engine module triggering the alert.
- **Unique Event UUID**: e.g., `6433a0b199cb41a980cf1301ac012eed`.
- **Dual Tab Raw Inspection**:
  - **REQUEST Tab**: Character encoding selector (`UTF-8`, `GBK`, `ISO-8859-1`), exact HTTP request line, complete headers, and body.
  - **RESPONSE Tab**: Server response code, headers, and body returned.
- **Analyst Action Buttons**:
  - **"Copy as cURL"**: Generates a reproducible `curl` command with identical headers, cookies, and payload for offline terminal testing.
  - **"CLOSE"**: Dismisses the modal.

---

### 3.3 Semantic Analysis Configuration (`/attact_events/semantics`)

SafeLine implements intelligent lexical triage and abstract syntax tree (AST) evaluation rather than naive regular expressions. Operators can tune 14 discrete detection modules across 4 operating modes:

| Detection Module | Target Vulnerability Class | Available Operating Modes |
| :--- | :--- | :--- |
| **SQL Inj** | SQL Injection (Union, Blind, Error, Boolean, Stacked) | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **XSS** | Cross-Site Scripting (Reflected, Stored, DOM-based) | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **File Uploading** | Webshells, polyglot files, executable MIME bypasses | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **File Including** | Local & Remote File Inclusion (LFI/RFI, Directory Traversal) | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **CMD Inj** | OS Command Injection (`sh`, `bash`, `cmd.exe`, PowerShell) | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **Java Code Inj** | OGNL, SpEL, Groovy, script engine code injection | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **Java Unserialize** | Java ObjectInputStream, CommonsCollections, Fastjson gadgets | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **PHP Unserialize** | PHP `unserialize()` object injection and magic methods | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **PHP Code Inj** | `eval()`, `assert()`, `preg_replace /e` code execution | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **ASP Code Inj** | Classic ASP and ASP.NET arbitrary code injection | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **SSTI** | Server-Side Template Injection (Jinja2, Twig, Freemarker) | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **CSRF** | Missing cross-site request tokens on state-changing paths | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **SSRF** | Server-Side Request Forgery targeting metadata/internal IP | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |
| **Mal HTTP** | HTTP Request Smuggling, anomalous headers, invalid protocol | `Disabled`, `Audit Mode`, `Balance Mode`, `Strict Mode` |

*Mode Behaviors:*
- **Disabled**: Module completely inactive.
- **Audit Mode**: Analyzes traffic and logs threats to forensics, but forwards request to upstream without blocking.
- **Balance Mode**: Blocks high-confidence threats while applying heuristic relaxation to avoid business false positives.
- **Strict Mode**: Maximum security; enforces rigid parsing, lower anomaly thresholds.

---

### 3.4 Enhanced Rules / Virtual Patching (`/attact_events/inner_rules`)

A library of **193 specialized vulnerability rules** providing targeted virtual patch coverage for known CVEs:

- Includes rules for:
  - Apache Log4j JNDI remote code execution (`CVE-2021-44228` / `Rule 131094`)
  - Apache Shiro authentication bypass (`Rule 131099`)
  - Git repository disclosure (`.git/config` access / `Rule 131095`, `131091`)
  - Ghostscript command execution & arbitrary file I/O (`CVE-2018-19475`, `CVE-2018-17961`)
  - WebLogic deserialization (`CNVD-C-2019-48814` / `Rule 131080`)
  - Jackson-databind polymorphic deserialization (`CVE-2020-36179~36189`, `CVE-2017-7525`)
  - Spring Framework RCE (Spring4Shell / `Rule 131073`, `131074`)
  - Vite arbitrary file reading (`CVE-2025-31125`, `CVE-2025-30208`)
  - MongoDB NoSQL JSON key injection (`Rule 65877`)
- **Management Controls**: Filter by Rule ID or Rule Name; toggle state (`Protect` vs. `Disable`); batch enable/disable.

---

## Module 4: Allow & Deny (Access Control Lists) (`/allow_deny_events`)

Manages custom access control policies, IP whitelists, and parameter-level false-positive bypasses.

### 4.1 Hit Logs & Custom Rules Views

- **Events Log**: Audit record of requests matching custom rules with IP, Application, Hit Count, Duration, and Start Time.
- **Custom Rules View (`/allow_deny_events/custom_rule`)**: Separate management tabs for **WHITELIST** and **BLACKLIST**.

### 4.2 Multi-Condition Rule Builder Modal

Clicking **"ADD RULES"** opens a visual boolean policy composer:

1. **Rule Type**: Radio toggle between `Allow` (Whitelist) and `Deny Rule` (Blacklist).
2. **Name**: Descriptive policy label.
3. **Execution Priority**: `First` (Evaluated at the top of the chain) or `Last`.
4. **Condition Groups**:
   - **Match Target**: `Source IP`, `IP Group`, `URL Path`, `Host`, `User-Agent`, `Referer`, `HTTP Method`, `Header`, `Cookie`, `Query Argument`.
   - **Operator**: `Equals`, `Not Equals`, `Contains`, `Not Contains`, `Prefix / Starts With`, `Suffix / Ends With`, `Regex Match`, `In IP Group`.
   - **Content**: Target value (IP, CIDR, string pattern).
   - **Logic Connectors**: Add nested conditions with **"ADD AN AND CONDITION"** or separate branches with **"ADD AN OR CONDITION"**.
5. **Special Whitelist Toggle**:
   - `[x] Continue to detect and log attack requests even when whitelisting`: Permits the traffic to bypass blocking, but continues running lexical analysis and forensic logging for security auditability.
6. **Enabled State**: Toggle to activate or pause the rule.

---

## Module 5: HTTP Flood & Volumetric Defense (`/http_flood`)

Coordinates three-tier rate limiting and traffic buffering via a virtual waiting room.

### 5.1 Active Blocked Clients Table (`/http_flood/limits`)

- Displays currently banned clients with Source IP, Application, Reason (e.g. `30 Reqs within 60 seconds, Basic Access Limit was triggered`), Action (`Block 5 minutes`, `Anti-Bot Challenge 1 minutes`), Trigger Timestamp, and Status (`Blocked` / `Unblocked`).
- **Emergency Button**: **"UNBLOCK ALL"** immediately clears the IP ban table in case of accidental broad lockouts.

### 5.2 Three-Tiered Rate Limiting Engine (`/http_flood/limits/config`)

SafeLine standardizes DDoS mitigation into three cascading tiers:

| Tier | Policy Name | Default Rule Specification | Trigger Action | Business Purpose |
| :--- | :--- | :--- | :--- | :--- |
| **Tier 1** | **Basic Access Limit** | An IP exceeding `100` requests within `10` seconds | Requires **Anti-Bot Challenge** on subsequent requests for `60` minutes | Differentiates fast human browsing from automated scrapers without blocking real users. |
| **Tier 2** | **Basic Attack Limit** | An IP triggering attack detection `10` times within `60` seconds | **Automatically blocked** for `30` minutes | Automatically bans persistent exploit scanners probing for vulnerabilities. |
| **Tier 3** | **Basic Error Limit** | An IP triggering `403, 404` upstream errors `10` times within `10` seconds | **Automatically blocked** for `30` minutes | Traps path-enumeration tools (DirBuster, ffuf, Gobuster) discovering hidden files. |

**Custom Rate Limit Rules (`ADD RULES`):**
Operators can build custom rules specifying:
- Match Target: `URL Path`, `Source IP`, `Header`, etc.
- Velocity Constraints: `[X]` requests within `[Y]` seconds.
- Enforcement Action: `Challenge` (PoW/CAPTCHA) or `Block` (HTTP 429) for `[Z]` minutes.

### 5.3 Waiting Room Throttling (`/http_flood/waiting_room`)

Designed for flash sales, ticket drops, or viral traffic spikes:
- Automatically buffers requests in excess of backend capacity into a virtual queue returning **HTTP 465**.
- Shows clients an estimated wait time and dynamic position in queue.
- **Operator Metrics**: Tracks Active Users Allowed, Total Users Waiting, Peak Waiting Users, Average Wait Time, and User Bounce Rate.

---

## Module 6: Anti-Bot Defense (`/captcha`)

Provides automated challenge response to eliminate headless browsers, web scrapers, and credential-stuffing bots.

### 6.1 Challenge Verification Log Table

- Logs every challenge issued: Source IP, Country, Target Application, Hits, Verification Outcome (`Verified: 1` vs. `Verified: 0`), Duration, and Timestamp.
- Demonstrates three distinct challenge archetypes:
  1. **CAPTCHA Slide Challenge**: Interactive sliding visual puzzle.
  2. **Anti-Replay Demo**: Time-limited cryptographic nonces preventing automated request replay.
  3. **Proof-of-Work Challenge (HTTP 468)**: Background browser CPU puzzle (Altcha/Anubis standard) executing transparently without user friction.

### 6.2 Captcha Configuration

Clicking **"SETTINGS"** exposes the architectural challenge mode toggle:
- **Cloud Challenge (Default)**: Connects to Chaitin managed cloud verification services for enhanced risk scoring.
- **Local Challenge**:
  - `[x] Switch to Local Challenge`: Executes challenge verification purely on the local SafeLine node.
  - Guarantees zero external network dependencies, lower latency, and full compliance with strict air-gapped / data privacy regulations.

---

## Module 7: Pre-Application Authentication & SSO Portal (`/auth`)

Acts as an identity-aware gateway, enforcing enterprise authentication before unauthenticated HTTP traffic reaches protected backends.

### 7.1 Authentication Event Log (`/auth`)

Audits every login event: Account Name, Target Application, Login Method (`Account password`, `SSO`, `GitHub`), Result (`SUCCESS` / `FAIL`), Source IP, Country, and Timestamp.

### 7.2 Identity Configuration (`/auth/config`)

Managed across three sub-sections:

#### 1. User Management (`tab=user`)
- Internal user directory supporting up to **5,000 local accounts**.
- Tracks: Username, Application Permissions, Bound Third-Party Accounts, **2FA TOTP Status** (`Open` / `Close`), and Last Login Timestamp.
- Actions: Add User, reset passwords, and enforce two-factor authentication.

#### 2. Single Sign-On (SSO) Portal (`&cusTabVal=unified`)
- **Unified SSO Toggle**: Enables single sign-on across all selected applications.
- Once authenticated at the central SafeLine portal, users receive an encrypted clearance token (`sl_jwt_session`) valid across all authorized upstream sites.

#### 3. Login Configuration & Identity Providers (`&cusTabVal=config`)
- **Regular Login**: Username and Password credentials with custom branding (e.g. customized login portal title).
- **Third-Party Identity Providers (IdP)**:
  - **GitHub**: OAuth2 client ID and secret binding.
  - **OIDC (OpenID Connect)**: Standard enterprise SSO compatible with Okta, Keycloak, Auth0, Google Workspace, and Microsoft Entra ID.
  - **LDAP**: Active Directory / OpenLDAP directory connection (Host, Port, Base DN, Bind DN).

---

## Module 8: Settings, Operations & Cluster Management (`/system`)

The administrative headquarters of the WAF instance, divided into **Protections**, **Management**, and **System Log**.

### 8.1 Protections Configuration (`/system?tab=rules`)

```
System Protections Matrix
├── IP Group Management
│   ├── Enhanced Malicious IP Group (5,000 active threat IPs)
│   ├── Search Engine Spider Group (Verified spider CIDRs: Baidu, Google, Bing)
│   └── Malicious IP Intelligence Group (Dynamic community threat feed)
│
├── Client Fingerprint Intelligence
│   └── Enhanced Malicious JA4 Database (153 verified malicious TLS hashes)
│
├── SSL/TLS Certificate Store
│   └── Uploaded & automated certs with domain mapping, issuer, and validity dates
│
├── Custom HTTP Status Code & Error Pages
│   ├── 403: Attack Detected (Custom HTML template)
│   ├── 429: Rate Limiting
│   ├── 404: Website / Page Not Found
│   ├── 502: Bad Gateway
│   ├── 504: Gateway Timeout
│   ├── 465: Waiting Room Queue
│   ├── 466: Application Offline
│   ├── 467: Auth Challenge
│   └── 468: Anti-Bot Challenge
│
├── Engine Performance Mode
│   └── Toggle between Single-Thread Mode and Multi-Thread Mode
│
├── Data Retention & Auto-Pruning
│   ├── Protection Logs Retention (Not Clean, 1d, 3d, 7d, 15d, 30d)
│   └── Statistics Data Retention (Not Clean, 1d, 3d, 7d, 15d, 30d)
│
├── High Availability & Cluster Sync (Config Auto Sync)
│   ├── Active Master Node Controller
│   └── Slave Node Registry (Slave Machine Code, IP, Nginx Health Status, Last Sync)
│
├── Multi-Channel Alert Notifications
│   ├── Telegram Push Notifications
│   ├── Discord Webhook Push Notifications
│   ├── Custom HTTP Webhook Integration
│   └── Egress via Outbound Proxy
│
├── SIEM Integration
│   └── Remote Syslog Forwarding (Syslog Host + Port)
│
└── Threat Intelligence & Experience Program
    ├── Malicious IP Community Sharing
    ├── User Experience Optimization Data
    └── Desensitized Threat Intelligence Sharing
```

---

### 8.2 Management Console Settings (`/system?tab=console`)

1. **Administrator User Directory**: Manage console operator accounts with Role-Based Access Control (RBAC) and mandatory 2FA enforcement.
2. **OpenAPI Tokens & Developer Docs**:
   - **"GENERATE"** button creates long-lived API bearer tokens for programmatic control plane automation.
   - **Direct Swagger UI Integration**: Embedded OpenAPI documentation available at `https://demo.waf.chaitin.com:9443/swagger/index.html`.
3. **Web Console SSL Binding**: Binds an enterprise certificate specifically to admin port `9443`.
4. **Global Outbound Proxy**: Configures upstream HTTP/HTTPS proxy credentials (`Proxy Address`, `Username`, `Password`) for air-gapped nodes requiring proxy traversal for licensing, threat feeds, and alert webhooks.
5. **System Identity**: Displays version string (`9.4.2 Pro`) and unique hardware Machine ID (`NbgEi7rHjpUHhZtWpMCmzyHcnnZBK9Hw`).

---

### 8.3 System Audit Log (`/system?tab=logs`)

An append-only, tamper-evident audit record tracking every administrative modification:
- Fields: Operator Username (`admin`), Content (e.g. `Updated Authentication - SSO`, `User login`, `Updated Protection Settings - General Settings - Block Page`, `Downloaded Site - Site - Log`, `Updated Site - Certificate`), Source IP (`123.56.10.27`), and Timestamp.
