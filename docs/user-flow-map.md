# SafeLine WAF — User Flow & Journey Maps

This document maps out the operator workflows, interactive state transitions, navigation paths, and user journeys within Chaitin SafeLine WAF v9.4.2.

---

## 1. Core Operator Personas & Objectives

| Persona | Primary Modules Used | Typical Objectives |
| :--- | :--- | :--- |
| **SOC Security Analyst** | Attacks, Statistics, Allow & Deny | Monitor real-time attack events, inspect payloads, identify zero-day or exploit attempts, triage false positives, and whitelist safe endpoints. |
| **DevOps / Gateway Engineer** | Applications, Settings, HTTP Flood | Onboard new upstream domains, bind multi-port listeners, configure SSL/TLS certificates, setup path-prefix routing, tune upstream proxy headers, and establish HA clusters. |
| **Infrastructure / SRE** | HTTP Flood, Waiting Room, Anti-Bot | Mitigate Layer 7 volumetric floods, activate the Waiting Room during traffic peaks, configure IP velocity rate limits, and select local vs. cloud bot challenges. |
| **IAM / Security Architect** | Auth, Settings | Enforce zero-trust access control before upstream applications, integrate enterprise SSO (OIDC/LDAP), issue API tokens, and audit admin change logs. |

---

## 2. Interactive Navigation State Machine

```mermaid
stateDiagram-v2
    [*] --> Dashboard: Login Successful
    
    state Dashboard {
        TrafficAnalysis: Traffic Analysis (/statistics)
        SecurityPosture: Security Posture (/statistics/security)
    }

    state Applications {
        AppList: Application Inventory (/sites)
        AddAppModal: Add Application Dialog
        
        state AppDetail {
            BasicInfo: Basic Info & Upstreams
            ForwardingRules: Path-Prefix Routing
            AdvancedConfig: Proxy Headers, SSL, HSTS, NTLM
            Routings: Auto-Discovered API Endpoints
        }
    }

    state Attacks {
        EventsView: Aggregated Attack Incidents
        LogsView: Raw Attack Logs
        ForensicDrawer: Request/Response & JA4 Inspector
        SemanticMatrix: 14 Semantic Modules Config (/attact_events/semantics)
        EnhancedRules: 193 CVE Signatures (/attact_events/inner_rules)
    }

    state AllowDeny {
        HitLogs: Rule Execution Logs
        CustomRules: Whitelist & Blacklist Matrix
        RuleBuilder: Boolean Logic Condition Dialog
    }

    state HTTPFlood {
        ActiveBlocks: Blocked Clients Table
        TieredConfig: 3-Tier Limits Config
        WaitingRoom: Flash Crowd Traffic Queue
    }

    state AntiBot {
        ChallengeTable: Bot Challenge Logs
        CaptchaConfig: Local vs Cloud Mode
    }

    state Auth {
        AuthLogs: Login Event Stream
        UserMgmt: 5000 User Directory & 2FA
        SSOGateway: Unified SSO Portal
        IdPConfig: LDAP, OIDC, GitHub
    }

    state Settings {
        Protections: IP Groups, JA4 DB, Custom Block Pages, HA
        Management: Admin Accounts, OpenAPI Tokens, Swagger UI
        SystemLogs: Immutable Audit Trail
    }

    Dashboard --> Applications: Manage Sites
    Dashboard --> Attacks: Investigate Security Spike
    
    AppList --> AddAppModal: Click 'ADD APPLICATION'
    AppList --> BasicInfo: Click 'DETAIL'
    BasicInfo --> ForwardingRules
    BasicInfo --> AdvancedConfig
    BasicInfo --> Routings

    Attacks --> EventsView: Top Attackers
    EventsView --> LogsView: Drilldown Specific Attacker
    LogsView --> ForensicDrawer: Click 'Detail'
    ForensicDrawer --> AllowDeny: Add Whitelist Exception
    ForensicDrawer --> Settings: Add IP to Blacklist Group
    Attacks --> SemanticMatrix: Click 'SEMANTIC ANALYSIS'
    Attacks --> EnhancedRules: Click 'ENHANCED RULES'

    AllowDeny --> CustomRules: Click 'CUSTOM RULES'
    CustomRules --> RuleBuilder: Click 'ADD RULES'

    HTTPFlood --> TieredConfig: Click 'SETTINGS'
    HTTPFlood --> WaitingRoom: Click 'Waiting Room'

    AntiBot --> CaptchaConfig: Click 'SETTINGS'

    Auth --> UserMgmt: Click 'SETTINGS'
    UserMgmt --> SSOGateway: Tab 'SSO'
    UserMgmt --> IdPConfig: Tab 'LOGIN CONFIGURATION'

    Settings --> Protections: Tab 'PROTECTIONS'
    Settings --> Management: Tab 'MANAGEMENT'
    Settings --> SystemLogs: Tab 'SYSTEM LOG'
```

---

## 3. Step-by-Step Operator User Flows

### Flow A: Attack Investigation & Remediation Flow

```mermaid
sequenceDiagram
    autonumber
    actor Analyst as SOC Analyst
    participant Dash as Dashboard (/statistics)
    participant Atk as Attacks Forensics (/attact_events)
    participant Insp as Forensic Inspector Modal
    participant Rule as Custom Rules (/allow_deny_events)

    Analyst->>Dash: Notices spike in "SQL Inj" and "Cmd Inj" in Security Posture
    Analyst->>Dash: Clicks on top attack IP (e.g. 182.11.1.196)
    Dash->>Atk: Navigates to Attack Events filtered by IP
    Atk->>Atk: Displays aggregated incident: "6 requests blocked in 4 minutes"
    Analyst->>Atk: Clicks "6 requests blocked"
    Atk->>Atk: Automatically switches to LOGS view with pre-filled filters
    Analyst->>Atk: Selects specific request and clicks "Detail"
    Atk->>Insp: Opens Forensic Inspector Drawer
    Insp-->>Analyst: Displays: Payload (1 and 1=1), Location (URLPATH), JA4 Fingerprint, Raw HTTP Request & Response
    
    alt If Malicious Attacker
        Analyst->>Insp: Clicks "Add to IP Group"
        Insp->>Rule: Inserts IP into "Enhanced Malicious IP Group" with 0-delay sync
    else If Business False Positive
        Analyst->>Insp: Clicks "Copy as cURL" to verify with developers
        Analyst->>Rule: Creates Whitelist rule targeting Path + Host + Param with "Continue to log" enabled
    end
```

**Key Interactions in Flow A:**
1. **Context Preservation**: Clicking an attack incident in the `EVENTS` tab auto-populates the query parameters in the `LOGS` tab (`ip`, `host`, `port`, `action`, `start`, `end`), preventing manual entry.
2. **Forensic Integrity**: The drawer allows inspecting the exact payload extracted by the AST/lexical engine (`URLPATH: 1 and 1=1`), the client JA4 TLS hash, and offers one-click **"Copy as cURL"** for offline reproduction.
3. **In-place Remediation**: Direct action buttons inside the drawer allow blacklisting the source IP or whitelisting the transaction.

---

### Flow B: Onboarding a New Application / API Gateway

```mermaid
flowchart TD
    Start(["Operator clicks 'ADD APPLICATION'"]) --> Modal["Open Add Application Modal"]
    Modal --> Step1["1. Enter Domain Name (Supports '*' wildcard)"]
    Step1 --> Step2["2. Configure Listening Ports<br/>(e.g., 80 HTTP + 443 HTTPS)"]
    Step2 --> Step3["3. Bind SSL/TLS Certificate"]
    Step3 --> Step4{"4. Select Access Method"}
    
    Step4 -->|"Reverse Proxy (Default)"| ProxyOpts["Add Upstream Backend IPs/Ports<br/>(Health Checks, Load Balancing Weights)"]
    Step4 -->|"Static Files"| StaticOpts["Specify Document Root Directory"]
    Step4 -->|"Redirect"| RedirectOpts["Define 301/302 Target URL"]
    
    ProxyOpts & StaticOpts & RedirectOpts --> Submit["Click 'SUBMIT'"]
    Submit --> SiteCard["Application created in Defense Mode"]
    
    SiteCard --> Detail["Click 'DETAIL' for Advanced Configuration"]
    Detail --> Forwarding["Add Path-Prefix Forwarding Rules<br/>(e.g. /api/v1 -> microservice upstream)"]
    Detail --> Advanced["Tune Advanced Proxy:<br/>• Get IP from XFF or Socket<br/>• Clear & rewrite XFF<br/>• Enable HSTS & SSE Streaming<br/>• Gzip / Brotli Compression<br/>• Custom NGINX block"]
    Detail --> Discovery["Monitor 'ROUTINGS' Tab for Auto-Discovered Endpoints"]
```

---

### Flow C: Three-Tier DDoS & Anti-Bot Defense Flow

SafeLine coordinates volumetric defense across three cascading tiers before triggering full IP bans:

```mermaid
flowchart TD
    Req(["Incoming Client Request"]) --> T1{"Tier 1: Access Velocity Limit<br/>(e.g., >100 req / 10s)"}
    
    T1 -->|"Normal"| CleanTraffic["Pass to ACL & WAF"]
    T1 -->|"Exceeded"| Challenge["Action: Anti-Bot Challenge (1 to 60 min)"]
    
    Challenge --> ChallengeType{"Challenge Mode Configured"}
    ChallengeType -->|"Local Mode"| LocalChallenge["Stateless SHA-256 Proof-of-Work (HTTP 468)<br/>or Local Sliding CAPTCHA"]
    ChallengeType -->|"Cloud Mode"| CloudChallenge["Chaitin Managed Cloud CAPTCHA"]
    
    LocalChallenge & CloudChallenge --> Verify{"Challenge Passed?"}
    Verify -->|"Yes"| IssueCookie["Issue Clearance HMAC Cookie -> Allow Access"]
    Verify -->|"No / Script Bot"| DropReq["Reject Connection"]
    
    CleanTraffic --> T2{"Tier 2: Attack Frequency Limit<br/>(e.g., >10 attack blocks / 60s)"}
    T2 -->|"Exceeded"| AutoBan1["Action: Auto-Ban IP (30 min)"]
    
    CleanTraffic --> T3{"Tier 3: Error Rate Scanner Trap<br/>(e.g., >10 upstream 403/404 / 10s)"}
    T3 -->|"Exceeded"| AutoBan2["Action: Auto-Ban Scanner IP (30 min)"]
    
    CleanTraffic --> Queue{"Flash Crowd Traffic Peak?"}
    Queue -->|"Waiting Room Active"| WaitRoom["Divert to Waiting Room Queue (HTTP 465)<br/>Displays Queue Position & Wait Time"]
```

---

### Flow D: Pre-Application Zero-Trust Identity Authentication Flow

SafeLine features an integrated identity verification gateway (*Auth Challenge*), intercepting unauthenticated traffic before it touches upstream applications:

```mermaid
sequenceDiagram
    autonumber
    actor User as End User
    participant WAF as SafeLine Gateway
    participant IdP as Identity Provider (OIDC/LDAP/Local)
    participant App as Protected Upstream App

    User->>WAF: GET /internal/admin-portal
    WAF->>WAF: Evaluates Auth Gate: Application requires Authentication
    WAF->>WAF: Checks Session Cookie / JWT Clearance Token
    
    alt Unauthenticated
        WAF-->>User: Returns HTTP 467 Auth Challenge (Login Portal)
        User->>WAF: Submits Credentials (Username/Password or SSO redirect)
        WAF->>IdP: Verifies with Local DB / LDAP / Okta / GitHub
        IdP-->>WAF: Auth Validated + 2FA TOTP Verified
        WAF->>WAF: Generates encrypted clearance cookie (`sl_jwt_session`)
        WAF-->>User: Redirects back to /internal/admin-portal with clearance cookie
    end

    User->>WAF: GET /internal/admin-portal (with clearance cookie)
    WAF->>WAF: Validates clearance cookie
    WAF->>App: Proxies request to upstream service
    App-->>User: Returns Application Content
```

---

### Flow E: Cluster Operations & High Availability (Master-Slave Sync)

SafeLine supports enterprise multi-node deployment with automated synchronization:

```mermaid
flowchart LR
    subgraph MasterNode["MASTER NODE (Control Plane + Data Plane)"]
        WebConsole["Web Console (Port 9443)"]
        ConfigDB[("Primary Database & Rules")]
        MasterEngine["WAF Engine"]
    end

    subgraph SlaveNode1["SLAVE NODE 1 (Data Plane)"]
        SyncClient1["Config Sync Agent"]
        SlaveEngine1["WAF Engine"]
    end

    subgraph SlaveNode2["SLAVE NODE 2 (Data Plane)"]
        SyncClient2["Config Sync Agent"]
        SlaveEngine2["WAF Engine"]
    end

    WebConsole --> ConfigDB
    ConfigDB --> MasterEngine
    ConfigDB -.->|"Machine Code Handshake & TLS Sync"| SyncClient1
    ConfigDB -.->|"Machine Code Handshake & TLS Sync"| SyncClient2
    SyncClient1 --> SlaveEngine1
    SyncClient2 --> SlaveEngine2
    
    SyncClient1 & SyncClient2 -.->|"Nginx Health Heartbeat"| WebConsole
```

1. **Slave Registration**: Operator inputs Slave Machine Code and IP Address in `Settings -> Protections -> Config Auto Sync`.
2. **Version Pinning**: SafeLine verifies that all nodes share identical version numbers (e.g., `9.4.2`) and compatible license tiers.
3. **Hot Configuration Push**: Changes made on Master (sites, semantic thresholds, IP groups, rate limits) sync across all slaves in sub-second latency.
4. **Health Heartbeat**: Master dashboard continuously displays node sync status (`Normal`, `Synchronizing`, `Offline`).
