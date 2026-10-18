# Implementation Plan: Raiwall Domain 5 (Access Control & Zero-Trust Identity Gateway)

## Overview
Implement **Domain 5: Access Control (ACLs) & Zero-Trust Identity Gateway** for **Raiwall**: an enterprise-grade access control, threat feed matching, rule exception, and pre-application authentication architecture. 

Domain 5 delivers four integrated pillars:
1. **Granular Parameter-Level Exception Engine (Anti-False-Positive):** Suppresses specific detection rules matching `Host`, `Path Regex`, `HTTP Method`, exact `Parameter Location` (Query, Body, Header, Cookie) + `Parameter Name`, and `RuleID` (e.g. bypassing SQLi AST only on `/api/v1/posts` for field `markdown_content` while keeping SQLi protection active on all other parameters). Evaluated per-parameter prior to AST/lexical triage to conserve CPU.
2. **Sub-Microsecond CIDR & Threat Feed Engine (`gaissmai/bart`):** Balanced Routing Tables matching incoming IPv4/IPv6 client addresses against 500,000+ threat intelligence entries (CrowdSec, Spamhaus, AbuseIPDB) in $\sim 15\text{ ns}$, with atomic pointer swapping for zero-downtime hot reloads.
3. **GeoIP Lookups & ASN Extractor (`oschwald/maxminddb-golang`):** MaxMind GeoLite2/GeoIP2 reader for country code, continent, ASN, and organization filtering, with graceful zero-allocation fallback when databases are omitted.
4. **Compiled Bytecode Boolean ACL Engine (`expr-lang/expr`):** Compiles multi-condition rules (combining IP, CIDR, Country, ASN, Path, Method, Headers, Cookies) into bytecode evaluated in $<15\text{ ns}$ with ordered first-match-wins semantics and rich actions (`allow`, `block`, `challenge`, `redirect`, `audit`).
5. **Zero-Code Pre-Application Authentication Gateway (`pkg/auth`):** Dual-mode authentication (OIDC Single Sign-On via `coreos/go-oidc` + Simple local credential auth) placing a secure session wall in front of legacy or staging services, issuing signed JWT session cookies (`rw_session`), and injecting upstream identity headers (`X-Auth-Email`, `X-Auth-Subject`, `X-Auth-Roles`).

---

## Architecture Decisions

- **Pre-Inspection Parameter-Level Exception Gate:** Evaluated per parameter directly inside `SemanticEngine` prior to lexical triage and AST verification. Matching parameters skip inspection for the designated `RuleID` without modifying the request payload or wasting parser CPU cycles on known-safe fields.
- **Atomic Balanced Routing Table (`bart.Table`):** High-throughput radix/BART routing table (`gaissmai/bart`) for IP/CIDR lookups in $\sim 15\text{ ns}$. Threat feed updates use `atomic.Pointer[bart.Table]` for zero-lock hot-reloads under load.
- **Graceful GeoIP Fallback:** MaxMind reader operates without panics or errors if `.mmdb` files are missing or unconfigured, returning empty/unknown metadata so rules can degrade gracefully.
- **High-Performance Bytecode Evaluation (`expr-lang/expr`):** ACL rules are pre-compiled into bytecode during configuration provisioning and executed on a pooled environment struct, achieving sub-15ns decision times with zero allocations on the hot path.
- **Dual-Mode Zero-Code Pre-App Auth:** Supports both enterprise OIDC SSO (Google, Keycloak, Okta, Microsoft) and local Simple Auth for staging environments. Upon successful authentication, issues a tamper-proof signed JWT cookie and injects standardized `X-Auth-*` identity headers into upstream requests.
- **Modular Nested Caddyfile Directives:** Clean operator UX with dedicated `exceptions { ... }`, `acl { ... }`, and `auth { ... }` blocks within the `raiwall` directive.

---

## Dependency Graph

```
Exception Engine (pkg/acl/exception.go)
   │
   └── Semantic Engine Integration (pkg/engine/semantic.go)

BART Routing Table (pkg/acl/bart.go) & Feed Loader
   │
   ├── GeoIP Reader (pkg/acl/geoip.go)
   │       │
   │       └── Compiled Bytecode ACL Engine (pkg/acl/expr.go)
   │
Pre-App Auth Core (pkg/auth/oidc.go, simple.go)
   │
   └── JWT Session & Identity Injector (pkg/auth/session.go, handler.go)
           │
           └── Caddy Middleware Pipeline & Nested Caddyfile Directives (pkg/proxy)
                   │
                   └── End-to-End Integration & Benchmark Suite
```

---

## Task List Index

Tasks are tracked in `tasks/todo.md`:

### Phase 1: Granular Parameter-Level Exception Engine
- [ ] **Task 37: Parameter-Level Exception Engine Core & Pattern Matcher** (Size: S)
- [ ] **Task 38: Exception Gate Integration with Semantic Threat Engine** (Size: S)
- [ ] *Checkpoint: Parameter Exception Engine successfully suppresses false positives at parameter precision while keeping adjacent parameters protected.*

### Phase 2: High-Performance CIDR Routing (`bart`) & GeoIP Engine (`maxminddb`)
- [ ] **Task 39: Balanced Routing Table CIDR & Threat Feed Engine (`gaissmai/bart`)** (Size: M)
- [ ] **Task 40: MaxMind GeoIP Lookup Reader & ASN Extractor (`oschwald/maxminddb-golang`)** (Size: S)
- [ ] *Checkpoint: BART CIDR table and MaxMind GeoIP readers provide sub-microsecond IP threat and geographic intelligence.*

### Phase 3: Compiled Bytecode Boolean ACL Engine (`expr-lang/expr`)
- [ ] **Task 41: Compiled Bytecode ACL Engine & Expression Environment** (Size: M)
- [ ] *Checkpoint: Compiled bytecode ACL engine executes multi-condition rules in $<15\text{ ns}$ with rich action outcomes.*

### Phase 4: Zero-Code Pre-Application Authentication Gateway (`pkg/auth`)
- [ ] **Task 42: Dual-Mode Auth Core (Simple Local Auth + OIDC Discovery Client)** (Size: M)
- [ ] **Task 43: JWT Session Management, Upstream Identity Injection & Auth Endpoints** (Size: M)
- [ ] *Checkpoint: Zero-code pre-app auth wall secures legacy apps with OIDC/Simple auth and injects identity headers upstream.*

### Phase 5: Caddy Middleware Integration, Nested Caddyfile Directives & End-to-End Validation
- [ ] **Task 44: Caddy Middleware Wiring & Nested Caddyfile Directives (`exceptions`, `acl`, `auth`)** (Size: M)
- [ ] **Task 45: Domain 5 End-to-End Integration Tests & Micro-Benchmark Suite** (Size: M)
- [ ] *Checkpoint: Milestone 5 complete, all tests passing with `-race`, single binary builds cleanly under 50MB.*

---

## Risks and Mitigations

| Risk | Impact | Mitigation Strategy |
| :--- | :---: | :--- |
| **Exception Engine Over-Bypass** | **Critical** | Require explicit matching across `Host`, `Path`, `Method`, `Location`, and `ParamName`. Support exact `RuleID` targeting (e.g. `SEMANTIC_SQLI` only) rather than blanket WAF bypasses. |
| **Memory Exhaustion on 500K+ Threat Feeds** | **High** | `gaissmai/bart` Balanced Routing Tables use memory-efficient compressed prefix trees ($\sim 2\text{ MB}$ for 500K routes). Threat feeds are parsed streaming line-by-line without duplicate buffering. |
| **Missing or Corrupted GeoIP Database** | **Medium** | Safe no-op fallback when `.mmdb` is missing, unreadable, or omitted. Private/loopback IPs evaluate to unknown geo attributes without panicking. |
| **`expr` Expression ReDoS or Slow Evaluation** | **Medium** | Pre-compile and validate all expressions during Caddy provisioning; reject invalid ASTs at startup. Restrict expression environment to purely functional, bounded helpers. |
| **OIDC IdP Latency / Downtime** | **High** | Cache OIDC discovery documents and JWKS keys. Sessions rely on local stateless signed JWT cookies (`rw_session`), requiring IdP roundtrips only during initial login. |
| **Header Injection Spoofing by Untrusted Clients** | **High** | Always strip incoming `X-Auth-*` headers from incoming client requests at the gateway boundary before injecting verified auth claims. |

---

## Open Questions & Future Work
- **1-Click Create Exception from UI (Domain 6):** The Control Plane UI log viewer will provide a "Create Exception" action that pre-fills the exception dialog with the exact Host, Path, Method, Location, and ParamName from the forensic event.
- **Dynamic Cluster Threat Sync (Domain 7):** Real-time threat feed updates and IP ban distribution over Redis Pub/Sub across multi-node clusters.
