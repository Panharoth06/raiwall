# Frontend Design & Visual Craft Specification

> **Mandatory Rule for Coding Agents:** Raiwall's user interface must not look like a generic, templated SaaS template or an off-the-shelf admin kit. Every view must reflect a distinctive, intentional point of view grounded in network engineering, telemetry instrumentation, and real-time cybersecurity defense.

---

## 1. Grounded in the Subject (Cybersecurity & Gateway Telemetry)

Raiwall is a high-throughput reverse proxy and semantic threat defense gateway. Its visual vernacular comes from **precision radar instrumentation, flight telemetry, and high-frequency network routers**:
- **Utilitarian & Unapologetic:** Interfaces should feel like professional industrial software (e.g. Grafana, Linear, Cloudflare Radar, Bloomberg Terminal, SafeLine).
- **Zero Cosmetic Fluff:** Avoid decorative rounded cards, floating gradient blobs, or generic illustrations.
- **Data as Interface:** The data itself (IPs, CIDRs, QPS, latencies, HTTP frames, attack vectors) provides the texture, geometry, and visual hierarchy of the page.

---

## 2. Spend Boldness in One Place (The Signature Element)

Do not scatter accents or visual noise across every corner of the screen. **Choose one signature moment per view** and keep everything surrounding it quiet, dark, and razor-sharp:
- **Topology View:** The interactive 3D WebGL Attack Globe and Sankey flow ribbons are the signature centerpiece. Surrounding metrics and tables are quiet grayscale panels.
- **Forensic Inspector View:** The high-density dual-tab triage drawer with syntax-highlighted exploit tokens and instant cURL reproduction is the signature element.
- **ACL / Rule Builder:** The real-time `expr` bytecode validator with inline syntax linting (<15ns evaluation indicator) is the signature element.
- **Standard Table Views (Sites, Upstreams, Policies):** The signature is extreme clarity—dense tabular figures, perfectly aligned columns, and zero visual friction.

---

## 3. Intentional Dual-Typography Hierarchy

Typography defines the technical personality of Raiwall:

### 3.1 Role Partitioning
1. **Primary Interface Face (`font-sans`):** High-clarity geometric technical sans (`Google Sans`, `-apple-system`, `BlinkMacSystemFont`, `Segoe UI`, `Roboto`).
   - Headings: `font-semibold tracking-tight` (dense and authoritative).
   - Eyebrows & Metadata Labels: `text-[10px] font-semibold uppercase tracking-wider text-muted-foreground`.
   - Body & Controls: `text-xs font-normal text-foreground`.
2. **Technical Utility & Data Face (`font-mono`):** High-readability monospace (`JetBrains Mono`, `Fira Code`, `ui-monospace`, `monospace`).
   - **MANDATORY:** Every IPv4/IPv6 address, CIDR prefix, port number, JA4 fingerprint, HTTP method (`GET`, `POST`), HTTP status code (`200`, `403`, `468`), latency metric (`12 µs`), and query payload MUST use `font-mono tabular-nums`.
   - Prevents jitter during real-time SSE telemetry updates.

---

## 4. Structure is Information (Never Decoration)

Structural elements must encode true architectural meaning:
- **Dividers & Splitters:** Use subtle 1px hairline rules (`border-border`) only where spatial separation clarifies ownership or parent-child hierarchy.
- **Eyebrows & Labels:** Eyebrows like `TIER 1 VELOCITY` or `JA4 FINGERPRINT` exist to specify an exact technical domain, not to fill white space.
- **No Decorative Numbering:** Never add arbitrary sequential markers (`01 / 02 / 03`) unless there is an actual temporal sequence (e.g. ACME challenge steps or a 3-stage threat verification pipeline).
- **Badge Semantics:** Badges are for system status (`BLOCKED`, `RATE_LIMITED`, `ONLINE`), never for decorative topic tags.

---

## 5. Active-Voice Technical Copywriting

All interface copy must speak from the operator's operational mental model:

| Anti-Pattern (Generic / Passive / Fluff) | Raiwall Standard (Active / Deterministic / Direct) |
| :--- | :--- |
| "Here you can manage your upstreams." | "Upstream Pool (3 nodes healthy)" |
| "Submit" / "Save" / "Apply" | "Deploy Snapshot v42" / "Add Exception" / "Unblock IP" |
| "Are you sure you want to delete this site?" | "Permanently remove api.example.com and terminate proxying?" |
| "Operation failed due to an unexpected error." | "Dial tcp 10.0.0.5:8080: connection refused. Upstream unreachable." |
| "No attacks found." | "Zero attacks recorded in the last 24 hours. Traffic is clean." |

### Cohesive Verb Matching
Actions must maintain identical vocabulary across buttons, modals, and toasts:
- Button: `[ Unblock All Clients ]`
- Confirmation Modal: `Unblock 14 Banned Clients`
- Success Toast: `14 clients unblocked from local ban registry.`

---

## 6. The Two-Pass Design Review

Before writing or modifying frontend components, perform this two-pass self-critique:

1. **Pass 1: Concept & Signature**
   - What is the single job of this screen?
   - What is the one memorable signature element?
   - Is 90%+ of the surface quiet, neutral grayscale?
2. **Pass 2: Generic Check**
   - Does this look like an off-the-shelf dashboard template?
   - Are there decorative cards that should be a dense table?
   - Are numbers and technical tokens strictly in `font-mono tabular-nums`?
   - Are the action buttons using active, deterministic verbs?
