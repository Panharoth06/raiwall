# Anti-AI Slop UI & Enterprise Ergonomics Specification

> **Mandatory Rule for Coding Agents:** Raiwall is an enterprise-grade cybersecurity gateway and WAF operations center. All user interfaces must be utilitarian, high-density, performant, and grounded in real-world SOC workflows. Generic, decorative "AI slop" interfaces are **strictly prohibited**.

---

## 1. What is "AI Slop UI"?

AI coding agents have a strong tendency to generate generic, bloated, and uninspired interfaces characterized by:
- Huge nested cards with vast empty padding and low information density.
- Gratuitous purple/cyan neon gradients, shiny border glows, and heavy glassmorphism blur.
- Vacuous marketing copywriting ("Effortlessly manage your security posture with our cutting-edge AI engine").
- "Happy-path only" code that crashes or looks broken on empty datasets, long URLs, network errors, or narrow screens.
- Sluggish animations (`transition-all duration-500`) applied to every mundane click or page load.
- Inert decorative elements: badges that look like buttons but do nothing, fake graphs without responsive resize.

**In Raiwall, interfaces must disappear into the operator's task.** Familiarity, speed, readability, and information density outrank novelty.

---

## 2. The 6 Anti-Slop Directives

### Directive 1: Information Density Over Decorative Cards
*Security analysts monitor high-frequency telemetry. Every pixel must serve a purpose.*

* ❌ **BANNED:** Wrapping single metric lines in massive standalone cards with `p-8` or `p-10`.
* ❌ **BANNED:** Stacking multiple decorative container borders inside container borders.
* ✅ **MANDATORY:**
  - Prioritize dense tabular layouts over oversized card grids for collections of resources (Sites, Rules, Exceptions, Banned IPs, Logs).
  - Use monospaced tabular figures (`font-mono tabular-nums`) for numeric metrics, IP addresses, CIDR blocks, port numbers, latencies, and JA4 hashes so columns remain vertically aligned.
  - Keep table row heights compact (`py-2` to `py-2.5` with clean dividers).
  - Right-align numeric columns; left-align textual descriptions; center status badges.

### Directive 2: Ban Artificial "AI Aesthetic" Slop (Gradients, Glows, Glassmorphism)
*Raiwall is a mission-critical infrastructure tool, not a crypto landing page.*

* ❌ **BANNED:** Radial or linear neon gradients (e.g. `bg-gradient-to-r from-purple-500 to-indigo-500`).
* ❌ **BANNED:** Gratuitous neon box glows (e.g. `shadow-[0_0_25px_rgba(37,116,245,0.5)]`).
* ❌ **BANNED:** Heavy backdrop blur (`backdrop-blur-xl`) over solid data surfaces.
* ❌ **BANNED:** Decorative sparkle icons (`✨`, `Sparkles`) next to standard technical labels.
* ✅ **MANDATORY:**
  - Solid, clean surfaces using semantic tokens (`bg-background`, `bg-card`, `bg-muted`).
  - Crisp, subtle 1px borders (`border-border`).
  - Restrained high-contrast semantic color application (`text-threat`, `bg-threat/10`, `text-primary`).

### Directive 3: Extreme Color Restraint & The 90-10 Rule (Strictly Ban Rainbow Interfaces)
*Color in enterprise software is for signal, never for decoration. When everything is colorful, nothing stands out.*

* ❌ **BANNED: The Rainbow Badge Phenomenon:** Never use multi-colored rainbow palettes (purple, cyan, pink, fuchsia, lime, teal, orange, violet) for random categories, tags, or table chips.
* ❌ **BANNED: Colorful Icon Backgrounds:** Do NOT wrap icons in multi-colored circular or square pills (`bg-purple-500/10 text-purple-400`, `bg-blue-500/10 text-blue-400`, `bg-amber-500/10 text-amber-400`). Use neutral slate containers (`bg-muted text-muted-foreground`).
* ❌ **BANNED: Colored Card Borders:** Never give cards blue, purple, or cyan accent borders or tinted backdrops just to make them look "active" or "modern". All card surfaces and borders must remain neutral (`border-border`).
* ❌ **BANNED: Decorative Color Usage:** Never apply color to an element unless its color conveys a distinct semantic state (threat, clean, active). If removing the color does not change the operator's understanding, the color must be neutral grayscale (`text-muted-foreground`, `border-border`).
* ✅ **MANDATORY: The 90-10 Monochromatic Rule:**
  - **90% Neutral Grayscale:** 90%+ of any screen surface must consist of neutral grayscale tokens: `bg-background`, `bg-card`, `bg-muted`, `border-border`, `text-foreground`, `text-muted-foreground`.
  - **10% Semantic Signals Only:** The remaining 10% is strictly partitioned into three primary semantic signals:
    1. **Primary Brand Blue (`text-primary`, `bg-primary`):** Strictly for primary user interactions, active tabs, and primary action buttons.
    2. **Threat Red (`text-threat`, `bg-threat/10`):** Strictly for active attacks, blocked exploits, critical CVEs, and destructive delete confirmations.
    3. **Clean Green (`text-success`, `bg-success/10`):** Strictly for verified clean traffic, healthy upstream endpoints, and active bypass exceptions.
    4. **Warning Amber (`text-warning`, `bg-warning/10`):** Used sparingly as an exception state for transient warnings (staged changes, rate limit waiting queue, expiring TLS certificates).

### Directive 4: Mandatory 6-State Coverage (Zero Happy-Path-Only Code)
*Every view and component must explicitly implement all 6 real-world states:*

1. **Loading State:** Render structured skeleton pulse rows matching the table's exact column layout and count. Never show a raw blank container or a single centered spinner when replacing tabular data.
2. **Empty State:** Provide helpful, actionable empty states with an illustration/icon, clear explanation, and a direct primary CTA button:
   - *Bad:* "No data found."
   - *Good:* "No custom ACL rules configured. Custom rules evaluate in <15ns before semantic inspection. [ + Create First ACL Rule ]"
3. **Error & Timeout State:** Display human-readable error descriptions with a dedicated "Retry" action button. Never fail silently.
4. **Truncation & Long-String Safety:** Real HTTP traffic contains 2,000-character URLs, malicious payloads, and Base64 cookies.
   - Always apply `truncate` or `break-all` to prevent layout blowouts.
   - Provide full-text display via tooltip or drawer.
   - Include one-click "Copy" buttons for hashes, IPs, and cURL commands.
5. **Disabled & In-Flight State:** Form controls and submit buttons must show `opacity-50 cursor-not-allowed` with pending spinner feedback while mutations are inflight to prevent duplicate submissions.
6. **Keyboard Focus & Accessibility:** All interactive elements must maintain visible keyboard focus outlines (`focus-visible:ring-2 focus-visible:ring-ring focus-visible:outline-none`).

### Directive 5: Purposeful Motion (Zero Sluggish Choreography)
*Every millisecond of artificial animation delay degrades operator response time.*

* ❌ **BANNED:** Never animate keyboard shortcuts or frequent actions (command palette, search bar).
* ❌ **BANNED:** Never apply `transition-all duration-300` or `duration-500` to entire page layouts.
* ❌ **BANNED:** Never use `ease-in` on dropdowns or modals (feels sluggish and delayed).
* ❌ **BANNED:** Never use `active:scale-*` or CSS transform scaling on buttons/controls (causes subpixel text jitter, font blur, and feels out of place on enterprise desktop consoles).
* ✅ **MANDATORY:**
  - Use `ease-out` for entering elements (starts fast, feels instant).
  - Keep state transitions fast and crisp (`duration-150` or `duration-200`).
  - Use standard desktop press feedback: subtle background or brightness/opacity shifts (e.g. `active:bg-primary/80`, `active:brightness-95`, `active:opacity-90`), **never** `active:scale`.
  - Tab switches, filter changes, and table pagination must update instantly.

### Directive 6: Direct Technical Copywriting (No Marketing Fluff)
*Enterprise software communicates through crisp, deterministic verbs.*

* ❌ **BANNED:** "Welcome to the Threat Intelligence Suite! Seamlessly monitor incoming requests."
* ❌ **BANNED:** "Here you can manage your protected applications effortlessly."
* ✅ **MANDATORY:**
  - Lead with the noun or verb: "Applications", "Active Bans (14)", "Add Application", "Deploy Snapshot v42", "Rollback to v41".
  - Use exact technical terminology: "Sub-path prefix", "Weighted Round-Robin", "JA4 Fingerprint", "BART CIDR Lookup", "AES-256-GCM Clearance Cookie".

### Directive 7: Optical Alignment & Layout Consistency
*Visual cohesion comes from mathematical rigor in spacing and alignment.*

* ❌ **BANNED:** Arbitrary spacing chaos (`p-3.5`, `m-[13px]`, `gap-7`).
* ✅ **MANDATORY:**
  - Follow the 4px/8px Tailwind scale (`p-2`, `p-3`, `p-4`, `p-6`).
  - Ensure concentric border radii: parent container `rounded-lg` (8px) → inner nested elements `rounded-md` (6px) or `rounded-sm` (4px). Outer radius must always exceed inner radius.
  - Always center icons optically with text using `flex items-center gap-2`.
  - Icon sizes must match line heights (16px `w-4 h-4` for compact inline text; 20px `w-5 h-5` for primary navigation).

---

## 3. Pre-Merge Finish Gate Checklist

Before committing or completing any frontend task, verify against this hard gate:

- [ ] **Density Check:** Does this view present data efficiently without unnecessary empty card nesting?
- [ ] **No Slop Check:** Are all gradients, glows, and sparkles absent?
- [ ] **Color Restraint:** Is 90%+ of the screen neutral grayscale? Are rainbow badges, colorful icon chips, and colored card borders completely absent?
- [ ] **All States Handled:** Does the component handle Loading (skeletons), Empty (with CTA), Error (with retry), and Disabled?
- [ ] **Payload Overflow:** Did I test with an abnormally long string (URL/Payload/IP) to ensure no layout breakage?
- [ ] **Instant Response:** Do tabs, filters, and buttons feel responsive with $\le 150\text{ms}$ transitions and clean active feedback (zero `active:scale`)?
- [ ] **Semantic Tokens:** Are all colors using semantic Tailwind tokens mapped to CSS custom properties (`bg-card`, `text-foreground`, `border-border`)?
