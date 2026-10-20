# UI Color Consistency & Semantic Token Design System

> **Mandatory Rule for Coding Agents:** All web user interfaces in Raiwall must use semantic Tailwind tokens backed by CSS custom properties. Arbitrary hex color values (e.g. `bg-[#181b20]`, `text-[#EF4444]`, `border-[#2d3440]`) are **strictly prohibited** in component templates and styles.

---

## 1. Core Principles

1. **Semantic Over Literal:** Choose classes based on what the element *represents* (`bg-card`, `text-muted-foreground`, `border-border`), never how you think the color looks in isolation.
2. **Dual-Theme Compatibility:** The application supports both Dark (default cybersecurity console) and Light modes. Never hardcode `text-white`, `bg-black`, `text-slate-100`, or arbitrary hex strings like `bg-[#1e222a]`, as they break in light mode.
3. **Domain-Specific Security States:** Always use first-class security status tokens for WAF state representations (`threat`, `success`, `warning`, `info`) instead of arbitrary green/red/amber utilities.
4. **The 90-10 Color Budget (No Rainbow Interfaces):** At least 90% of every screen must be neutral grayscale (`bg-background`, `bg-card`, `bg-muted`, `border-border`, `text-foreground`, `text-muted-foreground`). Color is strictly reserved for the remaining 10% as high-salience functional signals (`primary` for main actions, `threat` for attacks, `success` for clean/healthy). Never use decorative rainbow palettes (purple, cyan, lime, orange, fuchsia) on badges, cards, or icon backgrounds.

---

## 2. Canonical Token Hierarchy

All tokens are defined as HSL custom properties in `web/src/style.css` and exposed via `web/tailwind.config.js`.

### 2.1 Surfaces & Canvas

| Purpose | Tailwind Class | Semantic Meaning |
| :--- | :--- | :--- |
| **App Canvas** | `bg-background` | The outermost page canvas background. |
| **Cards & Panels** | `bg-card` | Contained content cards, table containers, widgets. |
| **Elevated / Popovers** | `bg-popover` | Modals, dropdown menus, flyout tooltips, forensic drawers. |
| **Subtle Inset / Rails** | `bg-muted` | Table headers, code blocks, inactive tabs, input background. |
| **Secondary Surface** | `bg-secondary` | Secondary buttons, badge backdrops, subtle chips. |

### 2.2 Typography & Foreground

| Purpose | Tailwind Class | Semantic Meaning |
| :--- | :--- | :--- |
| **Primary Text** | `text-foreground` | High-contrast body text, headings, prominent labels. |
| **Card Text** | `text-card-foreground` | Content text inside card surfaces. |
| **Muted / Subtext** | `text-muted-foreground` | Descriptions, timestamps, secondary metadata, placeholders. |
| **Interactive Text** | `text-primary` | Links, active tab text, branded indicators. |

### 2.3 Borders & Dividers

| Purpose | Tailwind Class | Semantic Meaning |
| :--- | :--- | :--- |
| **Structural Border** | `border-border` | Standard card borders, table dividers, panel splitters. |
| **Input Outlines** | `border-input` | Form controls, select dropdowns, search bars. |
| **Focus Rings** | `ring-ring` | Keyboard accessibility focus rings. |

### 2.4 Brand & Primary Actions

| Purpose | Tailwind Class | Semantic Meaning |
| :--- | :--- | :--- |
| **Primary Action** | `bg-primary text-primary-foreground` | Main CTA buttons, active radio buttons, active tab indicators. |
| **Primary Hover** | `hover:bg-primary/90` | Hover state for primary buttons. |
| **Primary Ghost** | `text-primary hover:bg-primary/10` | Ghost/flat buttons with brand tint. |

### 2.5 Security Domain Tokens (First-Class WAF Semantics)

| State | Background / Fill | Text Class | Border Class | Context & Usage |
| :--- | :--- | :--- | :--- | :--- |
| **Threat / Attack** | `bg-threat/10` | `text-threat` | `border-threat/30` | Blocked attacks, SQLi/XSS triggers, ban events, critical CVEs. |
| **Clean / Allowed** | `bg-success/10` | `text-success` | `border-success/30` | Clean traffic, bypassed exceptions, healthy upstream node. |
| **Warning / Challenge** | `bg-warning/10` | `text-warning` | `border-warning/30` | Bot PoW challenge (468), Rate-limiting queue (465), degraded health. |
| **Info / Discovery** | `bg-info/10` | `text-info` | `border-info/30` | Audit mode events, auto-discovered shadow APIs, TLS cert info. |

---

## 3. Negative Constraints & Prohibited Patterns

Agents must strictly avoid these antipatterns:

- ❌ **NO arbitrary hex backgrounds:**
  `bg-[#181b20]`, `bg-[#1e222a]`, `bg-[#14171d]`, `bg-[#17223B]`, `bg-[#080A0C]`  
  👉 **USE:** `bg-background`, `bg-card`, `bg-muted`, `bg-secondary`
- ❌ **NO arbitrary hex borders:**
  `border-[#2d3440]`, `border-[#363D4C]`, `border-[#1E232D]`  
  👉 **USE:** `border-border`, `border-input`
- ❌ **NO arbitrary hex text colors:**
  `text-[#848D9C]`, `text-[#B0B8C4]`, `text-[#2574F5]`, `text-[#EF4444]`  
  👉 **USE:** `text-muted-foreground`, `text-primary`, `text-threat`
- ❌ **NO hardcoded white/black text:**
  `text-white`, `text-black`, `text-slate-100`  
  👉 **USE:** `text-foreground`, `text-card-foreground`, `text-muted-foreground`
- ❌ **NO inline CSS color styles:**
  `style="background-color: #17223B"`  
  👉 **USE:** Tailwind semantic utility classes.

---

## 4. Migration Quick Reference

When touching or refactoring existing Vue templates:

| Legacy / Prohibited Syntax | Replacement Semantic Token |
| :--- | :--- |
| `bg-[#181b20]`, `bg-[#080A0C]` | `bg-background` |
| `bg-[#1e222a]`, `bg-[#17223B]` | `bg-card` |
| `bg-[#14171d]`, `bg-[#11141A]` | `bg-muted` |
| `border-[#2d3440]`, `border-[#363D4C]`, `border-[#1E232D]` | `border-border` |
| `text-slate-100`, `text-white` | `text-foreground` |
| `text-slate-400`, `text-[#848D9C]`, `text-subtext` | `text-muted-foreground` |
| `text-[#2574F5]`, `text-activeBlue` | `text-primary` |
| `text-[#EF4444]`, `text-threatRed`, `text-red-500` | `text-threat` |
| `text-[#10B981]`, `text-cleanEmerald`, `text-green-500` | `text-success` |
| `text-[#FFC000]`, `text-brand`, `text-yellow-500` | `text-warning` |
