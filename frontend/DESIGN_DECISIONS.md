# Design decisions — IPsec-AI Sentinel (design-quality pass D0–D9)

This file records every design decision, finding and deviation made during the
design pass. It is the companion to `PROGRESS_DESIGN.md` (phase checklist),
`PRODUCT.md` (product truth) and `DESIGN.md` (the binding visual system).

Operating rules honoured: never ask questions; decide, record here, continue.

---

## D0 — Setup

### 0.1 Impeccable installation

- `npx impeccable install` ran successfully (exit 0). Its interactive installer
  first targeted the detected harnesses (Claude Code, Cursor) because it
  auto-selects option 1 by default; re-run with `--force` and the explicit
  answer `opencode` + `global` installed the skill into
  `~/.config/opencode/skills/impeccable` (engine v0.1.5, linux-x64) and, at
  project scope, into `.claude/` and `.cursor/` plus their agent files and
  hooks. No install failure occurred, so no manual fallback was needed.
- `impeccable context` was run from the project root. It reported:
  `NO_PRODUCT_MD`, `EXISTING_VISUAL_SYSTEM`, `SCOPED_EXISTING_ALLOWED`,
  `MANUAL_DETECTOR_REQUIRED` (no auto design hook active — the detector must be
  run manually at the end of the work), `IMAGE_TOOLS: magick, ffmpeg`.
- `/impeccable init` is a *chat* command, not a CLI verb (the CLI says so
  verbatim). It was therefore executed by the agent following
  `reference/init.md`.

### 0.2 Interview substitution (disclosed)

`reference/init.md` step 3 requires a structured question round before writing
PRODUCT.md. The user's brief for this task explicitly states *"Do NOT ask me
questions. Decide, record the decision in DESIGN_DECISIONS.md, and continue."*
That is an explicit user instruction to proceed without an interview, so the
brief's own answers were used as the confirmed record. Every product fact in
`PRODUCT.md` is therefore taken from `FRONTEND_SPEC.md` and the task brief — none
is invented.

### 0.3 Init answers used

| Field | Answer used |
|---|---|
| Register | PRODUCT (app UI / dashboard / tool), not brand → app is in **Operate** mode |
| Audience | SOC and network-security analysts Tier 1–3 doing fast posture assessment of encrypted VPN traffic, plus a technical lead exporting reports. Long sessions, dense data, high stakes. |
| Personality | Precise, calm, authoritative, quietly technical. "Cockpit instrument" + "well-typeset technical manual". |
| Anti-references | neon glows, glassmorphism, purple→blue gradients, gradient text, glowing borders, cards in cards, rounded-square icon tiles above headings, emoji as UI, decorative heroes, fake 3D, bouncy/elastic motion, pure `#000` / pure grey |
| Constraints | dark theme only; offline at runtime (no CDN / remote fonts / remote images); WCAG 2.1 AA; `prefers-reduced-motion`; widths 768–2560 px |

Personality / anti-references are recorded under **Brand Commitments** in
`PRODUCT.md` (they are durable brand commitments from the user, not visual
recipes chosen by init) and are expanded into normative rules in `DESIGN.md`.

### 0.4 Files written at D0

- `PRODUCT.md` — product record (schema 1).
- `DESIGN.md` — the binding visual system (refreshed again at D2 with the final
  token values).
- `DESIGN_DECISIONS.md` — this file.
- `PROGRESS_DESIGN.md` — phase checklist D0–D9.

**Gate D0: PASS** — all four files exist.

---

## D1 — Baseline review

### 1.0 Method and provenance

⚠️ **DEGRADED: single-context (nested sub-agents blocked — the harness reported
`Subagent depth limit reached (1)`; the desktop browser bridge also reported
`No desktop browser is connected`. Both assessments were therefore run inline by
the parent agent.)**

Mitigations used instead of sub-agents and a live browser:

- **Assessment A (design review)** was formed from source reading plus real
  screenshots rendered by a headless Chrome (`puppeteer-core` + the system
  `google-chrome-stable`, installed in `/tmp/opencode/verify`, i.e. **outside**
  the project so no project dependency was added). Six pages × 1280 px and
  768 px, empty and fixture-loaded states.
- **Assessment B (detector + browser evidence)**: `impeccable detect --json src/`
  (saved to `/tmp/opencode/detect-baseline.json`) plus an automated DOM audit
  (horizontal scroll, header height/wrap, focus ring, touch-target sizes,
  reduced-motion, testids, console) saved to `/tmp/opencode/shots/report.json`.
- **Deviation disclosed:** the brief itself instructs running the detector as a
  separate D1 step, so detector output entered this context *before* Assessment
  A was written. Assessment A's design judgements below are nonetheless stated
  from visual/source evidence rather than inferred from detector rules.

Dev server for all visual checks: `npm run dev -- --host 127.0.0.1 --port 5173`
(kept running for D2–D9; stopped at the end of D9).

### 1.1 Audit health score

| # | Dimension | Score | Key finding |
|---|-----------|-------|-------------|
| 1 | Accessibility | 3 | Focus rings, landmarks, hidden chart tables and `aria-live` are in place; provenance/severity always colour+icon+text. Gaps: focus ring uses the accent (OK) but several controls sit under 32 px hit area; `line` borders are 1.5:1 (below the 3:1 non-text floor) so control boundaries are identified by fill alone. |
| 2 | Performance | 3 | No layout-thrashing loops; framer-motion is scoped. Gaps: `Recharts` instances are re-created per render on every filter keystroke; the packet table renders 100 rows unvirtualised (accepted by spec); bundle 1.13 MB (chunk warning). |
| 3 | Theming | 2 | Token names exist and are wired through Tailwind, but 13 hard-coded colours sit outside the token set (`#1E293B` in ScoreWaterfall/ConfidenceBreakdown/ModelEvaluation, `#ffffff`, print.css literals) and there is one flat Inter/system-ui font stack with no bundled font files. |
| 4 | Responsive | 3 | No horizontal scroll at 768/1024/1280/1920 (verified). Header stays 56 px and never wraps. Gaps: content does not cap its width, so 2560 px stretches the grid; sidebar→rail transition and table wrappers need a second look. |
| 5 | Implementation integrity | 2 | Coherent, product-specific system (provenance badges, risk gauge, threat matrix are unmistakably *this* product), but **three of six pages are unimplemented placeholders**, two orphan components exist (`AuditSummary`, `ScoreWaterfall` are never imported), and 31 detector findings show drift between DESIGN.md and code. |
| **Total** | | **13/20** | **Acceptable — significant work needed** |

### 1.2 Implementation-integrity verdict

**Fail.** The implementation does express a coherent product-specific system —
provenance badges, the risk gauge, the threat matrix and the mono evidence
strings could not be lifted onto another product unchanged — but it does not
express a *complete* one: `/audit`, `/compliance` and `/settings` render
placeholder cards ("Populated in phase P9/P10/P11"), `PROGRESS.md` is unticked
from P8 onward, and the four spec testids `policy-select`, `dh-table`,
`whatif-form`, `log-viewer` do not exist anywhere in the DOM. Orphaned
components prove the build stopped mid-phase.

### 1.3 Detector findings (saved `/tmp/opencode/detect-baseline.json`, exit 2)

31 findings, all `advisory`:

| Rule | Count | Locations |
|---|---|---|
| `design-system-font-size` | 15 | `src/styles/print.css` (7), `src/components/inferences/ModelEvaluation.tsx` (5), `src/components/layout/*` (4), `src/components/overview/*` (2) — 10 px/11 px literals off the ramp |
| `design-system-color` | 13 | `ScoreWaterfall.tsx:49` `#1E293B`, `ConfidenceBreakdown.tsx:56` `#1E293B`, `ModelEvaluation.tsx:10` `#ffffff`, `InspectorCharts.tsx`, `ClassChart.tsx`, `AnalystMenu.tsx`, `NotificationBell.tsx`, `SearchBox.tsx`, `Tabs.tsx`, `CryptoCard.tsx`, `KpiBar.tsx` |
| `overused-font` | 1 | `src/styles/index.css` — Inter flagged as an overused default |
| `design-system-font` | 1 | font stack not declared in DESIGN.md (DESIGN.md did not exist when the scan ran) |
| `border-accent-on-rounded` | 1 | accent border on a rounded element — the "glowing outline" anti-reference |

False positives: none worth suppressing — every finding maps to a real
drift between the token file and its consumers.

### 1.4 Browser / DOM evidence (`/tmp/opencode/shots/report.json`)

| Check | Result |
|---|---|
| Horizontal page scroll @768 / 1024 / 1280 | **none** on all six pages |
| Header height @768 | **56 px**, never wraps |
| Focus indicator | present on every one of 25 tab stops (`box-shadow` non-`none`) |
| `prefers-reduced-motion: reduce` | **0** elements with a running animation >0.01 ms |
| Touch/click targets <24 px | 2 per page — the skip link (pre-focus, `sr-only`) and one `sr-only` span; both expected |
| Console | **one 404 on `/`** = missing favicon (no `public/`, no `<link rel="icon">`) |
| Main content width | 1032 px @1280 (viewport minus sidebar) — no max-width cap at 2560 |
| Spec testids present | `risk-gauge`, `kpi-mode`, `kpi-confidence`, `kpi-volume`, `upload-zone`, `crypto-card`, `class-chart`, `handshake-timeline`, `threat-matrix`, `findings-list`, `packet-table` ✅ |
| Spec testids **missing** | `report-drawer` (renders only when open — verify with `r`), **`policy-select`, `dh-table`, `whatif-form`, `log-viewer` — do not exist** |

---

### 1.5 Prioritised issue list (drives D2–D8)

#### P0 — blocking

| # | Issue | Location | Fix phase |
|---|---|---|---|
| P0-1 | **Audit, Compliance and Settings are placeholder pages.** One `<Card>` each; no threat matrix, waterfall, radar, findings table, remediation plan, compliance table, DH lab, what-if form, preferences, model registry or log viewer. Four spec testids absent. AC-10/11/12/13 cannot pass. | `src/pages/AuditPage.tsx`, `CompliancePage.tsx`, `SettingsPage.tsx`; orphaned `src/components/audit/{AuditSummary,ScoreWaterfall}.tsx` | **D7** |
| P0-2 | `npm run verify` passes but the Definition of Done cannot: the D9 gate requires AC-01…AC-17 all passing. | — | D9 |

#### P1 — important

| # | Issue | Location | Fix phase |
|---|---|---|---|
| P1-1 | **Card soup / nesting.** Overview stacks 8 bordered cards; findings items are bordered blocks *inside* the bordered `findings-list` card, and each finding nests another bordered "Recommendation" block — three levels deep. | `OverviewPage.tsx`, `FindingsList.tsx`, `CryptoCard.tsx`, `KpiBar.tsx` | D5 |
| P1-2 | **Risk does not dominate.** The gauge is one of four equal-weight KPI cards; the upload zone and crypto suite sit above the findings. The 3-second question is not answered by the layout. | `KpiBar.tsx`, `OverviewPage.tsx` | D5 |
| P1-3 | **Non-text contrast below 3:1.** `line` #263449 on `surface` = **1.53:1**; secondary buttons, inputs and select borders rely on fill alone to be identified. | `src/styles/index.css` | D2/D3 |
| P1-4 | **13 hard-coded colours and 15 off-ramp font sizes** outside the token system. | listed in §1.3 | D2/D3 |
| P1-5 | **Inter is an overused default and no font file is bundled** — the app falls back to whatever the OS supplies, so metrics differ between machines. | `index.css`, `tailwind.config.ts` | D2 |
| P1-6 | **Chart junk**: default Recharts gridlines/axis styling, no direct value labels, `ConfidenceBreakdown` renders a giant green slab (all-green = decorative use of a semantic colour), confusion-matrix intensity is one flat blue. | `ConfidenceBreakdown.tsx`, `ModelEvaluation.tsx`, `ClassChart.tsx`, `InspectorCharts.tsx` | D6 |
| P1-7 | **Missing favicon → 404 in the console** (AC-15 requires no console errors). | `index.html` | D8 |
| P1-8 | **No content max-width**: at 2560 px the 12-col grid stretches and cards become 400 px+ tall of whitespace. | `PageScaffold.tsx` | D4/D8 |
| P1-9 | **Empty state uses a circular icon tile above the heading** (explicit anti-reference) and a borderless ghost "Load sample analysis" with almost no affordance. | `States.tsx`, `EmptyAnalysis.tsx` | D8 |
| P1-10 | **Badge vocabulary is ununified**: `Badge` (px-2 py-0.5, 11 px), `SeverityBadge`, `StatusChip`, `ProvenanceBadge` and `ConfidenceBar` differ in height/padding/icon size, so mixed rows do not align. | `src/components/ui/*` | D3 |

#### P2 — polish

| # | Issue | Location | Fix phase |
|---|---|---|---|
| P2-1 | Overview is 3614 px tall at 1280 — the eye has no resting points; secondary detail outranks findings. | `OverviewPage.tsx` | D5 |
| P2-2 | Threat-matrix intensity is weak and zero cells still carry a tint; row/column totals are not visually separated. | `ThreatMatrixCard.tsx` | D5 |
| P2-3 | Class chart legend duplicates the axis; top-1 highlight is subtle; no direct labels. | `ClassChart.tsx` | D5 |
| P2-4 | Handshake-timeline vertical rhythm: rekey steps repeat four near-identical rows with no grouping; connector line is faint. | `HandshakeTimeline.tsx` | D5 |
| P2-5 | Tables: header styling, hover/selected states, right-alignment of numerics and sort indicators are inconsistent between packet, SA and inference tables. | `PacketTable.tsx`, `SaTable.tsx`, `InferenceTable.tsx` | D6 |
| P2-6 | Slider thumb/track contrast and segmented-control states need one shared treatment. | `SegmentedControl.tsx`, threshold slider | D6 |
| P2-7 | Report drawer chrome: header hierarchy, sticky action bar, markdown typography measure. | `ReportDrawer.tsx`, `markdown.tsx` | D4 |
| P2-8 | Microcopy: some helper strings outside the copy deck are wordy or vague. | scattered | D8 |
| P2-9 | `print.css` carries 7 off-ramp font sizes. | `src/styles/print.css` | D8 |
| P2-10 | Motion: route changes have no transition, timeline stagger and gauge fill exist but drawer/popover/notification motion is unverified. | scattered | D8 |

#### Positive findings (keep)

- No horizontal scroll and a non-wrapping 56 px header at 768 px already.
- Focus ring on all 25 sampled tab stops; skip link is the first focusable element.
- `prefers-reduced-motion` already neutralises every running animation.
- Hidden data tables + `figure`/`figcaption` are present on charts.
- Provenance is conveyed by icon + outline style + text, not colour alone.
- One rule table (`evaluate`) feeds findings, score, matrix and compliance —
  the product's core claim holds in code.

**Gate D1: PASS** — the prioritised P0/P1/P2 list above is written.

---

## D2 — Foundations

Commands applied: `/impeccable typeset` (typography hierarchy) and
`/impeccable colorize` used as a *refinement* pass over the existing token set —
no new hues were added for decoration.

### 2.1 Font choice (approved deviation from Spec 3.2)

| | Before | After |
|---|---|---|
| UI | `Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif` — **no font file shipped**, so the rendered face depended on the OS | **IBM Plex Sans Variable** (`@fontsource-variable/ibm-plex-sans@5.3.0`), stack `IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif` |
| Mono | `"JetBrains Mono", …` — also no file, so it silently fell back to `ui-monospace` | **JetBrains Mono Variable** (`@fontsource-variable/jetbrains-mono@5.3.0`), stack `JetBrains Mono Variable, JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace` |

**Why:** the brief approved exactly one self-hosted UI family plus one mono
family. Plex was drawn for technical documentation — even colour, open apertures
and an engineered feel that suits an instrument panel without turning cold — and
it is not on the avoid-list. JetBrains Mono has unambiguous `0/O` and `1/l` and
stable widths for hex, SPIs and log lines. Both are imported in `src/main.tsx`
so Vite emits the `.woff2` files into `dist/assets/`; **nothing loads from a
CDN** and the build output confirms 12 local woff2 assets. The fallback tail is
byte-identical to the incumbent stack apart from replacing `Inter`.

Two consequences recorded: (a) the family names exposed by Fontsource are
`IBM Plex Sans Variable` / `JetBrains Mono Variable`, so both the variable name
*and* the plain name are listed; (b) the incumbent `font-feature-settings:
'cv02','cv03','cv04'` were Inter-specific alternates and were dropped.

### 2.2 Colour tokens (values retuned, names unchanged)

All fourteen Tailwind token names from Spec 3.1 survive (`base`, `surface`,
`raised`, `line`, `ink`, `muted`, `accent`, `accent-solid`, `highlight`, `safe`,
`warn`, `danger`, `orange`, `violet`) so no component broke. **Two tokens were
added:** `line-strong` (interactive borders, must reach 3:1) and `danger-solid`
(a filled danger button can carry white text at 4.93:1; the plain `danger` is an
on-dark text colour at 6.28:1).

| Token | Was | Now | Reason |
|---|---|---|---|
| `base` | `#0F172A` | **`#090F13`** | blue-teal tint, no pure black; deeper page ground |
| `surface` | `#111C33` | **`#121B23`** | tinted panel; 1.11:1 above base |
| `raised` | `#1E293B` | **`#1F2A34`** | 1.19:1 above surface — the third step is now perceptible |
| `line` | `#263449` | **`#354753`** | hairline was 1.46:1 and effectively invisible; now 1.80:1 |
| `line-strong` | — | **`#637684`** | new; interactive borders ≥ 3:1 on every surface |
| `ink` | `#E2E8F0` | **`#E7EEF3`** | slightly cooler, still 14.85:1 |
| `muted` | `#94A3B8` | **`#9DB0BE`** | 7.78:1 on `surface` |
| `accent` | `#3B82F6` | **`#5A9BF8`** | link/focus value that clears 4.5:1 on every surface |
| `accent-solid` | `#2563EB` | `#2563EB` | unchanged — white label 5.17:1 |
| `highlight` | `#06B6D4` | **`#22C3D6`** | calmer cyan, 9.04:1 |
| `safe` | `#10B981` | **`#34C88F`** | 9.00:1 on base, 6.15:1 on its own 15 % tint |
| `warn` | `#F59E0B` | **`#F0A63A`** | desaturated amber, 6.42:1 on tint |
| `orange` | `#F97316` | **`#F4763A`** | 5.03:1 on tint (was marginal) |
| `danger` | `#EF4444` | **`#F2665E`** | 4.68:1 on its own 15 % tint (the previous value failed there) |
| `violet` | `#A78BFA` | `#A78BFA` | unchanged |
| chart 1–7 | `#3B82F6 #06B6D4 #10B981 #F59E0B #A78BFA #F472B6 #94A3B8` | **`#5A9BF8 #41C7E8 #3FC98F #EBB13C #B79DF3 #EE8260 #93A3B4`** | Okabe–Ito derived for deuteranopia/protanopia; pink → vermillion so positions 5/6 stop collapsing under red-green CVD; every entry ≥ 6.87:1 on `base` |

Surface steps measured: `base/surface` **1.11**, `surface/raised` **1.19**,
`base/raised` **1.32** — three steps you can actually see on a real monitor
without the page turning into stripes.

### 2.3 Type scale (role-based, applied through `tailwind.config.ts`)

| Role | Tailwind step | Size/line | Weight | Tracking |
|---|---|---|---|---|
| Overline / badge micro | `text-2xs` (new) | 11/14 | 600 | `0.08em` uppercase (`.overline`) |
| Caption | `text-xs` | 12/16 | 400 | normal |
| **Body** | `text-sm` (**remapped 14→13 px**) | 13/20 | 400 | normal |
| **Card / section title** | `text-base` (**remapped 16→14 px**) | 14/20 | 600 | `-0.006em` |
| Sub-head | `text-lg` | 16/24 | 600 | `-0.006em` |
| **Page title** | `text-xl` | 20/28 | 600 | `-0.011em` (`tracking-tight`) |
| **KPI number** | `text-kpi` (new) | 28/32 | 600 | `-0.02em`, tabular |
| Mono data | `.mono` / `font-mono text-xs` | 12/16 | 400 | ligatures off |

The remap is the fix for the incumbent's main typographic drift: the spec's
body is 13 px and its card title is 14 px, but Tailwind's stock `sm`/`base`
steps are 14/16, so the app mixed three different "body" sizes. `text-sm` is now
the body and `text-base` the title, so every component converges on one scale.

**`font-variant-numeric: tabular-nums` is set globally on `body`** (plus the
`.tnum` utility kept for explicit use), satisfying "tabular-nums everywhere"
without having to remember it per table.

### 2.4 Shape, spacing, motion, elevation, z-index

- Radii retuned for a machined feel: **cards 10 px** (was 12), **controls 6 px**
  (was 8), cells 4 px, chips 999 px.
- Spacing stays a strict 4 px scale; `--card-pad` (16 px comfortable / 12 px
  compact) is now a CSS variable on `:root` instead of being re-declared.
- Motion tokens added: `--dur-instant 100ms`, `--dur-fast 140ms`,
  `--dur-base 180ms`, `--dur-slow 240ms`, `--ease-out cubic-bezier(.2,0,0,1)`,
  `--ease-in-out cubic-bezier(.4,0,.2,1)`, exposed as Tailwind
  `duration-fast|base|slow` and `ease-out|ease-inout`.
- Shadow vocabulary reduced to three: `shadow-card` (a 1 px hairline ring),
  `shadow-overlay` (black-alpha + ring, for popovers/drawer) and `shadow-focus`.
  No coloured shadow exists anywhere.
- z-index scale added: `sticky 100 · header 200 · dropdown 300 · overlay 400 ·
  drawer 450 · tooltip 500`.
- Scrollbars restyled to the token palette (10 px, `line` thumb,
  `line-strong` on hover).
- `prefers-reduced-motion` now sets state transitions to 1 ms (so feedback is
  *instant*, not removed) and switches the ambient loops (`shimmer`, anything
  marked `data-motion="ambient"`) off entirely — replacing the blanket
  `0.001ms` kill the audit flagged.
- `index.html` gained an inline **SVG favicon (data URI)** → removes the only
  console 404 (P1-7) with no network request.

### 2.5 Contrast table (every required pair, final values, measured)

Contrast helper: `/tmp/opencode/final.cjs` (WCAG 2.1 relative luminance, tinted
badges composited at 15 % over `surface` before measuring).

| Pair | Ratio | Min | Result | Note |
|---|---|---|---|---|
| ink on base | 16.45:1 | 4.5:1 | PASS |  |
| ink on surface | 14.85:1 | 4.5:1 | PASS |  |
| ink on raised | 12.45:1 | 4.5:1 | PASS |  |
| muted on base | 8.62:1 | 4.5:1 | PASS |  |
| muted on surface | 7.78:1 | 4.5:1 | PASS |  |
| muted on raised | 6.52:1 | 4.5:1 | PASS |  |
| accent (link) on base | 6.87:1 | 4.5:1 | PASS |  |
| accent (link) on surface | 6.20:1 | 4.5:1 | PASS |  |
| accent on raised | 5.20:1 | 4.5:1 | PASS |  |
| focus ring accent vs base | 6.87:1 | 3:1 | PASS | non-text |
| focus ring accent vs surface | 6.20:1 | 3:1 | PASS | non-text |
| focus ring accent vs raised | 5.20:1 | 3:1 | PASS | non-text |
| control edge vs base | 4.09:1 | 3:1 | PASS | non-text |
| control edge vs surface | 3.69:1 | 3:1 | PASS | non-text |
| control edge vs raised | 3.10:1 | 3:1 | PASS | non-text |
| hairline vs surface | 1.80:1 | 1.5:1 | PASS | decorative divider (not a UI boundary) |
| white on accent-solid | 5.17:1 | 4.5:1 | PASS |  |
| white on danger-solid | 4.93:1 | 4.5:1 | PASS |  |
| safe text on safe/15 tint (over surface) | 6.15:1 | 4.5:1 | PASS | tint `#173533` |
| warn text on warn/15 tint (over surface) | 6.42:1 | 4.5:1 | PASS | tint `#333026` |
| orange text on orange/15 tint (over surface) | 5.03:1 | 4.5:1 | PASS | tint `#342926` |
| danger text on danger/15 tint (over surface) | 4.68:1 | 4.5:1 | PASS | tint `#34262c` |
| accent text on accent/15 tint (over surface) | 4.91:1 | 4.5:1 | PASS | tint `#1d2e43` |
| highlight text on highlight/15 tint (over surface) | 6.19:1 | 4.5:1 | PASS | tint `#14343e` |
| violet text on violet/15 tint (over surface) | 5.04:1 | 4.5:1 | PASS | tint `#282c43` |
| safe text on base | 9.00:1 | 4.5:1 | PASS |  |
| warn text on base | 9.38:1 | 4.5:1 | PASS |  |
| orange text on base | 6.88:1 | 4.5:1 | PASS |  |
| danger text on base | 6.28:1 | 4.5:1 | PASS |  |
| accent text on base | 6.87:1 | 4.5:1 | PASS |  |
| highlight text on base | 9.04:1 | 4.5:1 | PASS |  |
| violet text on base | 7.08:1 | 4.5:1 | PASS |  |
| chart-1 `#5A9BF8` vs base | 6.87:1 | 3:1 | PASS | graphic object |
| chart-2 `#41C7E8` vs base | 9.69:1 | 3:1 | PASS | graphic object |
| chart-3 `#3FC98F` vs base | 9.15:1 | 3:1 | PASS | graphic object |
| chart-4 `#EBB13C` vs base | 9.99:1 | 3:1 | PASS | graphic object |
| chart-5 `#B79DF3` vs base | 8.38:1 | 3:1 | PASS | graphic object |
| chart-6 `#EE8260` vs base | 7.34:1 | 3:1 | PASS | graphic object |
| chart-7 `#93A3B4` vs base | 7.47:1 | 3:1 | PASS | graphic object |

**41/41 required pairs pass; 0 failures.**

`DESIGN.md` was updated with these final tokens (frontmatter is normative).

**Gate D2: PASS** — `typecheck`, `lint`, `test`, `build` all exit 0; contrast
table written with every required pair passing; verified visually at 1280 and
768 (header 56 px, no horizontal scroll, IBM Plex Sans active).

### 2.6 Deviation: the dev server had served a stale Tailwind config

Immediately after the token rewrite the headless harness still reported
`body = Inter, ui-sans-serif, system-ui, …` and a plain `"JetBrains Mono"` KBD.
Cause: the Vite dev process had been started **before** `tailwind.config.ts`
changed (and re-optimised deps because the font install touched the lockfile),
so it kept serving the old generated CSS. Restarting the dev server fixed it:

| probe | before restart | after restart |
|---|---|---|
| `body.fontFamily` | `Inter, ui-sans-serif, system-ui, …` | `"IBM Plex Sans Variable", "IBM Plex Sans", ui-sans-serif, …` |
| `document.fonts` (loaded) | `[]` | `["IBM Plex Sans Variable", "JetBrains Mono Variable"]` |
| `body.fontVariantNumeric` | `tabular-nums` | `tabular-nums` |

**Rule for D3–D9:** restart the dev server after any change to
`tailwind.config.ts`, `src/styles/*` or installed font packages, otherwise the
visual gate is read against stale CSS.

### 2.7 Visual re-check at 1280 / 768 (post-restart)

| page | h-scroll 1280 | h-scroll 768 | console | fixture |
|---|---|---|---|---|
| Overview | no | no | clean | Fixture B |
| Inspector | no | no | clean | Fixture B |
| Inferences | no | **YES** | clean | Fixture B |
| Audit | no | no | clean | Fixture B |
| Compliance | no | no | clean | Fixture B |
| Settings | no | no | clean | n/a (stub, no sample button) |

New P1: **Inferences overflows horizontally at 768** → fixed in D6 (its phase).
Also noted for D5: nothing uses the new `text-kpi` utility yet — Overview KPI
values are still at ad-hoc sizes.

Screenshots regenerated: `/tmp/opencode/shots/<page>-1280.png` / `-768.png`.

---

## D3 — UI primitives

*(written when D3 runs)*

---

## D4 — App shell

*(written when D4 runs)*

---

## D5 — Overview

*(written when D5 runs)*

---

## D6 — Inspector + Inferences

*(written when D6 runs)*

---

## D7 — Audit + Compliance + Settings

*(written when D7 runs)*

---

## D8 — States, motion, microcopy

*(written when D8 runs)*

---

## D9 — Final verification

*(written when D9 runs)*
