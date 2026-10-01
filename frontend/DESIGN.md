---
name: IPsec-AI Sentinel
description: Dark, restrained, information-dense instrument panel for SOC analysts assessing IPsec posture.
colors:
  base: "#090F13"
  surface: "#121B23"
  raised: "#1F2A34"
  line: "#354753"
  line-strong: "#637684"
  ink: "#E7EEF3"
  muted: "#9DB0BE"
  accent: "#5A9BF8"
  accent-solid: "#2563EB"
  highlight: "#22C3D6"
  safe: "#34C88F"
  warn: "#F0A63A"
  orange: "#F4763A"
  danger: "#F2665E"
  danger-solid: "#C4453C"
  violet: "#A78BFA"
  chart-1: "#5A9BF8"
  chart-2: "#41C7E8"
  chart-3: "#3FC98F"
  chart-4: "#EBB13C"
  chart-5: "#B79DF3"
  chart-6: "#EE8260"
  chart-7: "#93A3B4"
typography:
  page-title:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "20px"
    fontWeight: 600
    lineHeight: "28px"
    letterSpacing: "-0.011em"
  section-title:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "14px"
    fontWeight: 600
    lineHeight: "20px"
    letterSpacing: "-0.006em"
  card-title:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "13px"
    fontWeight: 600
    lineHeight: "20px"
  body:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "13px"
    fontWeight: 400
    lineHeight: "20px"
  caption:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "16px"
  label:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "11px"
    fontWeight: 600
    lineHeight: "16px"
    letterSpacing: "0.06em"
  kpi-number:
    fontFamily: "IBM Plex Sans Variable, IBM Plex Sans, ui-sans-serif, system-ui, -apple-system, Segoe UI, sans-serif"
    fontSize: "28px"
    fontWeight: 600
    lineHeight: "32px"
    letterSpacing: "-0.02em"
  mono-data:
    fontFamily: "JetBrains Mono Variable, JetBrains Mono, ui-monospace, SFMono-Regular, Menlo, monospace"
    fontSize: "12px"
    fontWeight: 400
    lineHeight: "16px"
rounded:
  card: "10px"
  control: "6px"
  chip: "999px"
  cell: "4px"
spacing:
  1: "4px"
  2: "8px"
  3: "12px"
  4: "16px"
  5: "20px"
  6: "24px"
  8: "32px"
components:
  button-primary:
    backgroundColor: "{colors.accent-solid}"
    textColor: "#ffffff"
    rounded: "{rounded.control}"
    height: "36px"
  button-secondary:
    backgroundColor: "{colors.raised}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    height: "36px"
  button-ghost:
    backgroundColor: "transparent"
    textColor: "{colors.muted}"
    rounded: "{rounded.control}"
    height: "36px"
  button-danger:
    backgroundColor: "{colors.danger-solid}"
    textColor: "#ffffff"
    rounded: "{rounded.control}"
    height: "36px"
  badge:
    backgroundColor: "rgba(157,176,190,0.12)"
    textColor: "{colors.ink}"
    rounded: "{rounded.chip}"
  card:
    backgroundColor: "{colors.surface}"
    textColor: "{colors.ink}"
    rounded: "{rounded.card}"
    padding: "16px"
  input:
    backgroundColor: "{colors.base}"
    textColor: "{colors.ink}"
    rounded: "{rounded.control}"
    height: "36px"
---

# Design System: IPsec-AI Sentinel

## Overview

**Creative North Star: "The Calm Instrument Panel"**

This is an **Operate**-mode surface: the analyst is doing a job, not being sold
one. The design borrows from cockpit instrumentation and from a well-typeset
technical manual — dense, aligned, quiet, and legible for hours. Hierarchy comes
from size, weight and colour value, not from more boxes. The screen should read
as one continuous instrument face with a few raised modules, not as a tray of
floating tiles.

Depth is made with a three-step tinted surface ladder (`base` < `surface` <
`raised`) and hairline rules, never with glow, blur or gradient. Semantic colour
is a scarce resource: severity and status colours appear only where they mean
something, so a red pixel always costs the analyst attention. The primary accent
(one blue) is reserved for the single primary action, the focus ring, and the
primary chart series.

Motion explains change and then gets out of the way: short, ease-out, transform
and opacity only, fully disabled under `prefers-reduced-motion`.

**Key Characteristics:**

- Tinted blue-teal neutrals; no pure black, no pure grey.
- Calm and dense: 4 px spacing rhythm, hairline separators, minimal chrome.
- One accent, reserved; severity colours reserved for meaning.
- Typography carries the hierarchy; boxes do not.
- Machine data in mono; everything else in a refined technical sans.
- Nothing bounces, glows, or gradients.

## Colors

A blue-teal tinted dark palette with a perceptible three-step elevation and
severity colours tuned to pass AA on `surface` and on their own 12–15 % tints.

### Primary

- **Instrument Blue** (`accent` #5A9BF8 / `accent-solid` #2563EB): the one
  primary action colour, the focus ring, links, and the primary chart series.
  `accent` is the on-dark readable value (6.2:1 on `surface`); `accent-solid` is
  the filled-button value (white text 5.2:1).

### Tertiary

- **Signal Cyan** (`highlight` #22C3D6): live-capture state, observed-provenance
  accents, the rekey step, secondary chart series. It is a *status* colour, not
  decoration.

### Neutral

- **Hold Black** (`base` #090F13): page background.
- **Panel Slate** (`surface` #121B23): cards, sidebar, header, table bodies.
- **Raised Slate** (`raised` #1F2A34): hover, inputs, table header, tracks.
- **Hairline** (`line` #354753): dividers and card borders (structural only;
  1.8:1 on `surface` so it is perceptible without becoming a wireframe).
- **Control Edge** (`line-strong` #637684): borders of interactive controls,
  which must meet 3:1 (3.7:1 on `surface`, 4.1:1 on `base`, 3.1:1 on `raised`).
- **Primary Ink** (`ink` #E7EEF3): primary text (14.9:1 on `surface`).
- **Secondary Ink** (`muted` #9DB0BE): secondary text (7.8:1 on `surface`).

### Semantic

- **Safe** (`safe` #34C88F): pass, compliant, low risk.
- **Warn** (`warn` #F0A63A): medium severity, thresholds.
- **Flag Orange** (`orange` #F4763A): high severity.
- **Danger** (`danger` #F2665E): critical, high risk, fail. `danger-solid`
  #C4453C exists only so a filled danger button can carry white text at 4.9:1.
- **Violet** (`violet` #A78BFA): inferred-provenance accent (dashed outline).

### Chart palette (7 classes, colour-blind separable)

`#5A9BF8` blue · `#41C7E8` cyan · `#3FC98F` bluish green · `#EBB13C` amber ·
`#B79DF3` violet · `#EE8260` vermillion · `#93A3B4` slate grey.
Derived from the Okabe–Ito set and re-tuned for a dark background; every entry
is ≥ 6.7:1 against `base`.

### Named Rules

**The Scarcity Rule.** `accent` occupies at most one primary action per view
area. Severity colours (`safe`/`warn`/`orange`/`danger`) never appear as
decoration, borders for flair, or ambient glow.

**The Tint-Then-Strengthen Rule.** Badges and matrix cells use the semantic
colour at 10–15 % alpha as a background with the *full-strength* colour for
text, icon and border. Every such pair is verified ≥ 4.5:1.

**The Never-Glow Rule.** No box-shadow uses a colour. Shadows are black-alpha
only, and only for overlays. No gradient touches text or a border.

## Typography

**Display / Body Font:** IBM Plex Sans Variable, IBM Plex Sans (bundled via
`@fontsource-variable`, self-hosted — never a CDN) with fallback
`ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif`.
**Label / Mono Font:** JetBrains Mono Variable, JetBrains Mono (bundled via
`@fontsource-variable`) with fallback `ui-monospace, SFMono-Regular, Menlo,
monospace`.

**Character:** Plex was drawn for technical documentation — even colour, open
apertures, a slightly engineered feel that suits an instrument panel without
becoming cold. JetBrains Mono has an unambiguous `0/O` and `1/l` and stable
widths for hex, SPIs and log lines. This pairing replaces the incumbent
Inter/system-ui default (approved font exception) while keeping the identical
fallback tail.

### Hierarchy

- **Page title** (600, 20/28, `-0.011em`): the `h1` on every page, `ink`.
- **Section title** (600, 14/20, `-0.006em`): `h2` group headings.
- **Card title** (600, 13/20): `h3`, module titles.
- **Body** (400, 13/20): default copy; prose is capped at ~75ch.
- **Caption** (400, 12/16): supporting text, always `muted`.
- **Overline / label** (600, 11/16, `0.06em`, uppercase): column headers,
  section eyebrows — used sparingly, never for full sentences.
- **KPI number** (600, 28/32, `-0.02em`, tabular): gauge score and KPI values.
- **Mono data** (400, 12/16): SPIs, hex, IPs, cipher identifiers, evidence
  strings, log lines — and nothing else.

### Named Rules

**The Tabular Rule.** Every number a user might compare down a column —
tables, KPIs, counters, timestamps, probabilities — uses `font-variant-numeric:
tabular-nums`.

**The Mono Means Machine Rule.** Mono is a semantic signal, not a texture. If it
was produced by a protocol, a model or a log, it is mono; if it was written for
a human, it is sans.

## Layout

A 12-column grid with a 16 px gap, 24 px page padding, and a 4 px spacing
rhythm (4/8/12/16/20/24/32). Sticky 56 px header, 248 px sidebar (64 px icon
rail below 1024 px), 32 px footer.

Density is a setting, not a breakpoint: `comfortable` rows are 40 px with 16 px
card padding, `compact` rows are 32 px with 12 px card padding. Both densities
share the same type scale and the same baseline grid so switching never
reflows the hierarchy.

Grouping is done with proximity, hairlines and surface steps. A bordered card is
reserved for a genuinely self-contained module; sections inside a card are
separated by a rule or by space, never by another card. Cards are never nested.

Above 1760 px the content column is capped at `max-w-[1760px]` and centred, so
2560 px viewports stay balanced instead of stretching. Below 1280 px the
Overview's 5/7 split stacks. Wide tables scroll inside labelled
`overflow-x-auto` wrappers. Nothing causes horizontal page scroll.

## Elevation & Depth

The system is **flat by default**: elevation is expressed by the three-step
surface ladder and by hairline borders. Shadows exist only on things that
genuinely float above the page.

### Shadow Vocabulary

- **Card** (`box-shadow: 0 0 0 1px var(--color-line)`): not a shadow at all — a
  hairline ring that stays crisp at any DPR.
- **Overlay** (`box-shadow: 0 10px 28px -10px rgba(0,0,0,0.75), 0 0 0 1px var(--color-line)`):
  popovers, tooltips, drawer, dialogs.
- **Focus** (`box-shadow: 0 0 0 2px var(--color-base), 0 0 0 4px var(--color-accent)`):
  every `:focus-visible`.

### Named Rules

**The Flat-By-Default Rule.** Surfaces are flat at rest. Nothing gains a shadow
on hover; hover changes the surface step or the hairline only.

## Shapes

Corners are slightly tightened from the incumbent 12 px so the panels read as
machined rather than soft: cards 10 px, controls 6 px, chips 999 px, table cells
4 px. Borders are 1 px everywhere. The recurring silhouette is the rectangular
module with a hairline ring; icon tiles, pills and floating circles are not part
of the vocabulary. Focus rings are drawn *outside* the control so they never
change layout.

## Components

### Buttons

- **Shape:** 6 px radius; heights 28 px (`sm`) and 36 px (`md`); 16 px icons;
  min hit area 32 px.
- **Primary:** `accent-solid` fill, white label. Exactly one per view area.
- **Secondary:** `raised` fill, `ink` label, 1 px `line-strong` border.
- **Ghost:** transparent, `muted` label, `raised` on hover.
- **Danger:** `danger-solid` fill, white label; destructive confirmations only.
- **Hover / Active / Disabled:** hover steps the surface lighter; active steps
  it darker; disabled is 50 % opacity with `not-allowed` and never a different
  colour. Focus is always the shared focus ring, never colour alone.
  Because the two filled variants cannot lighten past their own text colour and
  stay at 4.5:1, their label inverts to `ink-inverse` (an alias of `base`) for
  the duration of the hover and returns to white on press — the fill still
  steps lighter, and the label never drops below AA.

### Badges, chips and bars

One height (20 px), one padding (8 px), one radius (pill), one icon size
(12 px), one text style (11/16, 600). Severity badges carry icon + label +
colour. Provenance badges are distinguished by *shape and icon* — Observed is a
solid outline with an Eye, Inferred is a dashed outline with Sparkles — so the
difference survives greyscale and colour-blindness. Confidence is always a thin
bar plus a `%` in tabular figures.

### Cards / containers

- **Corner style:** 10 px.
- **Background:** `surface` on the `base` page; `raised` only for interactive or
  hovered rows.
- **Border:** 1 px `line` hairline ring.
- **Internal padding:** 16 px comfortable / 12 px compact.

### Inputs, selects, sliders, segmented controls, tabs

- **Style:** `base` fill (inset), 1 px `line-strong` border, 6 px radius,
  36 px height.
- **Focus:** the shared 2 px + 2 px focus ring, offset outside the control.
- **Error:** `danger` border plus a specific inline message with an icon.
- **Disabled:** `raised` fill, `muted` label, 60 % opacity, no focus ring.
- **Tabs:** `ink` label with a 2 px `accent` underline on the selected tab;
  roving tabindex; selection is never signalled by colour alone (it also changes
  weight and adds an underline).

### Tables

Sticky header on `raised` with an uppercase 11 px `muted` label; hairline row
separators (no zebra); hover steps to `raised`; the keyboard-selected row carries
a 2 px `accent` inset edge **and** a `raised` fill. Numeric columns are
right-aligned and tabular. Cells truncate with a `title` tooltip. Sortable
headers show a caret and `aria-sort`.

### Signature components

- **Risk gauge** — a 200×120 semicircle with a 14 px track split into three
  labelled bands (LOW / MODERATE / HIGH) so the threshold is visible without a
  legend; the score sits in 28 px tabular figures; the fill animates only
  `stroke-dashoffset`.
- **Threat matrix** — a heatmap on a monotonic 0→15 % severity tint ramp, quiet
  zero cells (a muted `0`, no fill), and a selected cell that shows a 2 px inset
  ring plus an `aria-pressed` state.
- **Provenance pair** — solid/Eye vs dashed/Sparkles, everywhere a parameter is
  shown.

### Motion

- **Durations:** 100 ms (instant feedback) · 140 ms (hover/press) · 180 ms
  (enter/exit) · 240 ms (layout-ish, gauge fill). Nothing exceeds 240 ms.
- **Easing:** `cubic-bezier(0.2, 0, 0, 1)` out; `cubic-bezier(0.4, 0, 0.2, 1)`
  in-out. No bounce, no elastic, no spring overshoot.
- **What moves:** gauge arc, timeline step reveal (30 ms stagger), drawer and
  popover enter/exit, notification arrival, a ≤160 ms route fade, and the
  live-capture dot pulse.
- **How:** `transform` and `opacity` only. Never animate layout on tables.
- **Reduced motion:** every one of these is a no-op under
  `prefers-reduced-motion: reduce`, including CSS shimmer and pulse.

## Do's and Don'ts

### Do:

- **Do** answer "how risky, and why" in the first viewport: risk gauge and top
  findings dominate; supporting modules recede.
- **Do** use the 4 px rhythm and increase separation between unrelated groups
  while tightening related ones.
- **Do** combine colour with an icon and a text label for every severity,
  status and provenance.
- **Do** put `tabular-nums` on anything compared down a column.
- **Do** verify contrast on the actual composite background before shipping.
- **Do** keep prose under ~75ch and truncate long machine values with a
  `title` tooltip.

### Don't:

- **Don't** nest a card inside a card; flatten to rules, space and surface
  steps.
- **Don't** use neon glow, glassmorphism, gradient text, gradient borders,
  coloured shadows, or a purple-to-blue wash.
- **Don't** put a rounded-square icon tile above every heading, or emoji in the
  UI.
- **Don't** use pure `#000000` or a pure neutral grey anywhere.
- **Don't** spend a severity colour on decoration, or the accent on more than
  one primary action per view area.
- **Don't** add bounce, elastic or >240 ms motion, or any motion that ignores
  `prefers-reduced-motion`.
- **Don't** load anything from the network at runtime — fonts, images and icons
  are bundled or inline.
