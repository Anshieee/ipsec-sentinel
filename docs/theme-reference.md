# Theme reference — palette (v1.2.4 source of truth) + reference extraction

## v1.2.4 palette (single token set; overrides v1.2.2 values where they differ)

Diffs vs the v1.2.2 tokens: page #0a0a0a→#080808, cards #101012→#101010,
nested #17171a→#161616, hairlines #26262b→#292929 (+#1e1e1e subtle,
#333333 strong), ink #f0f2f5→#f5f5f5, muted #a7aeb8→secondary #a0a0a0
(+#737373 muted large/icons/deco only, +#8a8a8a muted-small, +#525252
disabled), accent #5a9bf8→blue #3888ec, safe #34c88f→green #189f70
(+green-bright #20cc60 for success text), warn #f0a63a→amber #f8a008,
danger #f2665e→red #ff6467, violet #a78bfa→purple #ad59fc, orange kept
(#f08020), highlight/cyan folded into blue, danger-solid removed,
white-accent #fafafa added (single light primary action), track #63636e
retained. Radii kept (card 10px/control 6px ≈ .5rem scale). Chart
greys from the reference deliberately NOT adopted (series must stay
distinguishable: blue/green/purple/orange/amber/red + neutral grey).

Backgrounds: --bg #080808 (page), --bg-elevated #101010 (cards/panels),
--bg-card #161616 (nested/raised), --bg-hover #1a1a1a, --bg-input #101010.
Borders: --border #292929, --border-subtle #1e1e1e, --border-strong #333333.
Text: --text-primary #f5f5f5, --text-secondary #a0a0a0, --text-muted #737373,
--text-muted-small #8a8a8a, --text-disabled #525252.
Accents: --white-accent #fafafa, --blue #3888ec, --green #189f70,
--green-bright #20cc60, --purple #ad59fc, --orange #f08020,
--amber #f8a008, --red #ff6467. Chart grid #252525.
Buttons: single primary = light (#fafafa bg, #080808 text ≈ 15.6:1);
secondary/ghost/danger = neutral bordered. Focus ring blue #3888ec.
Badges: tinted bg 8-12% alpha, 1px border 30-40% alpha, bright/accent text.
Cards: bg-elevated + 1px --border, no box-shadow/glow. Slider track #63636e.

## Reference extraction (FreeLLMAPI, read-only)

Read date: 2026-10-04. Source: `http://localhost:3001/` (local
FreeLLMAPI container, `ghcr.io/tashfeenahmed/freellmapi:latest`),
page HTML + `assets/index-*.css` via curl. No code, names or logos
copied — design tokens only. oklch→hex below is approximate (achromatic
rungs exact; chromatic rounded).

## Fonts (open licence — adopted as-is, no substitution)

- Sans: **Geist Variable** (+ `Geist Variable` stack:
  `"Geist Variable", ui-sans-serif, system-ui, -apple-system, sans-serif`),
  self-hosted woff2-variations (latin, latin-ext, vietnamese, cyrillic…).
- Mono: **Geist Mono Variable** (stack: `"Geist Mono Variable",
  ui-monospace, SFMono-Regular, Menlo, monospace`).
- Bundled locally via `@fontsource/geist` + `@fontsource/geist-mono`
  (OFL); IBM Plex Sans / JetBrains Mono removed. App works offline
  (no CDN). Mono used for code, ids, rule names, evidence text and
  table numbers.

## :root / .dark CSS variables (dark theme only — we ship dark only)

| token | .dark value | ≈hex | where we use the equivalent |
|---|---|---|---|
| background | oklch(13.5% 0 0) | #080808 | page `bg-base` (#0a0a0a) |
| foreground | oklch(98% 0 0) | #f8f8f8 | headings/body `text-ink` (#f0f2f5) |
| card / popover | oklch(17.5% 0 0) | #101010 | card `surface` (#101012) |
| secondary / muted / accent (bg) | oklch(22–24% 0 0) | #1b1b1b–#1f1f1f | raised/hover (#17171a) |
| muted-foreground | oklch(68% 0 0) | #989898 | secondary text `muted` (#a7aeb8) |
| border / sidebar-border | oklch(100% 0 0 / .1) | white 10% | hairline `line` (#26262b, solid) |
| input | oklch(100% 0 0 / .14) | white 14% | inputs use `line-strong` + base bg |
| ring | oklch(60% 0 0) | #808080 | focus ring (kept blue accent: higher visibility) |
| primary | oklch(93% 0 0) | near-white | neutral (our primary action stays blue, used once) |
| destructive | oklch(70.4% .191 22.216) | #ff6467 | errors `danger` (#f2665e) |
| chart-1..5 | oklch(92/78/60/45/32% 0 0) | greys | NOT adopted (see below) |
| radius | .5rem (8px) | — | card 10px / control 6px (kept; close, larger) |

## Resolved element colours (our classes → token → hex)

- Page background: `bg-base` → #0a0a0a.
- Card surface: `surface` → #101012; hover/raised → #17171a.
- Card border: 1px `line` → #26262b; control edges `line-strong` → #3a3a42.
- Headings/body: `ink` → #f0f2f5; secondary text: `muted` → #a7aeb8.
- Active nav item: `bg-raised` + ink + 3px accent bar (#5a9bf8).
- Selected segmented control: `bg-raised` + ink + card shadow.
- Buttons: neutral bordered (`secondary`/ghost); single primary action
  (Upload) saturated blue `accent-solid` (#2563eb); print demoted to
  secondary. Danger fill variant exists but is unused.
- Inputs: base bg + `line-strong` border; slider track `track` (#63636e).
- Links: accent blue, used sparingly (primary chart series + links).
- Success/warning/error: safe #34c88f (emerald), warn #f0a63a (amber),
  danger #f2665e (red); LIKELY violet #a78bfa; SIMULATED amber outline.
- Gauge: green/orange/red bands kept bright (not dimmed).

## Contrast table (computed, small text ≥ 4.5:1, UI ≥ 3:1)

| pair | ratio | verdict |
|---|---|---|
| primary on page/card/nested | 18.4 / 17.5 / 16.6 | ✓ |
| secondary on page/card/nested | 7.7 / 7.3 / 6.9 | ✓ |
| muted-small on page/card/nested | 5.8 / 5.5 / 5.2 | ✓ (small muted text) |
| muted #737373 on page/card/nested | 4.2 / 4.0 / 3.8 | large/icons/decoration only |
| disabled #525252 | ~2.4 | disabled controls only |
| success #20cc60 / purple / blue / red / amber / orange on tinted badge bg | 8.1 / 4.5 / 4.7 / 5.9 / 7.8 / 6.3 | ✓ (purple exactly 4.5) |
| gauge: green-bright / amber / red on card | 8.9 / 9.1 / 6.6 | ✓ |
| light primary button #080808 on #fafafa | 15.6 | ✓ |
| slider track #63636e vs card | 3.21 | ✓ (meaningful border) |
| input/segmented borders (track) vs surface | 3.21 | ✓ |
| card hairline #292929 vs card | 1.31 | decorative edge only |
| white on blue #3888ec | ~3.6 | never used as filled-button text |

| pair | ratio |
|---|---|
| ink on base/surface/raised | 17.7 / 16.9 / 16.0 |
| muted on base/surface/raised | 8.9 / 8.5 / 8.0 |
| accent/safe/warn/danger/violet/highlight on surface | 6.8 / 8.9 / 9.3 / 6.2 / 7.0 / 8.9 |
| slider track #63636e on surface | 3.20 |
| hairline #26262b on base | 1.31 (structural hairline, not text) |

## Deliberate divergences

- Chart greys (chart-1..5) NOT adopted: monochrome series would destroy
  severity/series semantics (blue, green, amber, red, violet keep
  distinct hues; only lightness adjusted where needed).
- Radii kept (10/6px vs .5rem) — equivalent scale, avoids snapshot churn.
- Focus ring stays blue accent (higher visibility than the grey ring).
- Glass blur retained in CSS but inert over the now-opaque rungs.
