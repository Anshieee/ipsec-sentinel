# Product

<!-- impeccable:product-schema 1 -->

## Platform

web

## Users

- **SOC and network-security analysts, Tier 1–3.** They open the workbench during
  triage and long monitoring sessions to answer one question fast: *how risky is
  this IPsec configuration, and why?* They scan dense tables, charts and packet
  listings for hours at a time.
- **Technical lead.** Reviews the same analysis and exports an executive or
  technical report for stakeholders.

Both operate under time pressure and high stakes; wrong reads have real
consequences.

## Product Purpose

IPsec-AI Sentinel is the analyst workbench for an AI-driven IPsec/IKE/ESP traffic
analysis platform. The frontend ingests `.pcap`/`.pcapng` traces or a simulated
live capture, runs a deterministic in-browser rules engine over the returned
`AnalysisResult`, and presents risk, AI inferences with calibrated confidence and
provenance, packet-level detail, compliance posture and exportable reports.

Success means an analyst can assess posture in seconds, drill into evidence and
confidence when they doubt the machine, and export a defensible report — without
manual packet decoding.

## Positioning

Every displayed parameter declares **how** it was obtained — `observed` from
cleartext fields or `inferred` by ML/heuristics — and every inferred value ships
with a calibrated confidence. The same rule table produces the findings, the risk
score, the threat matrix and the compliance table, so the numbers can never
disagree with each other. A neighbouring product could not truthfully copy that
"one source of truth + explicit provenance on every value" mechanism.

## Operating Context

- Long, dense, single-operator sessions at a workstation; supported widths
  768–2560 px.
- Offline at runtime: no CDN, no remote fonts, no remote images, no external
  APIs. Mock/demo data is used while `VITE_USE_MOCK=true` and must be labelled.
- Reporting ritual: report drawer → Export PDF (print stylesheet) or Export JSON.
- Keyboard-first operation with global hotkeys (`/ u l r ?`) and full
  screen-reader support.

## Capabilities and Constraints

- Capabilities: PCAP upload and drag-drop with validation; simulated live capture
  with counters and notifications; Overview posture; Traffic Inspector with
  packet table, hex dump and SA table; AI Inferences with feature evidence and a
  tunable uncertainty threshold; Security Audit with score waterfall and
  remediation projection; Config Compliance with DH Key Lab and what-if
  simulation; Settings with density, thresholds, model registry and logs;
  executive/technical report drawer and print export.
- Fixed stack: Vite 5, React 18, TypeScript 5.5 (strict), Tailwind 3.4,
  React Router 6, Zustand 4, Recharts 2, lucide-react, framer-motion 11,
  react-markdown + remark-gfm, Vitest. No new runtime dependencies (a single
  self-hosted UI font and a single self-hosted mono font via `@fontsource` are a
  recorded, approved deviation).
- Terminology is binding: "confidence" never "accuracy"; IKE SA / CHILD SA for
  IKEv2, Phase 1 / Phase 2 (Quick Mode) for IKEv1; "Encrypted payload (size and
  timing only)" for encrypted exchanges.
- Accessibility: WCAG 2.1 AA — text ≥ 4.5:1, non-text UI ≥ 3:1; severity and
  status always combine colour + icon + text; `prefers-reduced-motion` honoured;
  charts carry `figure`/`figcaption` plus hidden data tables.

## Brand Commitments

- Existing name: **IPsec-AI Sentinel**, subtitle "Workbench". Voice: precise,
  calm, authoritative, quietly technical — a cockpit instrument and a
  well-typeset technical manual, not a crypto trading terminal or cyberpunk
  hacker UI.
- Binding anti-references: neon glows, glassmorphism, purple-to-blue gradients,
  gradient text, glowing borders, cards nested in cards, rounded-square icon
  tiles above every heading, emoji as UI, decorative hero sections, fake 3D,
  bouncy or elastic motion, pure `#000` / pure grey.
- Binding constraints: dark theme only; offline at runtime; WCAG 2.1 AA;
  `prefers-reduced-motion`; supported widths 768–2560 px.
- Register: product (app UI / dashboard / tool), not brand.

## Evidence on Hand

- `FRONTEND_SPEC.md` — the original normative spec (copy deck, data-testids,
  acceptance criteria AC-01…AC-17).
- Implemented, verified codebase in `src/` with fixtures A/B/C, a rules engine,
  and passing `npm run verify`.
- `DECISIONS.md` and `PROGRESS.md` record the build-phase decisions.

Absences that future work must not fabricate: no real backend, no real customer
data, no testimonials or usage metrics. All analysis results are demonstration
data and the UI must keep saying so while the mock flag is on.

## Product Principles

1. **The machine shows its work.** Every value carries provenance and, when
   inferred, a calibrated confidence; one rule table feeds every downstream
   number.
2. **Risk answers first.** The dominant element on every screen is the question
   the analyst came to answer; everything else is supporting evidence.
3. **Calm density.** Hours of scanning reward alignment, restraint and stable
   layout over decoration.
4. **Keyboard- and screen-reader-complete.** Nothing exists only for the mouse,
   nothing exists only for colour.
5. **Presentation may change; behaviour may not.** Design work touches the
   presentation layer only.

## Accessibility & Inclusion

WCAG 2.1 AA is required: text contrast ≥ 4.5:1 and non-text UI ≥ 3:1 measured on
the actual background; no information conveyed by colour alone; visible focus on
every interactive control; landmarks and skip link; roving tabindex on tab
grids; focus-trapped drawer; throttled `aria-live`; charts backed by hidden data
tables; full `prefers-reduced-motion` support; hit targets ≥ 32 px.
