# PROGRESS — design pass (phases D0–D9)

A phase is ticked only after its gate passes. Standard gate =
`npm run typecheck` + `npm run lint` + `npm run test` + `npm run build` all exit 0,
plus a visual check of the affected pages at 1280 px and 768 px.

- [x] **D0** Setup — `npx impeccable install` (OpenCode), `impeccable context`,
      `init` → `PRODUCT.md`, `DESIGN.md`, `DESIGN_DECISIONS.md`, `PROGRESS_DESIGN.md`
      Gate: the four files exist. ✅
- [x] **D1** Baseline review — `/impeccable audit` + `/impeccable critique` on all six
      pages; prioritised P0/P1/P2 issue list written into `DESIGN_DECISIONS.md`
      Gate: the issue list is written. ✅ (audit 13/20, critique 28/40,
      detector 31 findings → `DESIGN_DECISIONS.md` §1.5)
- [x] **D2** Foundations — tokens, type scale, fonts, CSS variables, contrast table
      Gate: standard gate + contrast table, every required pair passing.
      ✅ (`npm run verify` exit 0; contrast 41/41 PASS; visual check 1280/768)
- [ **D3** UI primitives — `src/components/ui/*` normalised and polished
      Gate: standard gate.
- [ **D4** App shell — header, sidebar, footer, popovers, notifications, search,
      help, report drawer chrome
      Gate: standard gate; header does not wrap at 768.
- [ **D5** Overview — risk-first hierarchy, flattened cards, gauge/timeline/notify
      motion
      Gate: standard gate; AC-01, AC-03, AC-06 unchanged in dev.
- [ **D6** Inspector + Inferences — tables, packet detail, hex dump, SA table,
      confusion matrix, reliability diagram, feature bars, threshold slider
      Gate: standard gate; pagination/filtering/threshold tests pass.
- [ **D7** Audit + Compliance + Settings — waterfall, radar, findings, checklist,
      DH lab, what-if, model registry, log viewer
      Gate: standard gate; what-if and log tests pass.
- [ **D8** States, motion and microcopy pass across ALL pages — `clarify`,
      `harden`, `distill`, `quieter`, `adapt`; skeleton-to-content parity
      Gate: standard gate.
- [ **D9** Final verification — re-audit, re-critique, detector, `npm run verify`,
      AC-01…AC-17 manual walk, responsive/console/reduced-motion/print/network
      checks, README "Design system" section
      Gate: `npm run verify` exits 0 and this file is fully ticked.
