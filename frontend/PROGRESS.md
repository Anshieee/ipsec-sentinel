# PROGRESS — IPsec-AI Sentinel frontend

Phase checklist. A phase is ticked only after its gate passes.

- [x] **P0** Scaffold, pinned deps, Tailwind, alias, Vitest config, scripts, `.env.example`, `PROGRESS.md`
      Gate: `npm run typecheck`, `npm run build`, `npm run test`
- [x] **P1** Design tokens, `index.css`, `tailwind.config.ts`, UI primitives (spec 3.3)
      Gate: `typecheck`, `build`; render smoke test for `Button`, `Badge`, `Tabs`
- [x] **P2** Types, `prng`, `dh`, `esp`, `rules`, `risk`, `threat`, `format`, `validate` with unit tests
      Gate: `npm run test` passes, including exact-score rule assertions
- [x] **P3** Fixture builder, three fixtures, model registry, logs, model eval
      Gate: fixtures A/B/C score exactly 9/78/94; probabilities sum to 1; SA totals within 1% of summary; determinism
- [x] **P4** Store, mock API, live socket simulator, `httpApi`
      Gate: simulator determinism, live stop yields valid `AnalysisResult`, validation cases
- [x] **P5** App shell: router, header, sidebar, footer, hotkeys, search, notifications, export
      Gate: `typecheck`, `build`; component test for search results and export enablement
- [x] **P6** Overview page and components
      Gate: `build`; gauge `aria-valuenow`, matrix filter toggle, upload validation error, uncertain banner for fixture C
- [x] **P7** Inspector
      Gate: `build`; pagination and protocol filtering counts
- [x] **P8** Inferences
      Gate: `build`; threshold slider toggles the Uncertain state
- [ ] **P9** Audit
      Gate: `build`; remediation projected score
- [ ] **P10** Compliance and DH Key Lab, what-if
      Gate: what-if from fixture B hardened → lower score, R01/R04/R05/R06/R07/R08 absent
- [ ] **P11** Settings, logs, report drawer, print CSS, reports
      Gate: report generator tests; log filtering test
- [ ] **P12** Accessibility and responsive pass, README, DECISIONS, final verification
      Gate: Section 17 Definition of Done
