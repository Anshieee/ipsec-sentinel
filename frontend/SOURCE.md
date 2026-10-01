# Frontend source snapshot

Vendored as a plain snapshot (no `.git`) from the friend's repository:

- Original repo URL: https://github.com/HarshitGbu/sih-frontend-
- Cloned commit: `d2b0d8715f5147ec4e45da29d602190634ce14d3`
- Authorship: all UI code is the friend's work; backend-integration
  changes in this repo touch only the API mapper layer
  (`src/api/live*.ts`, Settings toggle) and are listed in
  `docs/frontend-integration.md`.
- App: Vite 5 + React 18 + TypeScript (strict), Tailwind, Zustand,
  Recharts. See `FRONTEND_SPEC.md` for the original build spec.

Do not commit `node_modules/` or `dist/`.
