# DECISIONS — IPsec-AI Sentinel frontend

Operating rule: questions are never asked; every deviation, assumption or
interpretation of the spec is recorded here instead.

## Toolchain and configuration

1. **`typecheck` script.** The spec's `tsc -b --noEmit` combination fails on
   TypeScript 5.5 with `TS5094` ("You have not configured 'noEmit' with
   'build'"). The script is `tsc -p tsconfig.json --noEmit`; `npm run build`
   keeps `tsc -b` for the emit-config check, then `vite build`.
2. **Single `tsconfig.json`** (no project references): `strict` + `noUncheckedIndexedAccess`
   + `exactOptionalPropertyTypes`, `target`/`lib` ES2022, path alias `@/*` → `src/*`.
3. **Extra dependency `@types/node`** (dev) — required for `vite.config.ts` /
   `tailwind.config.ts` to typecheck under `tsc -b`.
4. **npm install-scripts.** `esbuild`'s postinstall was approved once via
   `npm install-scripts approve esbuild`; everything else runs with
   `--ignore-scripts=false` defaults after that approval.

## Routing and shell (P5)

5. **`createBrowserRouter`** (not `HashRouter`) with a single layout route that
   renders `Header`, `Sidebar`, `<Outlet/>`, `Footer`, `ReportDrawer`,
   `HelpDialog` and `PrintReport`. Document titles are set from the route table.
6. **Shared file input.** One hidden `<input type="file" accept=".pcap,.pcapng">`
   lives in the layout and is registered in `src/lib/filePicker.ts`, so the
   header button, the empty state and the `u` hotkey all drive the same picker.
7. **`LiveState` nesting.** Live state is stored under `live` (not flattened) so
   its `status` cannot collide with `AnalysisSlice.status`. It is extended with
   `handshake`, `findings`, `revealed`, `classes` and `working` — the working
   analysis rebuilt on every message batch while capturing.
8. **Live speed semantics.** `MockLiveSocket` ticks every `200 / speed` ms, so
   4× runs four simulation ticks per 200 ms of wall clock. `setLiveOptions`
   changes source/speed only while the capture is idle.
9. **IKEv1 step timing.** The six-step IKEv1 exchange uses `index * 0.25 s`,
   which intentionally extends past the 0.2–1.0 s window used for IKEv2.
10. **Fixture files split** into `spec`, `handshake`, `traffic`, `capture`,
    `stats`, `features` and `fixtureBuilder` to honour the ≤250-line file rule.
11. **Report drawer is part of the shell (P5).** The layout needs it for the
    `r` hotkey and Export PDF, so `ReportDrawer`, `PrintPortal` and the report
    markdown renderer are built in P5; their generator tests land in P11.
12. **Print flow.** Export PDF opens the drawer on the current tab, waits two
    animation frames (one for mount, one for paint), then calls
    `window.print()`. `PrintPortal` mounts `#print-root` outside `#root`; the
    report content is rendered with `react-markdown` + `remark-gfm`.
13. **Copy failures fall back to the notification bell.** There is no toast
    component in the spec's primitive list, so a clipboard error calls
    `notify({ severity: 'warn', … })` instead of inventing a new surface.
14. **Storage.** jsdom/Node 26 exposes no `window.localStorage`, so
    `src/test/setup.ts` installs an in-memory `Storage` polyfill; the store
    keeps its own `try/catch` guards for privacy-mode browsers.
15. **R09 confidence.** The rule engine uses the top-class probability as the
    rule confidence, so fixture C's R09 outcome is `unknown` rather than
    `pass`; `describeConfiguration` lives in `src/lib/report.ts` (the copy in
    `fixtureBuilder.ts` predates it and stays as the fixture-local variant).
16. **Responsive breakpoints.** Header search/export collapse into an overflow
    popover below 1024 px (`useMediaQuery('(min-width: 1024px)')`, defaulting
    to the wide layout when `matchMedia` is unavailable, as in jsdom).
