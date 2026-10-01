# IPsec-AI Sentinel: Frontend Specification (single-pass build)

Audience: an autonomous coding agent (OpenCode). Read this entire document before writing any code. Every requirement is normative unless marked "optional". Where the document is silent, choose the simplest option that satisfies the intent and record it in `DECISIONS.md`.

---

## 0. Operating rules for the agent

1. **Never ask questions.** Decide, document in `DECISIONS.md`, continue.
2. **Work in the phases of Section 16, in order.** After each phase run that phase's gate commands. Do not start the next phase until the gate passes. Fix failures immediately.
3. **Maintain `PROGRESS.md`** as a checklist of the phases. Tick each phase only after its gate passes. Update it after every phase.
4. **Write complete files.** Never write placeholders such as `// TODO`, `// rest unchanged`, `...`, lorem ipsum, or "implement later". Never truncate a file. If a file would exceed roughly 250 lines, split it into modules.
5. **Create one file per tool call** for files over about 100 lines. Re-read a file before editing it.
6. **Strict TypeScript.** No `any`, no `@ts-ignore`, no non-null assertions unless justified in a comment.
7. **Use only the packages listed in Section 2.** If an install fails, retry once, then fall back to the stated alternative, and record it.
8. **No network access at runtime.** No CDN, remote fonts, remote images, analytics, or external APIs.
9. **Determinism.** All mock data must come from the seeded PRNG in Section 8.4. `Math.random()` is forbidden in `src/api/` and `src/lib/`. Use it nowhere except optional cosmetic animation.
10. **Do not stop early.** Finish all phases, then the Definition of Done (Section 17). The final message must summarise what was built, the results of every verification command, and anything unresolved.

---

## 1. Product context and domain rules

The product is the analyst-facing dashboard of an AI-driven IPsec VPN protocol analysis platform. A backend (out of scope) ingests `.pcap`/`.pcapng` traces or live streams, parses IKE/ESP/AH, runs ML models, and returns an `AnalysisResult` (Section 6). This task delivers the **frontend only**, backed by a mock implementation of the API and of a WebSocket-style live capture stream. Swapping to the real backend must require only environment variables (Section 8.6).

### 1.1 Domain constraints the UI must honour (copy and behaviour)

- ESP payloads are encrypted. Parameters therefore have one of two **provenances**:
  - `observed`: read directly from cleartext (IKE_SA_INIT proposals, DH group, SPIs, outer IP version, NAT-T port, ESP sequence numbers, IKEv1 negotiated attributes).
  - `inferred`: estimated by ML or heuristics (tunnel vs. transport mode, cipher family in ESP, PFS, CHILD SA lifetime, replay behaviour, ESN, traffic type inside ESP).
- Every displayed parameter carries a provenance badge (`Observed` or `Inferred`). Inferred values additionally show a confidence percentage.
- "Confidence" is a calibrated probability. Never label it "accuracy".
- Use IKEv2 terminology (IKE SA, CHILD SA). When the detected version is IKEv1, use "Phase 1 / Phase 2 (Quick Mode)".
- In IKEv2, IKE_AUTH and later exchanges are encrypted. The timeline must show them as "Encrypted payload (size and timing only)".
- Mock data must be labelled as such: the footer of every page shows "Demonstration data. Analysis results are simulated." while `VITE_USE_MOCK=true`.

### 1.2 Users

SOC and network-security analysts (Tier 1 to 3) who need a fast posture assessment without manual packet inspection, and a technical lead who needs exportable reports.

---

## 2. Tech stack, packages, scaffolding

### 2.1 Fixed stack

Vite 5, React 18, TypeScript 5.5 (strict), Tailwind CSS 3.4, React Router 6, Zustand 4, Recharts 2, lucide-react, framer-motion 11, react-markdown 9 with remark-gfm 4, clsx, tailwind-merge, Vitest 2, React Testing Library 16, jsdom.

Do **not** add: Tremor, Chart.js, Redux, MUI, Ant Design, shadcn CLI, axios, date-fns, any virtualisation library, any animation library other than framer-motion.

### 2.2 Scaffolding commands (execute in the current directory)

```bash
npm create vite@latest . -- --template react-ts   # accept overwriting the empty directory
npm install
# Pin majors (the template may generate newer ones):
npm install react@18 react-dom@18
npm install -D @types/react@18 @types/react-dom@18 vite@5 @vitejs/plugin-react@4 typescript@~5.5
npm install react-router-dom@6 zustand@4 recharts@2 lucide-react framer-motion@11 react-markdown@9 remark-gfm@4 clsx tailwind-merge
npm install -D tailwindcss@3.4 postcss autoprefixer vitest@2 jsdom @testing-library/react@16 @testing-library/jest-dom@6 @testing-library/user-event@14
npx tailwindcss init -p --ts
```

If the template already uses ESLint flat config, keep it and ensure `npm run lint` passes.

### 2.3 `package.json` scripts (exact)

```json
{
  "dev": "vite",
  "build": "tsc -b && vite build",
  "preview": "vite preview",
  "typecheck": "tsc -b --noEmit",
  "lint": "eslint .",
  "test": "vitest run",
  "verify": "npm run typecheck && npm run lint && npm run test && npm run build"
}
```

### 2.4 Vitest configuration

In `vite.config.ts` set `test: { environment: 'jsdom', globals: true, setupFiles: './src/test/setup.ts', css: false }`. `src/test/setup.ts` imports `@testing-library/jest-dom/vitest`. Add `"types": ["vitest/globals", "@testing-library/jest-dom"]` to `tsconfig.app.json`. Use path alias `@` to `src` in both Vite and TypeScript.

---

## 3. Design system

### 3.1 Colour tokens

Define as CSS variables in `src/styles/index.css` (`:root`) and expose through `tailwind.config.ts` as `colors` that reference the variables.

| Token (Tailwind name) | Hex | Usage |
|---|---|---|
| `base` | `#0F172A` | page background |
| `surface` | `#111C33` | cards, sidebar, header |
| `raised` | `#1E293B` | hover, inputs, table header, tracks |
| `line` | `#263449` | borders and dividers |
| `ink` | `#E2E8F0` | primary text |
| `muted` | `#94A3B8` | secondary text (contrast on `surface` at least 4.5:1) |
| `accent` | `#3B82F6` | links, focus ring, primary chart series |
| `accent-solid` | `#2563EB` | filled buttons (white text passes AA) |
| `highlight` | `#06B6D4` | live indicator, secondary chart series |
| `safe` | `#10B981` | compliant, low risk |
| `warn` | `#F59E0B` | warning, medium severity |
| `danger` | `#EF4444` | critical, high risk |
| `orange` | `#F97316` | high severity (between warn and danger) |

Severity colour mapping: `critical` = `danger`, `high` = `orange`, `medium` = `warn`, `low` = `accent`, `pass` = `safe`, `unknown` = `muted`.
Chart categorical palette (7 classes, in order): `#3B82F6, #06B6D4, #10B981, #F59E0B, #A78BFA, #F472B6, #94A3B8`.

### 3.2 Typography, spacing, shape

- Sans: `Inter, ui-sans-serif, system-ui, -apple-system, "Segoe UI", sans-serif`. Mono: `"JetBrains Mono", ui-monospace, SFMono-Regular, Menlo, monospace`. No web-font files.
- Scale: page title 20/28 semibold; card title 14/20 semibold; body 13/20; caption 12/16; KPI number 28/32 semibold; mono data 12/16. Apply `font-variant-numeric: tabular-nums` globally to `.tnum` and to every number cell.
- Spacing base 4 px. Grid gap 16. Card padding 16. Main content padding 24. Radius: cards 12, buttons and inputs 8, chips 999.
- Shadows: none by default; `0 0 0 1px line`; focus ring `0 0 0 2px base, 0 0 0 4px accent`.
- Fixed dimensions: header height 56, sidebar 248 (expanded) or 64 (icon rail), drawer width 560 (max 100vw minus 24).

### 3.3 Required primitives (`src/components/ui/`)

`Card`, `CardHeader`, `Button` (variants `primary|secondary|ghost|danger`, sizes `sm|md`), `IconButton` (requires `label` prop rendered as `aria-label` and tooltip), `Badge` (tones `neutral|safe|warn|orange|danger|info|cyan`), `ProvenanceBadge` (`observed` = solid cyan outline with Eye icon, `inferred` = dashed violet-free outline with Sparkles icon; add `title` explaining), `ConfidenceBar` (0..1, thin bar plus `%` text), `SeverityBadge` (icon + label + colour), `StatusChip` (icon + label for Enabled/Disabled/Unknown), `Skeleton`, `EmptyState`, `ErrorState` (message + Retry button), `Tooltip` (accessible, keyboard focusable), `Tabs` (roving tabindex, arrow-key navigation, `role="tablist"`), `Drawer` (focus trap, Esc closes, `aria-modal`, restores focus), `Popover`, `Toggle` (`role="switch"`), `SegmentedControl`, `Kbd`, `cn()` helper (`clsx` + `tailwind-merge`).

Icons only from lucide-react. Suggested: `ShieldCheck`, `LayoutDashboard`, `ScanSearch`, `BrainCircuit`, `ShieldAlert`, `Scale`, `Settings`, `Upload`, `Bell`, `Search`, `Radio`, `Download`, `FileText`, `Eye`, `Sparkles`, `Lock`, `KeyRound`, `Clock`, `Repeat`, `Network`.

### 3.4 Accessibility requirements (all pages)

- WCAG 2.1 AA: text contrast at least 4.5:1, non-text UI at least 3:1.
- Every interactive element has a visible focus ring, is reachable by Tab in DOM order, and operable by keyboard.
- Icon-only buttons have `aria-label`.
- Severity and status always combine colour, icon, and text.
- Each chart is wrapped in a `figure` with a `figcaption` summary and a visually hidden `table` containing the same data.
- Live-updating regions (capture counters, notifications) use `aria-live="polite"` and throttle announcements to at most one per 5 s.
- `prefers-reduced-motion: reduce` disables framer-motion transitions (use `useReducedMotion`) and CSS animations (pulse, shimmer).
- Landmarks: `header`, `nav` (labelled "Primary"), `main`, `footer`. Skip link "Skip to main content" as the first focusable element.

---

## 4. Application shell

### 4.1 Routing

`createBrowserRouter` (or `HashRouter` if simpler; record the choice) with a layout route rendering `Header`, `Sidebar`, `<Outlet/>`, `Footer`, `ReportDrawer`, `HelpDialog`.

| Path | Page | Sidebar label |
|---|---|---|
| `/` | Overview | Dashboard Overview |
| `/inspector` | Inspector | Traffic Inspector & PCAP Parser |
| `/inferences` | Inferences | AI Inferences & Classification |
| `/audit` | Audit | Security Audit & Threat Matrix |
| `/compliance` | Compliance | Config Compliance & DH Key Lab |
| `/settings` | Settings | Settings & AI Model Logs |

Unknown paths render a 404 `EmptyState` with a link to `/`. Document title format: `<Page> | IPsec-AI Sentinel`.

### 4.2 Header (sticky, height 56)

Left to right:
1. Sidebar collapse `IconButton` (visible below 1024 px, and as a toggle above).
2. Brand: `ShieldCheck` icon, text "IPsec-AI Sentinel", muted subtitle "Workbench".
3. **Monitor status pill** (button). States: `Live Monitoring: Idle` (muted dot) and `Active Capture` (cyan dot, pulsing unless reduced motion, plus elapsed `mm:ss`). Click toggles the simulated live capture (Section 9). A small chevron opens a popover to choose the simulated source (Fixture A, B, or C) and speed (1x or 4x); disabled while capturing.
4. **Upload button** "Upload .pcap / .pcapng trace" (primary). Opens a hidden `<input type="file" accept=".pcap,.pcapng">`. Uses the same handler as the drop zone.
5. **Search** input with placeholder "Search findings, packets, steps…" and a `Kbd` hint `/`. Behaviour in Section 4.5.
6. **Notification bell** with unread count badge (cap "9+"). Popover shows the 5 latest notifications with severity icon, message, relative time, and "Mark all read".
7. **Export** group: `Export PDF` and `Export JSON` (secondary buttons). Disabled with a tooltip "Run an analysis first" when no analysis is loaded.
8. **Analyst menu** (avatar circle "AN"): shows "Analyst" and "SOC Tier 2"; items: Settings, Keyboard shortcuts, Reset demo data.

Below 1024 px, collapse items 5 and 7 into an overflow menu; the header must never wrap or overflow.

### 4.3 Sidebar

`nav aria-label="Primary"`. Six items with icons, active state (left 3 px accent bar plus `raised` background, `aria-current="page"`). At the bottom: capture status summary card (idle or live counters) and the app version string `v0.1.0`. Icon-rail mode shows tooltips.

### 4.4 Footer

One line: "Demonstration data. Analysis results are simulated." (only when mock) and the build version. Height 32.

### 4.5 Global search

Client-side. Index built from the current analysis: findings (title, evidence, recommendation), handshake steps, recommendations, packets (`info`, SPI, IPs, up to the sampled 2,000). Case-insensitive substring match. Dropdown grouped by type, maximum 3 results per group, maximum 9 overall. Arrow keys move, Enter navigates to the relevant route and sets `highlightId` in the store (the target row gets a 2 s accent outline and `scrollIntoView`). Esc closes. If no analysis: dropdown shows "No analysis loaded".

### 4.6 Keyboard shortcuts (ignore when focus is in an input, textarea, or contenteditable)

`/` focus search; `u` open file picker; `l` toggle live capture; `r` toggle report drawer; `?` open help dialog (lists these); `Esc` close topmost overlay. Implement in a single `useHotkeys` hook.

### 4.7 Export

- **Export JSON:** `Blob` of `JSON.stringify(analysis, null, 2)`, filename `sentinel-<fileName>-<yyyymmdd-hhmm>.json`. Packets array is included in full.
- **Export PDF:** opens the report drawer on the currently selected tab, waits one animation frame, then calls `window.print()`. The print stylesheet (Section 12) renders only the report.

---

## 5. State management (Zustand)

`src/store/useSentinel.ts`, one store with slices in separate files (`analysisSlice`, `uploadSlice`, `liveSlice`, `uiSlice`, `settingsSlice`). Persist only `settings` (via `persist` middleware, key `sentinel.settings.v1`, guarded with try/catch).

```ts
interface UploadState { status: 'idle'|'uploading'|'parsing'|'inferring'|'complete'|'error'; progress: number; fileName?: string; fileSize?: number; error?: string; summary?: AnalysisResult['summary']; }
interface LiveState { status: 'idle'|'connecting'|'capturing'|'stopping'; sourceId: 'A'|'B'|'C'; speed: 1|4; elapsedSec: number; counters: { packets: number; ike: number; esp: number; ah: number; other: number }; recent: PacketRow[] /* ring buffer, 200 */; }
interface UiState { sidebarCollapsed: boolean; reportOpen: boolean; reportTab: 'executive'|'technical'; helpOpen: boolean; highlightId?: string; searchQuery: string; notifications: Notification[]; }
interface Settings { density: 'comfortable'|'compact'; uncertainThreshold: number /*0.6*/; minRuleConfidence: number /*0.6*/; defaultPolicyId: PolicyId; defaultSource: 'A'|'B'|'C'; simulateErrors: boolean; }
interface AnalysisSlice { current: AnalysisResult | null; previousRiskScore?: number; status: 'idle'|'loading'|'ready'|'error'; error?: string; setAnalysis(a: AnalysisResult): void; clear(): void; }
```

`Notification = { id: string; severity: 'info'|'warn'|'critical'|'success'; message: string; at: string; read: boolean }`.

Selectors: `useAnalysis()`, `useDerived()` returning memoised derived values (findings by severity, threat matrix counts, category scores, compliance results). Derived values must be computed with pure functions from `src/lib/` and covered by tests.

---

## 6. Data contract (`src/types/analysis.ts`)

Implement exactly. Extend only where stated.

```ts
export type Provenance = 'observed' | 'inferred';
export type Severity = 'critical' | 'high' | 'medium' | 'low';
export type PolicyId = 'nist-baseline' | 'high-assurance' | 'legacy-interop';
export type TrafficLabel = 'VoIP' | 'Video Streaming' | 'Web Browsing' | 'ICMP' | 'WhatsApp' | 'E-mail' | 'Other';

export interface Param<T> { value: T; provenance: Provenance; confidence: number; /* 0..1, exactly 1 when observed */ note?: string }

export interface ProtocolInfo {
  ikeVersion: Param<'IKEv1' | 'IKEv2'>;
  exchangeMode: Param<'IKEv2 (IKE_SA_INIT + IKE_AUTH)' | 'Main Mode' | 'Aggressive Mode'>;
  mode: Param<'tunnel' | 'transport'>;
  ipVersion: Param<'IPv4' | 'IPv6'>;
  natTraversal: Param<boolean>;
  ike: { encryption: Param<string>; integrity: Param<string>; prf: Param<string>; dhGroup: Param<number>; lifetimeSec: Param<number | null> };
  child: { encryption: Param<string>; integrity: Param<string>; pfs: Param<boolean>; pfsGroup: Param<number | null>; lifetimeSec: Param<number | null>; replayProtection: Param<boolean>; esn: Param<boolean> };
}

export interface HandshakeStep {
  id: string; step: string; index: number; timeSec: number;
  direction: 'initiator->responder' | 'responder->initiator' | 'n/a';
  sizeBytes: number; encrypted: boolean; details: Record<string, string>;
}

export interface Finding {
  id: string; ruleId: string; severity: Severity; category: ThreatCategory; stride: StrideTag;
  title: string; evidence: string; reference: string; recommendation: string; status: 'fail';
}
export type ThreatCategory = 'Weak Cipher' | 'Key Exchange' | 'PFS' | 'Replay' | 'Lifetime' | 'Metadata' | 'Protocol';
export type StrideTag = 'Spoofing' | 'Tampering' | 'Repudiation' | 'Information Disclosure' | 'Denial of Service' | 'Elevation of Privilege';

export interface PacketRow {
  no: number; timeSec: number; src: string; dst: string; proto: 'IKE' | 'ESP' | 'AH' | 'UDP' | 'OTHER';
  spi?: string; seq?: number; length: number; info: string;
}

export interface SecurityAssociation {
  id: string; kind: 'IKE SA' | 'CHILD SA'; spiOut: string; spiIn: string; protocol: 'ESP' | 'IKE';
  mode: 'tunnel' | 'transport' | 'n/a'; encryption: string; integrity: string;
  packets: number; bytes: number; firstSeenSec: number; lastSeenSec: number;
  seqMin: number; seqMax: number; replayGaps: number;
}

export interface AnalysisResult {
  id: string; fileName: string; analyzedAt: string; source: 'upload' | 'live';
  riskScore: number; overallConfidence: number;
  summary: { packets: number; ikeHandshakes: number; espStreams: number; ahPackets: number; durationSec: number };
  protocol: ProtocolInfo;
  trafficClasses: { label: TrafficLabel; probability: number }[]; // sums to 1 (tolerance 1e-6)
  handshake: HandshakeStep[];
  findings: Finding[];
  sas: SecurityAssociation[];
  packets: PacketRow[];            // representative sample of at most 2000 packets
  flowStats: { meanLen: number; stdLen: number; meanIatMs: number; burstiness: number; upDownRatio: number };
  timeSeries: { t: number; ike: number; esp: number; other: number }[]; // packets per 10 s bucket
  lengthHistogram: { bin: string; count: number }[];                     // 12 bins
  featureEvidence: { param: string; features: { name: string; weight: number }[] }[]; // top 4 per inferred param, weights 0..1
}
```

Also define in `src/types/misc.ts`: `ModelEntry { id; name; task; version; type: 'Rule-based'|'GBM'|'CNN'|'Transformer'; macroF1: number; lastTrained: string; latencyMs: number; params: string }`, `LogLine { id; ts: string; level: 'DEBUG'|'INFO'|'WARN'|'ERROR'; source: string; message: string }`, `Policy`, `DhGroup`, `WhatIfConfig` (Section 10).

---

## 7. Analysis engine in the browser (pure functions, `src/lib/`)

### 7.1 Rule engine (`rules.ts`)

The findings, the risk score, the threat matrix, and the compliance table **all derive from one rule table**. Fixtures must not hard-code findings; they call `evaluate(protocol, trafficClasses, policy, minRuleConfidence)`.

```ts
export type RuleResult = 'fail' | 'pass' | 'unknown';
export interface Rule { id: string; severity: Severity; category: ThreatCategory; stride: StrideTag; title: string; reference: string; recommendation: string;
  check(ctx: RuleContext): { result: RuleResult; evidence: string } }
```

A rule that depends on an **inferred** parameter returns `unknown` when that parameter's confidence is below `minRuleConfidence` (default 0.6). Unknown never contributes to the score.

The baseline policy (`nist-baseline`) rules, exactly:

| ID | Severity | Category | Fails when | Reference | Recommendation |
|---|---|---|---|---|---|
| R01 | critical | Key Exchange | `ike.dhGroup` is 1 or 2 (modulus below 1536 bits) | NIST SP 800-131A Rev. 2; Logjam (CVE-2015-4000) | Replace DH group 1/2 with group 14 or higher, preferably ECP group 19, 20, or 21. |
| R02 | critical | Weak Cipher | `ike.encryption` or `child.encryption` starts with `3DES` or `DES` | Sweet32 (CVE-2016-2183); NIST SP 800-131A Rev. 2 | Replace 3DES/DES with AES-256-GCM (or AES-128-GCM). |
| R03 | critical | Protocol | `exchangeMode` is `Aggressive Mode` | RFC 2409; NIST SP 800-77 Rev. 1 | Disable IKEv1 Aggressive Mode; migrate to IKEv2 with certificate or strong PSK authentication. |
| R04 | high | PFS | `child.pfs` is false | NIST SP 800-77 Rev. 1; RFC 7296 | Enable Perfect Forward Secrecy on the CHILD SA using an ECP group or MODP 2048 or larger. |
| R05 | high | Replay | `child.replayProtection` is false | RFC 4303 (ESP anti-replay) | Enable ESP anti-replay with a window of at least 64 packets; consider ESN on high-throughput links. |
| R06 | high | Lifetime | `child.lifetimeSec` greater than policy maximum (baseline 28,800 s) | NIST SP 800-77 Rev. 1 | Reduce CHILD SA lifetime to 3,600 s or 8 hours at most, and enforce volume-based rekeying. |
| R07 | medium | Weak Cipher | `child.integrity` or `ike.integrity` is `HMAC-SHA1-96` or `HMAC-MD5-96` | RFC 8247; NIST SP 800-131A Rev. 2 | Use HMAC-SHA2-256 or higher, or an AEAD cipher such as AES-GCM. |
| R08 | medium | Weak Cipher | `ike.encryption` or `child.encryption` starts with `AES-` and contains `CBC` | RFC 8247 | Prefer AES-GCM (AEAD). CBC with separate HMAC is acceptable only where GCM is unavailable. |
| R09 | medium | Metadata | top traffic-class probability is at least 0.6 (traffic type is inferable) | NIST SP 800-77 Rev. 1 (traffic-flow confidentiality) | Enable traffic-flow confidentiality (ESP padding, dummy traffic) or use a fixed-size cell tunnel. |
| R10 | low | Replay | `child.esn` is false | RFC 4304 | Enable Extended Sequence Numbers to remove 32-bit sequence exhaustion risk. |
| R11 | low | Key Exchange | `ike.dhGroup` is 14 or 15 | RFC 8247 | Prefer elliptic-curve groups (19, 20, 21) for stronger security per byte. |

`evidence` strings must quote actual values, for example `IKE SA uses DH group 2 (1024-bit MODP); observed in IKE_SA_INIT.`

STRIDE mapping: R01 Information Disclosure; R02 Information Disclosure; R03 Spoofing; R04 Information Disclosure; R05 Tampering; R06 Information Disclosure; R07 Tampering; R08 Information Disclosure; R09 Information Disclosure; R10 Tampering; R11 Information Disclosure.

### 7.2 Risk score (`risk.ts`)

```ts
const WEIGHT: Record<Severity, number> = { critical: 25, high: 12, medium: 5, low: 2 };
export const computeRiskScore = (findings: Pick<Finding,'severity'>[]): number =>
  Math.min(100, findings.reduce((s, f) => s + WEIGHT[f.severity], 0));
export const riskBand = (s: number) => s >= 70 ? 'high' : s >= 40 ? 'moderate' : 'low'; // labels: HIGH RISK, MODERATE RISK, LOW RISK
```

Colour: low = `safe`, moderate = `warn`, high = `danger`.

### 7.3 Other pure modules

- `threat.ts`: `threatMatrix(findings)` returns counts for each `Severity` x `ThreatCategory` (4 x 7). `categoryScores(findings)` returns, per category, `100 - min(100, sum of weights of that category)` (a safety score for the radar chart).
- `esp.ts`: `espLength(innerBytes, cfg)` as in Section 8.5.
- `dh.ts`: the DH group table (Section 10.3) and `securityBits(group)`.
- `report.ts`: `buildExecutiveReport(analysis): string` and `buildTechnicalReport(analysis): string` (Markdown, Section 11).
- `format.ts`: `fmtBytes`, `fmtDuration` (`1h 32m 14s`), `fmtPct` (one decimal), `fmtInt` (locale grouping), `relTime`.
- `validate.ts`: `validateUpload(file)` (Section 8.2).
- `prng.ts`: `mulberry32(seed)`, `hashString(s)`.

---

## 8. Mock API layer (`src/api/`)

### 8.1 Client interface (`client.ts`)

```ts
export interface SentinelApi {
  uploadAndAnalyze(file: File, onProgress: (p: { stage: UploadStage; progress: number }) => void, signal?: AbortSignal): Promise<AnalysisResult>;
  getModelRegistry(): Promise<ModelEntry[]>;
  getModelLogs(sinceId?: string): Promise<LogLine[]>;
  openLiveCapture(sourceId: 'A'|'B'|'C', speed: 1|4): LiveSocket;
}
export const api: SentinelApi = import.meta.env.VITE_USE_MOCK === 'false' ? httpApi : mockApi;
```

`httpApi` (`http.ts`) must be a real implementation: `POST ${VITE_API_BASE_URL}/api/analyze` (multipart, using `XMLHttpRequest` for upload progress), `GET /api/models`, `GET /api/logs`, and a `WebSocket(${VITE_WS_URL}/ws/live)` wrapper implementing `LiveSocket`. It is untested against a server but must compile and be type-safe.

### 8.2 Upload validation

`validateUpload(file)` rejects with a specific message: extension not `.pcap` or `.pcapng` ("Unsupported file type. Upload a .pcap or .pcapng trace."), size 0 ("The file is empty."), size above 200 MB ("File exceeds the 200 MB limit."). Validation runs before any progress starts and shows an inline `role="alert"` message in the drop zone.

### 8.3 Simulated pipeline

`mockApi.uploadAndAnalyze`: stages and timings (scaled by nothing; fixed): `uploading` 0 to 40 % over 1200 ms, `parsing` 40 to 75 % over 1500 ms, `inferring` 75 to 100 % over 1300 ms; progress updates every 50 ms. Honour `AbortSignal` (reject with `AbortError`). If the file name contains `corrupt` or `settings.simulateErrors` is true, fail during `parsing` with "Failed to parse capture: unexpected end of file at packet 18,204." Fixture selection: name contains `gcm` gives A; contains `cbc` gives B; contains `ikev1` or `legacy` gives C; otherwise `hashString(name) % 3` (0 A, 1 B, 2 C). The result copies the fixture with `fileName` replaced, `analyzedAt = new Date().toISOString()`, `source = 'upload'`, and a fresh `id`.

### 8.4 Determinism utilities

```ts
export function mulberry32(a: number) { return () => { a |= 0; a = (a + 0x6D2B79F5) | 0; let t = Math.imul(a ^ (a >>> 15), 1 | a); t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t; return ((t ^ (t >>> 14)) >>> 0) / 4294967296; }; }
export function hashString(s: string): number { let h = 2166136261; for (let i = 0; i < s.length; i++) { h ^= s.charCodeAt(i); h = Math.imul(h, 16777619); } return h >>> 0; }
```

Fixture seeds: A `0xA11CE`, B `0xB0B`, C `0xC0FFEE`.

### 8.5 ESP length model

```ts
// tunnel mode: innerBytes includes the inner IP header (20 or 40); transport mode: it does not
export function espLength(payload: number, c: { outerIp: 20|40; iv: number; icv: number; block: number; tunnelInnerIp: 0|20|40 }) {
  const inner = payload + c.tunnelInnerIp;
  const padded = Math.ceil((inner + 2) / c.block) * c.block;   // +2: pad length and next header
  return c.outerIp + 8 + c.iv + padded + c.icv;                 // 8: SPI + sequence number
}
```

Cipher parameters: AES-GCM: iv 8, icv 16, block 4. AES-CBC + HMAC-SHA1-96: iv 16, icv 12, block 16. AES-CBC + HMAC-SHA2-256-128: iv 16, icv 16, block 16. 3DES-CBC + HMAC-SHA1-96: iv 8, icv 12, block 8. Traffic payload size distributions per class (bytes, before ESP): VoIP 60 to 200 uniform at 20 ms cadence; Video Streaming 1100 to 1380 (90 %) and 60 to 120 (10 %); Web Browsing bimodal 60 to 100 (45 %) and 1300 to 1400 (55 %); ICMP constant 84; WhatsApp 90 to 620 with bursts; E-mail 200 to 1200 uniform; Other uniform 60 to 1400. The dominant class of a fixture (Section 8.7) draws 80 % of its ESP packets from its distribution, the rest from the others weighted by probability.

### 8.6 Environment variables (`.env.example`, committed)

```
VITE_USE_MOCK=true
VITE_API_BASE_URL=http://localhost:8000
VITE_WS_URL=ws://localhost:8000
```

### 8.7 Fixtures (`src/api/fixtures/`)

Three fixtures generated by `buildFixture(spec)` in `fixtureBuilder.ts` from the tables below, so parameters, handshake, SAs, packets, statistics, and findings stay mutually consistent. Findings come from the rule engine. Risk scores come from `computeRiskScore`. **The engine must reproduce these totals** (asserted in tests): A = 9, B = 78, C = 94.

| | **A: modern** | **B: legacy CBC** | **C: obsolete IKEv1** |
|---|---|---|---|
| Default file name | `ipsec_ikev2_tunnel_aes256gcm.pcapng` | `branch_vpn_aescbc_sha1.pcap` | `legacy_ikev1_transport_3des_v6.pcap` |
| Duration (s) | 7,320 | 68,400 | 4,120 |
| Packets / IKE handshakes / ESP streams / AH | 48,213 / 2 / 4 / 0 | 1,204,377 / 3 / 6 / 0 | 9,377 / 2 / 2 / 0 |
| IKE version, exchange mode | IKEv2 obs, IKEv2 (IKE_SA_INIT + IKE_AUTH) obs | IKEv2 obs, IKEv2 (IKE_SA_INIT + IKE_AUTH) obs | IKEv1 obs, Aggressive Mode obs |
| Mode (inferred, confidence) | tunnel 0.98 | tunnel 0.95 | transport 0.82 |
| IP version, NAT-T (obs) | IPv4, false | IPv4, true | IPv6, false |
| IKE encryption / integrity / PRF (obs) | AES-256-GCM-16 / AEAD (implicit) / PRF_HMAC_SHA2_384 | AES-128-CBC / HMAC-SHA1-96 / PRF_HMAC_SHA1 | 3DES-CBC / HMAC-SHA1-96 / PRF_HMAC_SHA1 |
| DH group (obs) | 14 | 2 | 1 |
| IKE lifetime | null (not observed) | null (not observed) | 28,800 obs |
| CHILD encryption (inferred, conf) | AES-256-GCM-16, 0.97 | AES-128-CBC, 0.93 | 3DES-CBC, 0.78 |
| CHILD integrity (inferred, conf) | AEAD (implicit), 0.97 | HMAC-SHA1-96, 0.90 | HMAC-SHA1-96, 0.74 |
| PFS (inferred, conf), PFS group | true 0.92, 14 (0.90) | false 0.88, null | false 0.70, null |
| CHILD lifetime s (inferred, conf) | 3,600, 0.94 | 32,400, 0.87 | 3,600, 0.66 |
| Replay protection (inferred, conf) | true 0.96 | false 0.81 | true 0.72 |
| ESN (inferred, conf) | false 0.89 | false 0.85 | false 0.69 |
| Rekey times (s) | CHILD at 3,600 | CHILD at 32,400 and 64,800 | none |
| Traffic classes (VoIP / Video / Web / ICMP / WhatsApp / E-mail / Other) | 0.04 / 0.08 / 0.78 / 0.02 / 0.03 / 0.03 / 0.02 | 0.71 / 0.07 / 0.06 / 0.02 / 0.11 / 0.02 / 0.01 | 0.08 / 0.05 / 0.22 / 0.44 / 0.04 / 0.14 / 0.03 |
| Overall confidence | 0.964 | 0.918 | 0.731 |
| Expected rule failures | R09, R10, R11 | R01, R04, R05, R06, R07, R08, R09, R10 | R01, R02, R03, R04, R07, R10 |
| Expected score | 9 (LOW RISK) | 78 (HIGH RISK) | 94 (HIGH RISK) |

Notes: in fixture C the top traffic probability (0.44) is below the 0.6 threshold, so R09 does not fire and the classifier card shows the **"Uncertain"** state. Fixture C's CHILD parameters are inferred because IKEv1 Quick Mode is encrypted.

**Handshake generation** (`buildHandshake`): IKEv2 steps `IKE_SA_INIT request`, `IKE_SA_INIT response`, `IKE_AUTH request`, `IKE_AUTH response`, then `ESP stream established`, then one `CREATE_CHILD_SA (rekey)` request and response per rekey time. IKEv1 Aggressive: `Phase 1 Aggressive Mode msg 1/2/3`, `Phase 2 Quick Mode msg 1/2/3`, `ESP stream established`. Timestamps (s): IKEv2 init 0.000 and 0.012, auth 0.031 and 0.058, first ESP 0.071. IKEv1: 0.000, 0.041, 0.083, then Quick Mode 0.120, 0.160, 0.201, ESP 0.240. Rekey request/response at the rekey time and +0.020 s. Sizes: `IKE_SA_INIT = 184 + dhBytes` (dhBytes from Section 10.3), `IKE_AUTH request = 288`, `IKE_AUTH response = 272`, `CREATE_CHILD_SA = 160 + (PFS ? dhBytes : 0)`; IKEv1 messages 216, 184, 96, 152, 152, 72. `details` for `IKE_SA_INIT` steps: `Initiator SPI`, `Responder SPI` (16 hex chars from the PRNG), `Proposal: encryption`, `integrity`, `PRF`, `DH group`, `Nonce length` (32), `NAT-D` (`present`/`absent`). Encrypted steps have `encrypted: true` and `details = { Payload: 'Encrypted (size and timing only)' }`.

**SAs:** one `IKE SA` entry plus one `CHILD SA` entry per direction per rekey generation (SPIs from the PRNG, 8 hex chars). Packet and byte totals across SAs must sum to about 99 % of `summary.packets`; `seqMin/seqMax` consistent with counts; `replayGaps`: A 0, B 3, C 0.

**Packets:** 2,000-packet sample (or all packets for C if fewer than 2,000 are generated), sorted by `timeSec`, with the handshake packets first at their timestamps. ESP packets use the SPI of the active CHILD SA, incrementing `seq` per SPI, `length` from `espLength`. `info` strings: `IKE_SA_INIT (initiator)`, `ESP (SPI 0x…, seq …)`, etc. IPs: A `10.10.0.2` to `203.0.113.10`; B `192.168.20.5` to `198.51.100.7`; C `2001:db8::2` to `2001:db8:ffff::1`. IKE uses UDP 500 (4500 with NAT-T).

**flowStats, timeSeries, lengthHistogram:** computed from the generated sample. `timeSeries` uses 10 s buckets scaled to the full `summary`. `lengthHistogram` has 12 equal-width bins from 0 to 1,500 bytes. `burstiness` is the coefficient of variation of inter-arrival times.

**featureEvidence:** for each inferred parameter (mode, child cipher, PFS, replay, traffic class) four features with weights, for example cipher: `ESP length mod 16 distribution` 0.41, `Minimum ESP overhead` 0.29, `IV/ICV size delta` 0.19, `Padding entropy` 0.11. Weights are descending and normalised to sum 1 per parameter.

---

## 9. Simulated live capture

### 9.1 Socket abstraction (`live.ts`)

```ts
export interface LiveMessage { type: 'open'|'packet'|'handshake'|'param'|'classification'|'stats'|'finding'|'close'; seq: number; ts: number; payload: unknown }
export interface LiveSocket { onmessage: ((m: LiveMessage) => void) | null; onclose: (() => void) | null; onerror: ((e: Error) => void) | null; close(): void }
```

`MockLiveSocket` emits `LiveMessage`s on a 200 ms tick (`setInterval`, divided by `speed`; for 4x, advance four simulated ticks per real tick so the sequence remains identical). The stream is fully determined by the fixture seed.

### 9.2 Scripted timeline (simulated time `t` in seconds)

| Simulated time or condition | Emitted |
|---|---|
| `t = 0` | `open` |
| `0.2` to `1.0` | `handshake` messages for the IKE steps of the chosen fixture (real relative timestamps compressed: use the step index times 0.25 s), each also emits a `packet` |
| From `t = 1.2` | Each tick 6 to 14 ESP `packet` messages (PRNG), `stats` every 1 s |
| ESP packets seen >= 150 | `param`: mode (confidence ramps `final * n/(n+300)`) |
| >= 300 | `param`: child encryption and integrity |
| >= 600 | `param`: replay protection and ESN |
| >= 700 | `param`: PFS (and group) |
| >= 800 | `classification` every 1 s: `p = normalize(0.8*prev + 0.2*target + jitter)` starting from uniform |
| `t = 40` (labelled "time-compressed rekey") | `handshake` `CREATE_CHILD_SA (rekey)`; then `param`: CHILD lifetime (inferred value from the fixture) |
| Any moment the rule engine yields a new `fail` | `finding` |

Observed parameters (IKE version, mode of exchange, IP version, NAT-T, IKE cipher, DH group) are revealed right after the `IKE_SA_INIT` response (or the third Aggressive Mode message for IKEv1). A parameter's `confidence` keeps ramping until it reaches its fixture value.

### 9.3 Store integration

`liveSlice.start(sourceId, speed)` opens the socket, sets `status: 'connecting'` then `'capturing'` on `open`. It maintains a **working analysis** that is rebuilt on each message batch: counters, revealed params (others shown as "Pending…" skeletons with a dashed border), running findings via the rule engine (with unknown rules ignored), running risk score, running class probabilities. Overview and Inspector read from `live.working` when `live.status === 'capturing'` and from `analysis.current` otherwise. The header pill shows `Active Capture` with `mm:ss`. `stop()` closes the socket, freezes the working state into a full `AnalysisResult` (`source: 'live'`, `fileName: 'live-capture-<yyyymmdd-hhmmss>'`, packets from the ring buffer sample), sets it as `analysis.current`, and pushes a notification "Live capture stopped. Analysis ready." Starting a capture while an upload is in progress is disallowed (button disabled with tooltip).

Notifications emitted: capture started, each new **critical** finding ("Critical: <title>"), rekey observed, capture stopped, analysis complete after upload.

---

## 10. Pages

Shared page layout: `<main>` with page title (h1) and a one-line description; content in a 12-column grid (`grid-cols-12 gap-4`). Each data-driven card supports four states (Section 13). Use `data-testid` on: `risk-gauge`, `kpi-mode`, `kpi-confidence`, `kpi-volume`, `upload-zone`, `crypto-card`, `class-chart`, `handshake-timeline`, `threat-matrix`, `findings-list`, `report-drawer`, `packet-table`, `policy-select`, `dh-table`, `whatif-form`, `log-viewer`.

### 10.1 Overview (`/`)

**A. KPI bar** (4 cards, 3 columns each at 1280 px and above; 2 x 2 at 768 to 1279 px):
1. **Global Risk Score**: custom SVG semicircular gauge (`viewBox="0 0 200 120"`; path `M 20 100 A 80 80 0 0 1 180 100`; `pathLength="100"`; track stroke `raised` width 14 round caps; value arc `stroke-dasharray="{score} 100"`, colour by band; animate `strokeDashoffset` with framer-motion unless reduced motion). Centre text: score (28 px) and `/ 100`; beneath, the band label (`LOW RISK`, `MODERATE RISK`, `HIGH RISK`) with icon. `role="meter"` with `aria-valuemin=0`, `aria-valuemax=100`, `aria-valuenow`, `aria-valuetext="78 out of 100, high risk"`. Below: delta versus `previousRiskScore` (`+12 since previous analysis`, arrow icon, red if higher).
2. **Detected mode badge group**: three badges `IKEv2`, `Tunnel Mode`, `ESP` (or `AH` if AH packets exist), each with `ProvenanceBadge` and, when inferred, confidence.
3. **AI Confidence**: large `96.4%`, label "Overall AI confidence (calibrated probability)", thin bar, tooltip explaining aggregation ("mean of inferred-parameter confidences weighted by parameter importance"). Colour: at least 0.85 `safe`, 0.7 to 0.85 `warn`, below 0.7 `danger`.
4. **Capture volume**: four mini-stats (Packets, IKE handshakes, ESP streams, Duration).

**B. Left column (5 columns)**
1. **Upload and capture zone** (`data-testid="upload-zone"`): dashed drop area, `Upload` icon, text "Drag and drop a .pcap or .pcapng trace, or click to browse", secondary text "Maximum 200 MB. Processed locally in demo mode." Supports drag-over highlight, keyboard activation (Enter and Space), `aria-describedby` for constraints, inline error alert, cancel button during processing. While processing: determinate progress bar (`role="progressbar"`), stage labels `Uploading`, `Parsing packets`, `Running AI inference`, percentage, file name and size. On complete: **instant stream summary** table (Packets, IKE, ESP, AH, Other) with a success check icon and "Analysis complete".
2. **Protocol and cryptographic suite card** (`data-testid="crypto-card"`): two sections. When IKEv2: "IKE SA" and "CHILD SA". When IKEv1: "Phase 1 (ISAKMP SA)" and "Phase 2 (Quick Mode SA)". Rows: Encryption (badge `AES-GCM` or `AES-CBC` with key size), Integrity/Authentication, PRF, DH group with name (for example "Group 14 (MODP-2048)") and PFS badge (`Enabled` green or `Disabled` red), IP version, NAT-T, Mode. Each row shows a `ProvenanceBadge` and confidence if inferred. Rows with a failing rule show a small `SeverityBadge` linking to the finding.
3. **Status chips row**: Replay protection (`Enabled` with ESN sub-label `ESN on/off`), IKE lifetime, CHILD lifetime (formatted `1 h`, with chip `Within policy` or `Exceeds policy (max 8 h)`), NAT-T. `Unknown` chip (grey) when confidence is below `minRuleConfidence`.

**C. Right column (7 columns)**
1. **Encrypted traffic classifier** (`data-testid="class-chart"`): horizontal `BarChart` sorted descending, probability axis 0 to 100 %, top-1 highlighted with `accent`, others `muted`; toggle (`SegmentedControl`) to a donut (`PieChart`). Under the chart: top-1 label with confidence. If top-1 is below `uncertainThreshold`, show an amber `Uncertain classification` banner listing the top 3 candidates. Hidden data table for a11y.
2. **Handshake timeline** (`data-testid="handshake-timeline"`): vertical stepper of `handshake` steps with icon, name, relative time (`+0.012 s`), size, direction arrow, and an `Encrypted` badge where applicable. Each step is a button that expands (`aria-expanded`) to a definition list of `details`. Enter and Space toggle; Up and Down arrows move between steps. Steps appear with staggered framer-motion fade (30 ms stagger; none if reduced motion). A "Rekey" step is visually distinguished (cyan `Repeat` icon).
3. **Live ticker** (only while capturing): a compact list of the last 8 packets (time, proto badge, length) plus a `packets/s` sparkline (`LineChart`, last 60 s).

**D. Bottom row (full width)**
1. **Threat matrix** (`data-testid="threat-matrix"`): 4 rows (Critical, High, Medium, Low) by 7 columns (`Weak Cipher`, `Key Exchange`, `PFS`, `Replay`, `Lifetime`, `Metadata`, `Protocol`) with counts. Cell background is the severity colour at 15 % (0 count shows `0` in muted, no colour) and text with the count plus an accessible name like "Critical, Key Exchange: 1 finding". Row totals on the right and column totals below. Clicking a non-zero cell toggles a filter (`aria-pressed`); a "Clear filter" button appears.
2. **Findings and recommendations engine** (`data-testid="findings-list"`): filtered by the matrix selection and the global search. Each finding: `SeverityBadge`, title, category chip, evidence (mono), reference, STRIDE tag, and a recommendation block with a `KeyRound` icon and a "Copy" button. Sorted by severity then rule ID. Empty state: "No findings. This configuration meets the baseline policy." (green check).
3. **Report preview button** "Open report preview" (also `r`). See Section 11.

### 10.2 Traffic Inspector & PCAP Parser (`/inspector`)

Layout: top stats strip, then two columns (packet table and detail), then charts.

1. **Stats strip**: total, IKE, ESP, AH, Other counts and duration (from `summary` or live counters).
2. **Filters**: protocol chips (`IKE`, `ESP`, `AH`, `UDP`, `OTHER`, multi-select), text filter (matches src, dst, SPI, info; debounced 150 ms), direction select (`All`, `Outbound`, `Inbound`; by source IP equal to the initiator IP), "Reset filters".
3. **Packet table** (`data-testid="packet-table"`): columns No., Time (s, 6 decimals), Source, Destination, Proto (coloured badge), SPI (mono), Seq, Length, Info. Sortable by No., Time, Length. **Pagination** with 100 rows per page, page-size selector (50, 100, 250), first/prev/next/last, "Showing 1 to 100 of 2,000 sampled packets (of 48,213 total)". Row selection by click or Up/Down keys (`role="grid"` with roving focus). Sticky header. Density from settings.
4. **Packet detail panel**: for the selected packet show a decoded header table and a hex dump. IKE packets: Initiator SPI, Responder SPI, Next Payload, Version, Exchange Type (numeric and name), Flags, Message ID, Length. ESP packets: SPI, Sequence Number, Payload length, Estimated padding, Estimated IV/ICV, with a banner "Payload is encrypted. Only the header is observable." The hex dump shows 64 bytes (16 per row: offset, hex, ASCII) generated deterministically from the packet number (`mulberry32(no)`); IKE headers are real-looking (first 28 bytes constructed from fields), ESP starts with SPI and sequence number then pseudo-random bytes. Copy-hex button.
5. **SA table**: columns Kind, SPI out, SPI in, Mode, Encryption, Integrity, Packets, Bytes, First seen, Last seen, Seq range, Replay gaps (highlight non-zero in `warn` with icon).
6. **Charts**: stacked `AreaChart` of packets per 10 s by protocol (`timeSeries`), and `BarChart` of `lengthHistogram` with caption "ESP length distribution. Overhead and padding patterns support cipher inference." Each with hidden tables.
7. Empty state when no analysis: text plus button "Upload a trace" and dev-only "Load sample analysis".

### 10.3 AI Inferences & Classification (`/inferences`)

1. **Inference table**: one row per parameter (IKE version, exchange mode, tunnel/transport, IP version, NAT-T, IKE cipher, integrity, PRF, DH group, CHILD cipher, CHILD integrity, PFS, PFS group, CHILD lifetime, replay, ESN). Columns: Parameter, Value, Provenance, Confidence (`ConfidenceBar`), Method (`Direct parse`, `Rule-based heuristic`, `GBM classifier`, `Sequence model`), and an expand control revealing `featureEvidence` as horizontal bars (Recharts `BarChart`, layout vertical) with a caption "Top contributing features (importance weights)".
2. **Traffic classification detail**: class probability table (label, probability, bar), top-1 summary, threshold slider bound to `settings.uncertainThreshold` (0.3 to 0.9, step 0.05, keyboard accessible, with live effect on the "Uncertain" state).
3. **Flow features card**: `meanLen`, `stdLen`, `meanIatMs`, `burstiness`, `upDownRatio` with short definitions (formal language).
4. **Model evaluation** (static demonstration data from `src/api/modelEval.ts`): a 7 x 7 **confusion matrix** heatmap for the traffic classifier (CSS grid, diagonal 0.82 to 0.97, off-diagonals small, rows sum to 1, cell colour `accent` at intensity by value, each cell has an accessible name with value) and a **reliability diagram** (`LineChart`: predicted probability bins 0.1 to 1.0 against observed frequency, with the diagonal reference and the model curve slightly below the diagonal at high confidence; caption states "Calibration: Expected Calibration Error 0.031").
5. **Confidence breakdown**: `BarChart` of confidence for each inferred parameter, colour by band.
6. Cross-links: each parameter links to the related finding (if any) on `/audit`.

DH group table (used here, on Compliance, and in fixtures), `src/lib/dh.ts`:

| Group | Name | Kind | Bits | Security bits | KE bytes | Status |
|---|---|---|---|---|---|---|
| 1 | MODP-768 | MODP | 768 | below 64 | 96 | Broken |
| 2 | MODP-1024 | MODP | 1024 | 80 | 128 | Deprecated |
| 5 | MODP-1536 | MODP | 1536 | 90 | 192 | Deprecated |
| 14 | MODP-2048 | MODP | 2048 | 112 | 256 | Acceptable |
| 15 | MODP-3072 | MODP | 3072 | 128 | 384 | Acceptable |
| 16 | MODP-4096 | MODP | 4096 | 152 | 512 | Acceptable |
| 19 | ECP-256 | ECP | 256 | 128 | 64 | Recommended |
| 20 | ECP-384 | ECP | 384 | 192 | 96 | Recommended |
| 21 | ECP-521 | ECP | 521 | 256 | 132 | Recommended |

For sorting and charting, treat "below 64" as 64 with a footnote.

### 10.4 Security Audit & Threat Matrix (`/audit`)

1. **Header summary**: risk gauge (reuse), band, counts by severity, and "Score derivation" text: `25 x critical + 12 x high + 5 x medium + 2 x low, capped at 100`.
2. **Full threat matrix** (same component as Overview, larger).
3. **Score contribution waterfall**: `BarChart` with one bar per failing finding sized by its weight, ordered descending, plus a total bar. Hidden table alternative.
4. **Category safety radar**: `RadarChart` of `categoryScores` across the seven categories (0 to 100), caption "Higher is safer".
5. **Findings table**: sortable (severity, category, rule, STRIDE), filterable by severity chips and STRIDE tag, each row expandable to show evidence, reference, and recommendation. Export of the filtered list as CSV via Blob (`findings.csv`).
6. **STRIDE breakdown**: six-item horizontal list with counts and the findings mapped.
7. **Remediation plan**: an ordered checklist grouped `Immediate (critical)`, `Short term (high)`, `Planned (medium and low)` built from recommendations; each item has a local-only checkbox (in-memory state) and a progress bar "3 of 8 completed". Optional: show a projected score after ticked items are applied (`computeRiskScore` over unticked findings), displayed as "Projected risk score: 24".

### 10.5 Config Compliance & DH Key Lab (`/compliance`)

**Section 1: Policy compliance**
- `Policy` select (`data-testid="policy-select"`) with three policies:

| Policy | Rule changes relative to baseline |
|---|---|
| NIST SP 800-77 Rev. 1 baseline (`nist-baseline`, default) | none (Section 7.1 as written) |
| High assurance (`high-assurance`) | R06 maximum 14,400 s; R07 raised to high; R08 raised to high; R10 raised to medium; R11 raised to medium |
| Legacy interoperability (`legacy-interop`) | R06 maximum 86,400 s; R07 lowered to low; R08 disabled; R11 disabled |

- The policy evaluation reuses `evaluate(...)` with overrides; the primary Overview score always uses the baseline.
- Results table: Rule ID, Requirement, Observed value, Provenance, Result (`Pass` green check, `Fail` severity badge, `Unknown` grey), Reference. Summary cards: compliance percentage (`pass / (pass + fail)`, unknown excluded, shown with a note "n rules could not be evaluated"), pass, fail, unknown counts. Policy-specific score displayed next to the baseline score.

**Section 2: DH Key Lab** (`data-testid="dh-table"`)
- Table of the nine groups (Section 10.3) with a status badge (`Broken` danger, `Deprecated` orange, `Acceptable` info, `Recommended` safe), sortable by security bits and KE bytes. The group detected in the current analysis is highlighted with a "Detected" chip.
- `BarChart` of security bits by group (bars coloured by status) with reference lines at 112 ("minimum acceptable") and 128 ("recommended minimum").
- **Key-exchange payload cost** mini-chart: KE bytes by group with note "Elliptic-curve groups offer equal or greater security with smaller payloads."
- **DH explainer** (formal, concise paragraph): ephemeral Diffie-Hellman exchange, why small moduli are vulnerable to precomputation (Logjam), why PFS depends on fresh ephemeral keys per CHILD SA.

**Section 3: What-if configuration evaluator** (`data-testid="whatif-form"`)
- Controlled form: IKE version (`IKEv1`/`IKEv2`), exchange mode (options depend on version), IKE encryption (`AES-128-CBC`, `AES-256-CBC`, `AES-128-GCM-16`, `AES-256-GCM-16`, `3DES-CBC`), IKE integrity (`AEAD (implicit)`, `HMAC-SHA1-96`, `HMAC-SHA2-256-128`, `HMAC-SHA2-384-192`), DH group (from the table), PFS toggle and PFS group, CHILD encryption and integrity (same options), CHILD lifetime (number input in seconds, 300 to 172,800), replay protection toggle, ESN toggle, mode (tunnel/transport), and "Assumed traffic exposure" (`Inferable` sets top probability to 0.7; `Uninferable` to 0.4).
- Live result panel: projected risk score (gauge), findings list, and a delta chip versus the current analysis (`-64` in green). Button "Load current analysis into form" and "Reset". Values are validated (lifetime range) with inline errors.
- Uses only `evaluate` and `computeRiskScore` (no separate logic). All inputs treated as `observed` with confidence 1.

### 10.6 Settings & AI Model Logs (`/settings`)

1. **Preferences** (persisted): density (`SegmentedControl`), uncertainty threshold slider, minimum rule confidence slider (0.3 to 0.9), default compliance policy, default simulated source, "Simulate parse errors" toggle, and a read-only card showing risk-band thresholds. "Reset all settings" and "Reset demo data" (clears analysis, notifications, live state).
2. **Model registry** table (from `getModelRegistry`), five entries:

| Name | Task | Type | Version | Macro-F1 | Latency | Last trained |
|---|---|---|---|---|---|---|
| ike-parser-rules | IKE/ESP header and proposal parsing | Rule-based | 1.4.0 | 1.000 | 0.4 ms | 2026-08-30 |
| cipher-fingerprint-gbm | ESP cipher and integrity family | GBM | 2.1.3 | 0.962 | 3.1 ms | 2026-09-12 |
| mode-pfs-replay-gbm | Tunnel/transport, PFS, replay, ESN | GBM | 1.8.0 | 0.934 | 2.7 ms | 2026-09-12 |
| traffic-cnn1d | Traffic type inside ESP | CNN | 3.0.2 | 0.887 | 11.8 ms | 2026-09-18 |
| traffic-transformer | Traffic type (ensemble member) | Transformer | 0.9.1 | 0.901 | 24.6 ms | 2026-09-21 |

3. **Log viewer** (`data-testid="log-viewer"`): monospace, virtual-free scrolling container (`role="log"`, `aria-live="off"` with a manual "Live announce" toggle off by default), initial 200 lines from `getModelLogs`, then one new line every 1,200 ms while the page is mounted (PRNG-seeded generator producing realistic lines such as `INFO  traffic-cnn1d  Inference batch=32 latency=11.6ms`, `WARN  cipher-fingerprint-gbm  Low margin (0.07) between AES-CBC and 3DES-CBC`). Controls: level filter chips, text search, pause/resume, auto-scroll toggle, clear, and "Download .log". Cap the buffer at 2,000 lines.
4. **About** card: version, build mode (mock/real), contract endpoints.

---

## 11. Reports

`ReportDrawer` (right side, `data-testid="report-drawer"`, `Tabs`: Executive, Technical). Actions: `Copy Markdown`, `Download .md` (filename `sentinel-<tab>-report-<yyyymmdd>.md`), `Print / Save as PDF`. Rendered with `react-markdown` and `remark-gfm` using Tailwind-styled components for `h1..h3`, `table`, `code`, `ul`.

**Executive report (about one page):** title; metadata table (file, analysed at, source, analyst "Analyst"); overall risk (score, band, one-sentence interpretation); AI confidence with interpretation; detected configuration in one line; top three findings by severity with impact statements; top five prioritised recommendations; scope and limitations paragraph ("Inferred parameters are probabilistic estimates derived from encrypted-traffic side channels; observed parameters are read directly from cleartext protocol fields.").

**Technical report:** 1. Summary (capture metrics); 2. Detected protocol parameters (table with provenance and confidence); 3. IKE handshake analysis (table of steps); 4. Security associations (table); 5. Traffic inference (class probabilities and flow statistics); 6. Findings (table with rule, severity, category, STRIDE, evidence, reference); 7. Threat matrix (Markdown table of counts); 8. Recommendations (grouped by priority); 9. Methodology (rule engine, scoring formula, models used with macro-F1 from the registry); 10. Limitations and assumptions; Appendix: legend for provenance.

Reports must be generated by pure functions and unit-tested (headings present, contains the score, table row count equals findings count, no `undefined` or `NaN` in output).

---

## 12. Print stylesheet (`src/styles/print.css`)

Implement a `PrintPortal` that renders the active report Markdown into a `div#print-root` appended to `document.body` (outside `#root`) only while printing or while the drawer is open. CSS: `@media print { body > #root { display: none !important } #print-root { display: block !important; color: #000; background: #fff; font-size: 11pt } #print-root table { border-collapse: collapse } #print-root th, #print-root td { border: 1px solid #999; padding: 4px 6px } @page { margin: 16mm } }` and `@media screen { #print-root { display: none } }`. Avoid page breaks inside table rows (`tr { break-inside: avoid }`) and add page numbers via footer text only if trivial (optional).

---

## 13. Required UI states (every data-driven component)

| State | Behaviour |
|---|---|
| Empty (no analysis) | `EmptyState` with icon, one-sentence guidance, primary button "Upload a trace", secondary "Start live capture", and a dev-only (`import.meta.env.DEV`) button "Load sample analysis" that opens a small menu for fixtures A, B, C. |
| Loading | Skeletons matching the final layout (never a lone spinner). |
| Error | `ErrorState` with the message and a Retry button that re-invokes the last action. |
| Populated | Final content. |

Overview, Inspector, Inferences, Audit, and Compliance all consume the same store and show the same empty state.

---

## 14. Responsive and density behaviour

- Supported widths 768 to 2560 px. No horizontal page scroll at 768, 1024, 1280, 1440, 1920. Wide tables scroll inside `overflow-x-auto` wrappers with `tabIndex=0` and an accessible label.
- Below 1024 px the sidebar becomes the icon rail; below 768 px show a full-width notice "This workbench is optimised for tablet and desktop widths." (no mobile layout is built).
- Overview grid: at 1280 px and above, left 5 / right 7; below, stacked single column.
- Density `compact` reduces table row height from 40 to 32 px and card padding from 16 to 12.

---

## 15. Copy deck (use verbatim)

| Location | Text |
|---|---|
| Empty analysis title | "No analysis loaded" |
| Empty analysis body | "Upload a .pcap or .pcapng trace, or start a simulated live capture, to generate a security posture assessment." |
| Uncertain banner | "Uncertain classification. The top prediction is below the confidence threshold; treat the traffic type as unknown." |
| Provenance tooltip (observed) | "Read directly from cleartext protocol fields." |
| Provenance tooltip (inferred) | "Estimated by an AI model from encrypted-traffic characteristics. Confidence is a calibrated probability." |
| ESP payload banner | "Payload is encrypted. Only the header is observable." |
| Rule unknown | "Not evaluated: insufficient confidence in the underlying inference." |
| Mock footer | "Demonstration data. Analysis results are simulated." |
| No findings | "No findings. This configuration meets the baseline policy." |

---

## 16. Build phases and gates

Create the folder structure first:

```
src/
  api/ (client.ts, http.ts, mock.ts, live.ts, modelEval.ts, fixtures/ (spec.ts, fixtureBuilder.ts, index.ts), logs.ts, models.ts)
  components/ (layout/, kpi/, upload/, crypto/, charts/, timeline/, threat/, findings/, report/, inspector/, inference/, compliance/, settings/, ui/)
  pages/ (Overview.tsx, Inspector.tsx, Inferences.tsx, Audit.tsx, Compliance.tsx, Settings.tsx, NotFound.tsx)
  hooks/ (useHotkeys.ts, useReducedMotionSafe.ts, useDebounce.ts)
  lib/ (rules.ts, risk.ts, threat.ts, esp.ts, dh.ts, report.ts, format.ts, validate.ts, prng.ts)
  store/ (useSentinel.ts, slices/)
  styles/ (index.css, print.css)
  test/ (setup.ts)
  types/ (analysis.ts, misc.ts)
```

| Phase | Deliverable | Gate (all must pass) |
|---|---|---|
| P0 | Scaffold, pinned deps, Tailwind, alias, Vitest config, scripts, `.env.example`, `PROGRESS.md` | `npm run typecheck`, `npm run build`, `npm run test` (0 tests allowed via `--passWithNoTests`) |
| P1 | Tokens, `index.css`, `tailwind.config.ts`, UI primitives (3.3) | `typecheck`, `build`; a render smoke test for `Button`, `Badge`, `Tabs` |
| P2 | Types, `prng`, `dh`, `esp`, `rules`, `risk`, `threat`, `format`, `validate` with unit tests | `npm run test` passes, including exact-score assertions for rules on hand-built inputs |
| P3 | Fixture builder, three fixtures, model registry, logs, model eval | Test: fixtures A, B, C score exactly 9, 78, 94; probabilities sum to 1; SA packet totals within 1 % of summary; determinism (two builds deep-equal) |
| P4 | Store, mock API, live socket and simulator, `httpApi` | Tests: simulator determinism (same seed gives same first 50 messages), live stop yields a valid `AnalysisResult`, validation cases |
| P5 | App shell: router, header, sidebar, footer, hotkeys, search, notifications, export | `typecheck`, `build`; component test for search results and export enablement |
| P6 | Overview page and all its components | `build`; tests: gauge `aria-valuenow`, matrix filter toggling, upload validation error, uncertain banner for fixture C |
| P7 | Inspector | `build`; test: pagination and protocol filtering counts |
| P8 | Inferences | `build`; test: threshold slider toggles the Uncertain state |
| P9 | Audit | `build`; test: remediation projected score |
| P10 | Compliance and DH Key Lab, what-if | Test: what-if loaded with fixture B then changed to AES-256-GCM, DH 19, PFS on, lifetime 3,600, replay on gives a lower score and no R01, R04, R05, R06, R07, R08 |
| P11 | Settings, logs, report drawer, print CSS, reports | Tests: report generators; log filtering |
| P12 | Accessibility and responsive pass, README, DECISIONS, final verification | Section 17 complete |

---

## 17. Definition of done

Run `npm run verify`; every command must exit 0. Then run `npm run dev` and, using the running application (or headless checks where available), confirm each item:

- [ ] AC-01 Loading fixtures A, B, C (via file names containing `gcm`, `cbc`, `legacy`) shows scores 9, 78, 94 with bands LOW, HIGH, HIGH and consistent numbers on every page.
- [ ] AC-02 Uploading a `.txt` file shows the exact error text; a 0-byte `.pcap` shows the empty-file error; a file named `corrupt.pcap` shows the parse error and a working Retry.
- [ ] AC-03 Fixture C shows the Uncertain banner; fixtures A and B do not.
- [ ] AC-04 Every displayed parameter has a provenance badge; inferred ones show confidence.
- [ ] AC-05 Starting live capture from the header updates counters, reveals parameters progressively, produces at least one critical finding notification for source C, and stopping it yields an exportable analysis.
- [ ] AC-06 Threat matrix cell click filters findings; Clear filter restores them; keyboard operable.
- [ ] AC-07 Report drawer opens with `r`, traps focus, closes with Esc, restores focus; Copy, Download, and Print work; print preview shows only the report.
- [ ] AC-08 Export JSON downloads a valid file that parses back and equals the in-memory analysis.
- [ ] AC-09 Inspector pagination, sorting, filtering, and packet detail with hex dump work; ESP banner appears.
- [ ] AC-10 DH Key Lab table, chart, and what-if evaluator work; what-if loaded from the current analysis reproduces its score.
- [ ] AC-11 Compliance policy switching changes the results table while the Overview baseline score stays unchanged.
- [ ] AC-12 Settings persist across reload; "Reset demo data" clears analysis and notifications.
- [ ] AC-13 Log viewer streams, filters, pauses, and downloads.
- [ ] AC-14 Keyboard-only navigation reaches every control; visible focus everywhere; skip link works; shortcuts `/ u l r ?` work.
- [ ] AC-15 No horizontal page scroll at 768, 1024, 1280, and 1920 px; no console errors or warnings.
- [ ] AC-16 `prefers-reduced-motion` disables animations.
- [ ] AC-17 No network requests are made at runtime except Vite dev assets.

---

## 18. Deliverable documents

1. **README.md**: overview, screenshots section (text placeholders are not allowed; describe pages instead), setup, scripts, folder map, environment variables, how to switch from mock to the real backend, the backend contract (`POST /api/analyze`, `GET /api/models`, `GET /api/logs`, `WS /ws/live` with the `LiveMessage` envelope and example JSON for each message type), keyboard shortcuts, testing, known limitations.
2. **DECISIONS.md**: each assumption and deviation with a one-line reason.
3. **PROGRESS.md**: the final phase checklist, all ticked.
4. **`.env.example`**.

---

## 19. Out of scope

Real pcap parsing in the browser, authentication, server code, phone layout, light theme, internationalisation, printing of the dashboard pages themselves, persisted analyses across reloads.

---

## 20. Final response format

When finished, reply with: (1) a five-line summary of what was built; (2) a table of each verification command and its result; (3) the list of acceptance criteria AC-01 to AC-17 with pass or fail; (4) any unresolved issues and the decisions recorded in `DECISIONS.md` that the user should review.
