# Final report (M5)

## Addendum — v1.2 correctness release (2026-10-04)

Supersedes the counts and scores below where they differ; the M5 record
is kept intact underneath.

- Corpus: **480 pcaps** — 414 synthetic (21 variants × r1–r3 × 6 types +
  plain × {v4,v6} × r1–r3 × 6) + 66 real (v1 × r1/r2/r3 + v3,v5,v7,v12,v18
  × r1/r2 with forced rekeys + extra TCP). Validator gate 480/480,
  config gate 1717/1717, leakage audit green, checksums 961 entries.
- Assessment rule **1.2.0**: 10 controls (new ike-cipher w5,
  ike-integrity w3, both IKE-SA-scoped), confidence-weighted
  posture/coverage (OBSERVED/label 1.0, INFERRED its confidence,
  UNKNOWN 0), LIKELY verdict for inferred FAILs (severity capped one
  level). No weight tuning: data-plane weights unchanged.
- Oracles (hand-computed, f = 1): v1=88, v7=74, v11=71, v8=69, v19=75,
  v20=99, v21=87, plain=WITHHELD (no score).
- Live: v1=89 @ 0.6684, v19=72 @ 0.6258 (weak-cipher LIKELY),
  v20=99 @ 0.6327 (no findings), v21=80 @ 0.6576 (three CONFIRMED IKE
  FAILs, GCM child PASSes at 25), plain=WITHHELD.
- Model eval (regenerated): child enc CV 0.889 (honest ESP-size signal,
  never parsed from IKE), ike rows 1.000, dh 0.0 by design, pfs 0.957.
- UI: backend-mapped (`src/api/backend.ts`) with ike_sa/child_sa cards,
  detection state, controls list, posture+coverage headline (WITHHELD
  shows no gauge), LIKELY badges, SIMULATED badges on simulated
  surfaces; client rule-engine numbers relabeled where they disagree.
- Release asset: `dataset/ipsec-dataset-v1.tar.gz`, sha256 in
  `docs/RELEASE.md` (publish command included, not run).

## What was built
An AI-driven IPsec analysis platform: 18-variant testbed (real netns
captures + byte-realistic synthetic generator), a hybrid classifier
(deterministic wire parsers + RF models with `unknown`), a weighted
security assessment, a frozen API (+mock) and CLI, and PDF reports —
426 pcaps, every manifest row validator-green, leakage audit green.

## Real metrics (sample counts; unknown counts as error throughout,
accuracy-given-attempted reported separately and labeled)
- Corpus: 360 synthetic (18+plain × 3 runs × 6 types) + 66 real
  (v1,v3,v5,v7,v12,v18; r2/r3 include forced rekeys + extra TCP).
- Grouped 5-fold CV (360): parsed fields 1.000; traffic 0.989
  (0.994 attempted); PFS-length model 0.950 (1.000 attempted, v12
  abstains); ESP ablation dh 0.82 (prior + cipher pockets, dh5 0/18,
  dh2 6/18).
- Synth→real (66): parsed 1.000 incl. mode/enc/dh; traffic 0.515
  (1.000 attempted, ZERO wrong guesses); PFS correct on all 5 IKEv2
  rekey pcaps (1.000 attempted), unknown elsewhere.
- Holdout, train 396 → test 30 new runs: parsed 1.000, traffic 0.867.
- Security oracles: v1=88, v7/v11=73, v8=75, plain=5 (hand-computed).

## Limitations (must-read)
Synthetic-only numbers prove pipeline behavior on the synthetic
distribution only. Real evidence covers 6 variants, IPv4, short
captures. PFS unparseable from real IKE (SK-only rekeys, proven).
Lifetimes/replay/ESN never observed. Full list: `docs/limitations.md`.

## Oracle vs live scores (MAJOR-4)
Label-fed oracles are **ideal-visibility** scores (v1 = 88: every field
known incl. lifetimes/replay from labels). The live tool on a short
capture cannot observe lifetimes or replay windows, so live v1 = 73
(88 − lifetime 10 − replay 5, both `unknown`); v12 = 57 (additionally
PFS unknown: QM encrypted). Per-sample live table:
`docs/expected-live-scores.md` (pinned by test). The rubric is
unchanged — only visibility differs, never the weights.

## Human double-checks requested
1. Replay `demo/demo.typescript` and run `demo/DEMO_SCRIPT.md` steps.
2. Skim two technical PDFs (`reports/out/`) for tone/accuracy.
3. Confirm the rubric weights match your risk appetite
   (`docs/security-rubric.md`).
4. Verify the tarball checksum before handing the dataset anywhere.
5. Read `docs/QA_PREP.md` before any defense/demo.
