# IPsec dataset v1 (426 pcaps)

Single dataset deliverable: `ipsec-dataset-v1.tar.gz` (built by
`scripts/build-dataset.sh`, NOT committed — regenerable). Verify from the
repo root with the exact command (paths in the file are relative to the
tarball root, which mirrors `data/`):

```bash
cd /tmp/ds-test && tar -xzf <path-to>/ipsec-dataset-v1.tar.gz \
  && sha256sum -c checksums.sha256 | grep -vc ": OK"   # want 0
```

Or against the live tree: `cd data && sha256sum -c
../dataset/checksums.sha256`. Get the tarball from the release artifacts. Extract over `data/` to restore the full corpus
including `data/real/` (66 captures); without it only synthetic data
regenerates (`generate-data`), and real-dependent steps (real-NAT-T
report, synth→real eval, holdout) skip or fail loudly.

Composition proof: the tarball's `real/` + checksums verified (0
failures over 853 checksum entries, 919 files); with `data/real` present,
`reports/make_all.py` produces all 8 PDFs including
`technical-real-natt.pdf` (verified in `reports/out/`).

## Splits (grouped by run — never split a run across train/test)

- `train.csv`: synthetic r1+r2 (240 rows)
- `test.csv`: synthetic r3 (120 rows)
- `real.csv`: all real captures, held out (66 rows: v1,v3,v5,v7,v12,v18;
  r2/r3 runs include forced CHILD rekeys + extra TCP captures)

Columns: same as `data/manifest.csv`
(`file,variant,traffic,ip_version,packets,esp_packets,ike_packets,source,valid`).

## Labels
`labels/` mirrors `pcaps/` with per-pcap JSON ground truth conforming to
`testbed/label_schema.json` (variant fields from `testbed/matrix.py`).

## Regeneration
`ipsec-analyze generate-data --real && ipsec-analyze train` rebuilds
pcaps, labels, manifest and models deterministically (per-(variant,run,
traffic) seeds). Real captures need the netns testbed
(`testbed/scripts/`).
