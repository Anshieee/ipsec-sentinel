# Release dataset asset (v1.2)

The full corpus (except regenerable synthetic data) ships as a GitHub
release asset because `data/real/` (live testbed captures) is not
committed.

## Asset

- File: `dataset/ipsec-dataset-v1.tar.gz` (built by
  `scripts/build-dataset.sh`, NOT committed — regenerable).
- v1.2 contents: 480 pcaps (414 synthetic + 66 real) + 480 labels +
  manifest + split manifests + `checksums.sha256` (961 entries).
- sha256 (v1.2 tarball):
  `1dcbf0f472b18a55788e827a51ab6687802c606d394a0c610994a3a7656da312`
- Verify after download:
  `sha256sum dataset/ipsec-dataset-v1.tar.gz` must print the hash above.

## Publish (maintainer; do NOT run in CI)

```bash
gh release create v1.2 dataset/ipsec-dataset-v1.tar.gz \
  --title "v1.2" \
  --notes "Correctness release: IKE/CHILD SA split, controls-based assessment (rule 1.2.0), mismatch variants v19-v21. Dataset: 480 pcaps, sha256 1dcbf0f472b18a55788e827a51ab6687802c606d394a0c610994a3a7656da312."
```

## Restore (user)

```bash
tar -xzf dataset/ipsec-dataset-v1.tar.gz -C /tmp/ds
cp -r /tmp/ds/* data/
ipsec-analyze generate-data --real   # folds data/real labels + manifest
```

Without the asset, `generate-data --real` / `--ingest-real` exits 2
with an actionable message naming this file; the synthetic-only path
(`generate-data` without `--real`) still works, and real-dependent
tests skip with an explicit reason.
