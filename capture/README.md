# Capture pipeline (M2)

- `synth/synth_pcap.py` — synthetic generator (Scapy, imports
  `testbed/matrix`); `--ingest-real` folds `data/real` labels.
- `validate_pcap.py` — validation gate (independent IKE parse + scapy +
  dpkt + tcpdump; `--self-test` negative controls).
- `audit_leakage.py` — anti-leakage gate (permutation MI + grouped
  nearest-match).
