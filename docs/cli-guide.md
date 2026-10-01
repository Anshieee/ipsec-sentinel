# CLI user guide (`ipsec-analyze`)

Install: `uv pip install -e .` (entry point `ipsec-analyze`, any cwd).

```bash
ipsec-analyze analyze demo/samples/v1-voip.pcap            # human summary
ipsec-analyze analyze X.pcap --json                        # API-shaped JSON
ipsec-analyze analyze X.pcap --report pdf                  # X.report.pdf
ipsec-analyze batch demo/samples --json                    # every .pcap below
ipsec-analyze train                                        # deterministic (seed 7)
ipsec-analyze evaluate                                     # full eval + report
ipsec-analyze generate-data [--real]                       # rebuild corpus
ipsec-analyze serve [--port 8000]                          # real API
ipsec-analyze serve --mock                                 # frontend samples
```

Errors: exit 2 = usage (missing/non-pcap/empty input, bad flags);
exit 1 = unreadable pcap; exit 3 = missing optional backend
(e.g. reportlab) with the install command named.
`batch` records per-file errors inline and continues.
