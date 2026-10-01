# IPsec Analysis Dashboard Wireframes

## Page 1: Upload/Select PCAP

```
+-----------------------------------------------------+
| IPsec Analysis Dashboard                          |
+-----------------------------------------------------+
|                                                     |
|  [Upload PCAP]  [Select from dataset]  [Analyze]  |
|                                                     |
|  [ ] Include IKE negotiation (default)            |
|  [ ] Include AH packets (if present)              |
|                                                     |
|  [ ] Auto-detect traffic type (default)           |
|  [ ] Force specific traffic type: [Dropdown]     |
|                                                     |
|  [ ] Generate security assessment (default)      |
|                                                     |
+-----------------------------------------------------+
```

## Page 2: Classification Results

```
+-----------------------------------------------------+
| Classification Results                            |
+-----------------------------------------------------+
|  Protocol: IPsec (IKEv2)                         |
|  Mode: Tunnel Mode                                |
|  Encryption: AES-256-GCM-16 (98% confidence)       |
|  Integrity: AES-256-GCM-16 (98% confidence)      |
|  DH Group: DH20 (95% confidence)                  |
|  PFS: Enabled (97% confidence)                      |
|  IP Version: IPv4 (99% confidence)                  |
|  Traffic Type: Web Browsing (85% confidence)       |
|                                                     |
|  [Overall AI Confidence: 92%]                    |
|                                                     |
+-----------------------------------------------------+
```

## Page 3: Security Assessment

```
+-----------------------------------------------------+
| Security Assessment                              |
+-----------------------------------------------------+
|  Security Score: [92/100]                        |
|  Risk Score: [Medium]                             |
|                                                     |
|  Threat Matrix:                                  |
|  +----------------+----------------+----------------+
|  |                | Likelihood     |                |
|  |                | High           | Medium         |
|  | Impact         +----------------+----------------+
|  | High           | Critical       | High           |
|  | Medium         | High           | Medium         |
|  | Low            | Medium         | Low            |
|  +----------------+----------------+----------------+
|                                                     |
|  Findings:                                        |
|  - Weak DH Group (DH20) (Score: 75)              |
|  - Short SA Lifetime (1h) (Score: 70)            |
|  - No Replay Protection (Score: 65)              |
|  - Weak Cipher Suite (Score: 80)                 |
|                                                     |
+-----------------------------------------------------+
```

## Page 4: Traffic Analysis

```
+-----------------------------------------------------+
| Traffic Analysis                                 |
+-----------------------------------------------------+
|  Packet Size Distribution:                       |
|  [Chart: Histogram of packet sizes]               |
|                                                     |
|  Inter-Packet Timing:                           |
|  [Chart: Line graph of timing between packets]    |
|                                                     |
|  Inferred Traffic Type: Web Browsing (85%)       |
|                                                     |
+-----------------------------------------------------+
```

## Page 5: Reports

```
+-----------------------------------------------------+
| Reports                                          |
+-----------------------------------------------------+
|  [Download Executive Report]                     |
|  [Download Technical Report]                     |
|                                                     |
|  Expected Solutions:                              |
|  - Upgrade to DH24 (Score: 90)                    |
|  - Increase SA Lifetime to 8h (Score: 85)         |
|  - Implement Replay Protection (Score: 95)        |
|  - Use AES-256-GCM-256 (Score: 98)               |
|                                                     |
+-----------------------------------------------------+
```

## Navigation

```
+-----------------------------------------------------+
| [Upload] [Classification] [Security] [Traffic] [Reports] |
+-----------------------------------------------------+
```