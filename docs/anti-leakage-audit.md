# Anti-leakage audit

Corpus: 396 synthetic pcaps. Method: stratified permutation MI (200 shuffles within family×plain strata, Fisher-combined; pass requires p > 0.01) + leave-one-run-out exact-match (pass < 0.20). ESP/AH presence markers are excluded from the incidental set: presence is a declared M3 classification target, not leakage.

| field | p | verdict |
|---|---|---|
| outer_src | 1.000 | PASS |
| outer_dst | 1.000 | PASS |
| non_ike_sports | 1.000 | PASS |
| macs | 1.000 | PASS |
| start_day | 1.000 | PASS |
| spis | 1.000 | PASS |
| combined | 1.000 | PASS |

Leave-one-run-out exact-match accuracy (chance ~0.10, pass < 0.20):
- outer_src: 0.091 PASS
- outer_dst: 0.091 PASS
- non_ike_sports: 0.121 PASS
- macs: 0.091 PASS
- start_day: 0.086 PASS
- spis: 0.091 PASS

SPI uniqueness: 540 distinct SPIs, 0 reused.
values (n>=3) seen in a single variant: 0.

RESULT: PASS
