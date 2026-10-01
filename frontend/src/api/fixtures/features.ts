import type { AnalysisResult } from '@/types/analysis'

/** Top contributing features per inferred parameter (spec 8.7). Weights sum to 1. */
export const FEATURE_EVIDENCE: AnalysisResult['featureEvidence'] = [
  {
    param: 'mode',
    features: [
      { name: 'Outer IP length stability', weight: 0.34 },
      { name: 'TTL distribution shift', weight: 0.27 },
      { name: 'Per-packet size variance', weight: 0.22 },
      { name: 'IKE proposal length hints', weight: 0.17 },
    ],
  },
  {
    param: 'child.encryption',
    features: [
      { name: 'ESP length mod 16 distribution', weight: 0.41 },
      { name: 'Minimum ESP overhead', weight: 0.29 },
      { name: 'IV/ICV size delta', weight: 0.19 },
      { name: 'Padding entropy', weight: 0.11 },
    ],
  },
  {
    param: 'child.pfs',
    features: [
      { name: 'Rekey KE payload present', weight: 0.38 },
      { name: 'Rekey interval ratio', weight: 0.27 },
      { name: 'DH group change at rekey', weight: 0.21 },
      { name: 'Rekey packet size delta', weight: 0.14 },
    ],
  },
  {
    param: 'child.replayProtection',
    features: [
      { name: 'Sequence number monotonicity', weight: 0.44 },
      { name: 'Duplicate SPI usage', weight: 0.24 },
      { name: 'Replay window gaps', weight: 0.19 },
      { name: 'Sequence wrap behaviour', weight: 0.13 },
    ],
  },
  {
    param: 'trafficClass',
    features: [
      { name: 'Flow duration', weight: 0.31 },
      { name: 'Packet size distribution', weight: 0.29 },
      { name: 'Inter-arrival CV', weight: 0.23 },
      { name: 'Burst length histogram', weight: 0.17 },
    ],
  },
]
