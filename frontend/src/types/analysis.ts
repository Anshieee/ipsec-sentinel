export type Provenance = 'observed' | 'inferred'
export type Severity = 'critical' | 'high' | 'medium' | 'low'
export type PolicyId = 'nist-baseline' | 'high-assurance' | 'legacy-interop'
export type TrafficLabel = 'VoIP' | 'Video Streaming' | 'Web Browsing' | 'ICMP' | 'WhatsApp' | 'E-mail' | 'Other'

export interface Param<T> {
  value: T
  provenance: Provenance
  /** 0..1, exactly 1 when observed. Calibrated probability, never "accuracy". */
  confidence: number
  note?: string
}

export interface ProtocolInfo {
  ikeVersion: Param<'IKEv1' | 'IKEv2'>
  exchangeMode: Param<'IKEv2 (IKE_SA_INIT + IKE_AUTH)' | 'Main Mode' | 'Aggressive Mode'>
  mode: Param<'tunnel' | 'transport'>
  ipVersion: Param<'IPv4' | 'IPv6'>
  natTraversal: Param<boolean>
  ike: {
    encryption: Param<string>
    integrity: Param<string>
    prf: Param<string>
    dhGroup: Param<number>
    lifetimeSec: Param<number | null>
  }
  child: {
    encryption: Param<string>
    integrity: Param<string>
    pfs: Param<boolean>
    pfsGroup: Param<number | null>
    lifetimeSec: Param<number | null>
    replayProtection: Param<boolean>
    esn: Param<boolean>
  }
}

export interface HandshakeStep {
  id: string
  step: string
  index: number
  timeSec: number
  direction: 'initiator->responder' | 'responder->initiator' | 'n/a'
  sizeBytes: number
  encrypted: boolean
  details: Record<string, string>
}

export type ThreatCategory = 'Weak Cipher' | 'Key Exchange' | 'PFS' | 'Replay' | 'Lifetime' | 'Metadata' | 'Protocol'
export type StrideTag =
  | 'Spoofing'
  | 'Tampering'
  | 'Repudiation'
  | 'Information Disclosure'
  | 'Denial of Service'
  | 'Elevation of Privilege'

export interface Finding {
  id: string
  ruleId: string
  severity: Severity
  category: ThreatCategory
  stride: StrideTag
  title: string
  evidence: string
  reference: string
  recommendation: string
  status: 'fail'
}

export interface PacketRow {
  no: number
  timeSec: number
  src: string
  dst: string
  proto: 'IKE' | 'ESP' | 'AH' | 'UDP' | 'OTHER'
  spi?: string
  seq?: number
  length: number
  info: string
}

export interface SecurityAssociation {
  id: string
  kind: 'IKE SA' | 'CHILD SA'
  spiOut: string
  spiIn: string
  protocol: 'ESP' | 'IKE'
  mode: 'tunnel' | 'transport' | 'n/a'
  encryption: string
  integrity: string
  packets: number
  bytes: number
  firstSeenSec: number
  lastSeenSec: number
  seqMin: number
  seqMax: number
  replayGaps: number
}

export interface AnalysisResult {
  id: string
  fileName: string
  analyzedAt: string
  source: 'upload' | 'live'
  riskScore: number
  overallConfidence: number
  /** Backend assessment passthrough (live mode only; see docs/frontend-integration.md). */
  backendAssessment?: { securityScore: number; riskScore: number; riskLevel: string }
  summary: {
    packets: number
    ikeHandshakes: number
    espStreams: number
    ahPackets: number
    durationSec: number
  }
  protocol: ProtocolInfo
  /** Sums to 1 (tolerance 1e-6). */
  trafficClasses: { label: TrafficLabel; probability: number }[]
  handshake: HandshakeStep[]
  findings: Finding[]
  sas: SecurityAssociation[]
  /** Representative sample of at most 2000 packets. */
  packets: PacketRow[]
  flowStats: {
    meanLen: number
    stdLen: number
    meanIatMs: number
    burstiness: number
    upDownRatio: number
  }
  /** Packets per 10 s bucket. */
  timeSeries: { t: number; ike: number; esp: number; other: number }[]
  /** 12 bins. */
  lengthHistogram: { bin: string; count: number }[]
  /** Top 4 per inferred param, weights 0..1. */
  featureEvidence: { param: string; features: { name: string; weight: number }[] }[]
}

export type UploadStage = 'uploading' | 'parsing' | 'inferring'
