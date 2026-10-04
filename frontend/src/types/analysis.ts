export type Provenance = 'observed' | 'inferred'
export type Severity = 'critical' | 'high' | 'medium' | 'low'
/** Backend field honesty state (docs/api-contract.md v1.1+). */
export type FieldStatus = 'OBSERVED' | 'INFERRED' | 'UNKNOWN' | 'NOT_OBSERVED' | 'NOT_APPLICABLE'
/** Backend control verdict (v1.2 adds LIKELY: FAIL on inferred evidence). */
export type ControlStatus = 'PASS' | 'FAIL' | 'LIKELY' | 'UNKNOWN' | 'NOT_APPLICABLE'
export type FindingVerdict = 'CONFIRMED' | 'LIKELY'
export type ScoreStatus = 'PUBLISHED' | 'WITHHELD'
export type PolicyId = 'nist-baseline' | 'high-assurance' | 'legacy-interop'
export type TrafficLabel = 'VoIP' | 'Video Streaming' | 'Web Browsing' | 'ICMP' | 'WhatsApp' | 'E-mail' | 'Other'

export interface Param<T> {
  value: T
  provenance: Provenance
  /** 0..1, exactly 1 when observed. Calibrated probability, never "accuracy". */
  confidence: number
  /** Backend honesty state; render UNKNOWN/NOT_OBSERVED as "not observed". */
  status?: FieldStatus
  /** Evidence origin; drives the Method column (parsed/model/measured). */
  source?: 'parsed' | 'model' | 'measured' | 'none'
  /** Explicit method label when the source alone is ambiguous
   * (e.g. size-overhead inference vs generic model). */
  method?: string
  note?: string
}

export interface ProtocolInfo {
  ikeVersion: Param<'IKEv1' | 'IKEv2'>
  /** Derived from ike_sa evidence (never hard-coded): observed exchanges or "not observed". */
  exchangeMode: Param<string>
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
  /** Backend verdict: CONFIRMED (observed bytes) or LIKELY (inferred evidence). */
  verdict?: FindingVerdict
  /** Model confidence behind a LIKELY finding, if known. */
  confidence?: number | null
}

/** Backend assessment control (docs/api-contract.md, rule v1.2.0). */
export interface BackendControl {
  id: string
  ruleVersion: string
  title: string
  status: ControlStatus
  weight: number
  points: number
  evidence: Record<string, unknown> | null
  explanation: string
  resolveBy: string | null
  remediation: string | null
  source: 'observed' | 'inferred' | 'label' | 'none'
  confidence: number
}

/** Backend headline: posture is meaningless without its coverage. */
export interface AssessmentHeadline {
  postureScore: number | null
  coverage: number
  scoreStatus: ScoreStatus
  riskScore: number | null
  riskLevel: string | null
  /** v1.2.1 headline band: numeric-risk band floored by the worst CONFIRMED finding. */
  riskBand: 'LOW' | 'MODERATE' | 'HIGH' | null
  ruleVersion: string
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
  /** Backend risk (100 - posture) when PUBLISHED, else null: never show a score without its coverage. */
  riskScore: number | null
  overallConfidence: number
  /** Backend assessment passthrough (live mode only; see docs/frontend-integration.md). */
  backendAssessment?: { securityScore: number | null; riskScore: number | null; riskLevel: string | null }
  /** v1.1+ backend headline; present on backend-mapped results, absent on fixtures/simulations. */
  posture?: AssessmentHeadline
  /** v1.1+ backend controls; present on backend-mapped results. */
  controls?: BackendControl[]
  /** v1.1+ IPsec detection; false renders the "no IPsec detected" state. */
  detection?: { ipsecDetected: boolean; nPackets?: number; nIke?: number; nEsp?: number; nAh?: number }
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
    /** Null when the backend does not provide the stat: render "not provided", never 0. */
    stdLen: number | null
    meanIatMs: number | null
    burstiness: number | null
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
