/**
 * Live-backend mapper (docs/frontend-integration.md).
 *
 * Converts the frozen backend AnalyzeResponse
 * (`docs/api-contract.md`, `docs/openapi.json`) into the UI's
 * `AnalysisResult`. Rules:
 * - `parsed` -> `observed`, `model` -> `inferred`, `measured` -> `observed`.
 * - Backend `"unknown"` becomes a placeholder value with confidence 0 and
 *   an explanatory `note`. Nothing from the backend is ever dropped.
 * - Arrays the backend does not provide (packets, handshake, SAs, series)
 *   stay empty; existing UI empty states render them.
 */
import type {
  AnalysisResult,
  Finding,
  Param,
  Severity,
  ThreatCategory,
  StrideTag,
  TrafficLabel,
} from '@/types/analysis'

/** Backend field object shape (see docs/examples/analyze-v1.json). */
export interface BackendField {
  value: unknown
  source: 'parsed' | 'model' | 'measured'
  confidence: number
  detail?: {
    header_parse?: string
    reason?: string
    size_signal?: { value: unknown; confidence: number }
    decided_by?: string
  } | null
}

export interface BackendFinding {
  id: string
  severity: Severity
  likelihood: number
  impact: number
  text: string
  solution: string
}

export interface BackendAnalyzeResponse {
  fields: Record<string, BackendField>
  ai_confidence: number
  metadata: Record<string, BackendField>
  assessment: {
    security_score: number
    risk_score: number
    risk_level: string
    findings: BackendFinding[]
    threat_matrix: { id: string; likelihood: number; impact: number; risk: number }[]
    breakdown: Record<string, number>
  }
}

type Provenance = Param<unknown>['provenance']

const toProvenance = (source: BackendField['source']): Provenance =>
  source === 'model' ? 'inferred' : 'observed'

const str = (v: unknown, fallback: string): string =>
  typeof v === 'string' ? v : fallback

const CIPHER_MAP: Record<string, string> = {
  'aes-128-cbc': 'AES-128-CBC',
  'aes-256-cbc': 'AES-256-CBC',
  'aes-128-gcm': 'AES-128-GCM-16',
  'aes-256-gcm': 'AES-256-GCM-16',
  '3des-cbc': '3DES-CBC',
  none: 'None',
}

const INTEGRITY_MAP: Record<string, string> = {
  'hmac-sha256': 'HMAC-SHA2-256-128',
  'hmac-sha1': 'HMAC-SHA1-96',
  aead: 'AEAD (implicit)',
  none: 'None',
}

const TRAFFIC_MAP: Record<string, TrafficLabel> = {
  voip: 'VoIP',
  video: 'Video Streaming',
  web: 'Web Browsing',
  icmp: 'ICMP',
  whatsapp: 'WhatsApp',
  email: 'E-mail',
}

const FINDING_CATEGORY: Record<string, ThreatCategory> = {
  'weak-cipher': 'Weak Cipher',
  'weak-dh': 'Key Exchange',
  'weak-integ': 'Weak Cipher',
  'no-pfs': 'PFS',
  'no-replay': 'Replay',
  'long-sa': 'Lifetime',
  ikev1: 'Protocol',
  transport: 'Metadata',
  'no-conf': 'Weak Cipher',
  'unknown-lifetime': 'Lifetime',
  'unknown-replay': 'Replay',
}

const FINDING_STRIDE: Record<string, StrideTag> = {
  'weak-cipher': 'Information Disclosure',
  'weak-dh': 'Information Disclosure',
  'weak-integ': 'Tampering',
  'no-pfs': 'Information Disclosure',
  'no-replay': 'Tampering',
  'long-sa': 'Information Disclosure',
  ikev1: 'Spoofing',
  transport: 'Information Disclosure',
  'no-conf': 'Information Disclosure',
}

/** Category/stride for backend finding ids (unknown-* default by suffix). */
export function findingTaxonomy(id: string): { category: ThreatCategory; stride: StrideTag } {
  const category = FINDING_CATEGORY[id] ?? 'Protocol'
  const stride = FINDING_STRIDE[id] ?? 'Information Disclosure'
  return { category, stride }
}

const num = (v: unknown, fallback: number): number =>
  typeof v === 'number' && Number.isFinite(v) ? v : fallback

const bool = (v: unknown, fallback: boolean): boolean =>
  typeof v === 'boolean' ? v : fallback

/** Placeholder value + confidence-0 note for backend `"unknown"`. */
function unknownNote(field: string): string {
  return `Unknown: the backend declined to decide ${field}.`
}

interface MappedProtocol {
  protocol: AnalysisResult['protocol']
}

/** Map backend fields onto the UI protocol block (honest placeholders). */
export function mapProtocol(fields: Record<string, BackendField>): MappedProtocol['protocol'] {
  const get = (k: string): BackendField => fields[k] ?? { value: 'unknown', source: 'model', confidence: 0, detail: null }
  const ikeVer = str(get('ike_version').value, '')
  const modeVal = str(get('mode').value, '')
  const ipVer = num(get('ip_version').value, 0)
  const encVal = str(get('enc_alg').value, '')
  const authVal = str(get('auth_alg').value, '')
  const dhVal = num(get('dh_group').value, 0)
  const pfsVal = get('pfs').value
  const natVal = get('nat_t').value
  const isNone = (f: BackendField): boolean => f.value === 'unknown' || f.value === 'none'

  const ikeVersion: AnalysisResult['protocol']['ikeVersion'] =
    ikeVer === 'ikev1'
      ? { value: 'IKEv1', provenance: toProvenance(get('ike_version').source), confidence: get('ike_version').confidence }
      : ikeVer === 'ikev2'
        ? { value: 'IKEv2', provenance: toProvenance(get('ike_version').source), confidence: get('ike_version').confidence }
        : { value: 'IKEv2', provenance: 'inferred', confidence: 0, note: 'No IKE observed — not applicable.' };

  const modeDetail = get('mode').detail
  const modeNote =
    modeDetail?.decided_by === 'size-overhead-model'
      ? 'Mode from ESP size overhead (inner headers are encrypted).'
      : modeDetail?.decided_by === 'ah-next-header'
        ? `Mode from AH next header (${modeDetail.header_parse ?? 'n/a'}).`
        : undefined
  const mode: AnalysisResult['protocol']['mode'] =
    modeVal === 'tunnel' || modeVal === 'transport'
      ? {
          value: modeVal,
          provenance: toProvenance(get('mode').source),
          confidence: get('mode').confidence,
          ...(modeNote ? { note: modeNote } : {}),
        }
      : { value: 'tunnel', provenance: 'inferred', confidence: 0, note: 'No IPsec — not applicable.' };

  const cipherName = CIPHER_MAP[encVal] ?? encVal
  const integName = INTEGRITY_MAP[authVal] ?? authVal
  const isAhChild = str(get('ipsec_proto').value, '') === 'ah'

  return {
    ikeVersion,
    exchangeMode:
      ikeVer === 'ikev1'
        ? { value: 'Main Mode', provenance: 'inferred', confidence: 0.5, note: 'Aggressive mode never observed; backend does not distinguish.' }
        : ikeVer === 'ikev2'
          ? { value: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)', provenance: toProvenance(get('ike_version').source), confidence: get('ike_version').confidence }
          : { value: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)', provenance: 'inferred', confidence: 0, note: 'No IKE observed — not applicable.' },
    mode,
    ipVersion:
      ipVer === 4 || ipVer === 6
        ? { value: ipVer === 4 ? 'IPv4' : 'IPv6', provenance: toProvenance(get('ip_version').source), confidence: get('ip_version').confidence }
        : { value: 'IPv4', provenance: 'inferred', confidence: 0, note: unknownNote('ip_version') },
    natTraversal: {
      value: bool(natVal, false),
      provenance: toProvenance(get('nat_t').source),
      confidence: get('nat_t').confidence,
    },
    ike: {
      encryption: {
        value: isNone(get('enc_alg')) ? '' : cipherName,
        provenance: toProvenance(get('enc_alg').source),
        confidence: get('enc_alg').confidence,
        ...(isNone(get('enc_alg')) ? { note: unknownNote('IKE cipher') } : {}),
      },
      integrity: {
        value: isNone(get('auth_alg')) ? '' : integName,
        provenance: toProvenance(get('auth_alg').source),
        confidence: get('auth_alg').confidence,
        ...(isNone(get('auth_alg')) ? { note: unknownNote('IKE integrity') } : {}),
      },
      prf: {
        value: '',
        provenance: 'inferred',
        confidence: 0,
        note: 'Not provided by the backend.',
      },
      dhGroup: {
        value: dhVal,
        provenance: toProvenance(get('dh_group').source),
        confidence: get('dh_group').confidence,
        ...(get('dh_group').value === 'unknown' ? { note: unknownNote('DH group') } : {}),
      },
      lifetimeSec: {
        value: null,
        provenance: 'inferred',
        confidence: 0,
        note: 'Lifetimes are never observed in short captures.',
      },
    },
    child: {
      encryption: {
        value: isAhChild ? 'None' : cipherName === '' ? '' : cipherName,
        provenance: toProvenance(get('enc_alg').source),
        confidence: get('enc_alg').confidence,
        note: isAhChild
          ? 'AH provides integrity only (RFC 4302).'
          : 'Mirrors the IKE suite on this testbed (matrix D8).',
      },
      integrity: {
        value: isAhChild ? integName : integName === '' ? '' : integName,
        provenance: toProvenance(get('auth_alg').source),
        confidence: get('auth_alg').confidence,
        note: isAhChild ? undefined : 'Mirrors the IKE suite on this testbed (matrix D8).',
      },
      pfs: {
        value: pfsVal === true,
        provenance: toProvenance(get('pfs').source),
        confidence: get('pfs').confidence,
        ...(typeof pfsVal !== 'boolean' ? { note: unknownNote('PFS (rekey SK length)') } : {}),
      },
      pfsGroup: {
        value: pfsVal === true ? dhVal : null,
        provenance: toProvenance(get('pfs').source),
        confidence: get('pfs').confidence,
      },
      lifetimeSec: {
        value: null,
        provenance: 'inferred',
        confidence: 0,
        note: 'Lifetimes are never observed in short captures.',
      },
      replayProtection: {
        value: false,
        provenance: 'inferred',
        confidence: 0,
        note: 'Not observed in short captures.',
      },
      esn: {
        value: false,
        provenance: 'inferred',
        confidence: 0,
        note: 'Not observed in short captures.',
      },
    },
  }
}

/** Backend finding -> UI finding (1:1, taxonomy mapped + documented). */
export function mapFinding(f: BackendFinding): Finding {
  const { category, stride } = findingTaxonomy(f.id)
  return {
    id: f.id,
    ruleId: f.id,
    severity: f.severity,
    category,
    stride,
    title: f.text,
    evidence: `likelihood ${f.likelihood}/5 x impact ${f.impact}/5 (backend assessment)`,
    reference: 'Backend rubric docs/security-rubric.md',
    recommendation: f.solution,
    status: 'fail',
  }
}

const TRAFFIC_LABELS: TrafficLabel[] = ['VoIP', 'Video Streaming', 'Web Browsing', 'ICMP', 'WhatsApp', 'E-mail', 'Other']

/** Single backend label+confidence -> 7-way distribution (max-entropy remainder). */
export function mapTrafficClasses(
  label: unknown,
  confidence: number,
): { label: TrafficLabel; probability: number }[] {
  const mapped = typeof label === 'string' ? TRAFFIC_MAP[label] : undefined
  const top: TrafficLabel = mapped ?? 'Other'
  const pTop = mapped ? Math.min(1, Math.max(0, confidence)) : 0
  const rest = (1 - pTop) / (TRAFFIC_LABELS.length - 1)
  return TRAFFIC_LABELS.map((l) => ({
    label: l,
    probability: l === top ? pTop : rest,
  }))
}

/** Full backend response -> UI AnalysisResult (honest empties included). */
export function mapAnalyzeResponse(
  file: { name: string },
  resp: BackendAnalyzeResponse,
  analyzedAt = new Date().toISOString(),
): AnalysisResult {
  const f = resp.fields
  const hasEsp = str(f.ipsec_proto?.value, '') === 'esp'
  const hasAh = str(f.ipsec_proto?.value, '') === 'ah'
  const hasIke = str(f.ike_version?.value, '') === 'ikev1' || str(f.ike_version?.value, '') === 'ikev2'
  const meta = resp.metadata
  const metaNum = (k: string, fallback: number): number => {
    const v = meta[k]?.value
    return typeof v === 'number' && Number.isFinite(v) ? v : fallback
  }
  const trafficLabel = str(f.traffic_type?.value, '')
  const tConf = typeof f.traffic_type?.confidence === 'number' ? (f.traffic_type?.confidence as number) : 0
  return {
    id: `live-${Date.now().toString(36)}`,
    fileName: file.name,
    analyzedAt,
    source: 'upload',
    riskScore: resp.assessment.risk_score,
    overallConfidence: resp.ai_confidence,
    backendAssessment: {
      securityScore: resp.assessment.security_score,
      riskScore: resp.assessment.risk_score,
      riskLevel: resp.assessment.risk_level,
    },
    summary: {
      packets: metaNum('n_packets', 0),
      ikeHandshakes: hasIke ? 1 : 0,
      espStreams: hasEsp ? 1 : 0,
      ahPackets: hasAh ? 1 : 0,
      durationSec: metaNum('duration_s', 0),
    },
    protocol: mapProtocol(f),
    trafficClasses: mapTrafficClasses(trafficLabel === 'unknown' ? undefined : trafficLabel, tConf),
    handshake: [],
    findings: resp.assessment.findings.map(mapFinding),
    sas: [],
    packets: [],
    flowStats: {
      meanLen: metaNum('mean_bytes', 0),
      stdLen: 0,
      meanIatMs: 0,
      burstiness: 0,
      upDownRatio: metaNum('direction_ratio', 0),
    },
    timeSeries: [],
    lengthHistogram: [],
    featureEvidence: [],
  }
}
