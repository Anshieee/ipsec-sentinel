/**
 * Live-backend mapper (docs/frontend-integration.md).
 *
 * Converts the v1.2 backend AnalyzeResponse (`docs/api-contract.md`,
 * `docs/openapi.json`) into the UI's `AnalysisResult`. Rules:
 * - `ike_sa` / `child_sa` objects are the source of truth (each field
 *   carries its own status); flat `fields` are not used for crypto.
 * - Backend `"unknown"` / NOT_OBSERVED / UNKNOWN never render as a
 *   value: they get confidence 0, status passthrough and a "not
 *   observed" note.
 * - `detection.ipsec_detected === false` renders the "no IPsec
 *   detected" state (no score, no findings).
 * - `score_status === 'WITHHELD'` renders no gauge and no risk band:
 *   riskScore is null, confirmed FAILs and resolve-by hints still show.
 * - LIKELY findings keep the backend-capped severity and carry the
 *   inferred badge + confidence (looked up from their control).
 * - Arrays the backend does not provide (packets, handshake, SAs,
 *   series) stay empty; existing UI empty states render them.
 */
import type {
  AnalysisResult,
  AssessmentHeadline,
  BackendControl,
  ControlStatus,
  FieldStatus,
  Finding,
  FindingVerdict,
  Param,
  ScoreStatus,
  Severity,
  ThreatCategory,
  StrideTag,
  TrafficLabel,
} from '@/types/analysis'

/** Backend field object shape (see docs/examples/analyze-v1.json). */
export interface BackendField {
  value: unknown
  source: 'parsed' | 'model' | 'measured' | 'none'
  confidence: number
  status?: FieldStatus
  detail?: {
    header_parse?: string
    reason?: string
    size_signal?: { value: unknown; confidence: number }
    decided_by?: string
  } | null
  evidence?: Record<string, unknown> | null
}

export interface BackendFinding {
  id: string
  severity: Severity
  likelihood: number
  impact: number
  text: string
  solution: string
  verdict?: FindingVerdict
}

export interface BackendAssessment {
  controls: BackendControl[]
  posture_score: number | null
  coverage: number
  score_status: ScoreStatus
  security_score: number | null
  risk_score: number | null
  risk_level: string | null
  findings: BackendFinding[]
  threat_matrix: { id: string; likelihood: number; impact: number; risk: number }[]
  breakdown: Record<string, number>
  rule_version: string
}

export interface BackendAnalyzeResponse {
  fields: Record<string, BackendField>
  ike_sa: Record<string, BackendField>
  child_sa: Record<string, BackendField>
  detection: { ipsec_detected: boolean }
  ai_confidence: number
  metadata: Record<string, BackendField>
  assessment: BackendAssessment
}

type Provenance = Param<unknown>['provenance']

const toProvenance = (source: BackendField['source']): Provenance =>
  source === 'model' ? 'inferred' : 'observed'

const toStatus = (f: BackendField): FieldStatus => f.status ?? 'OBSERVED'

const str = (v: unknown, fallback: string): string =>
  typeof v === 'string' ? v : fallback

const CIPHER_MAP: Record<string, string> = {
  'aes-128-cbc': 'AES-128-CBC',
  'aes-256-cbc': 'AES-256-CBC',
  'aes-128-gcm': 'AES-128-GCM-16',
  'aes-256-gcm': 'AES-256-GCM-16',
  '3des-cbc': '3DES-CBC',
  'des-cbc': 'DES-CBC',
  none: 'None',
}

const INTEGRITY_MAP: Record<string, string> = {
  'hmac-sha256': 'HMAC-SHA2-256-128',
  'hmac-sha384': 'HMAC-SHA2-384',
  'hmac-sha1': 'HMAC-SHA1-96',
  'hmac-md5': 'HMAC-MD5',
  md5: 'MD5',
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
  'weak-ike-cipher': 'Weak Cipher',
  'weak-dh': 'Key Exchange',
  'weak-ike-dh': 'Key Exchange',
  'weak-integ': 'Weak Cipher',
  'weak-ike-integ': 'Weak Cipher',
  'no-pfs': 'PFS',
  'no-integ': 'Weak Cipher',
  'no-replay': 'Replay',
  'long-sa': 'Lifetime',
  ikev1: 'Protocol',
  'no-conf': 'Weak Cipher',
}

const FINDING_STRIDE: Record<string, StrideTag> = {
  'weak-cipher': 'Information Disclosure',
  'weak-ike-cipher': 'Information Disclosure',
  'weak-dh': 'Information Disclosure',
  'weak-ike-dh': 'Information Disclosure',
  'weak-integ': 'Tampering',
  'weak-ike-integ': 'Tampering',
  'no-pfs': 'Information Disclosure',
  'no-integ': 'Tampering',
  'no-replay': 'Tampering',
  'long-sa': 'Information Disclosure',
  ikev1: 'Spoofing',
  'no-conf': 'Information Disclosure',
}

/** Finding id -> control id, for LIKELY confidence lookup. */
const FINDING_CONTROL: Record<string, string> = {
  'weak-cipher': 'child-cipher',
  'no-conf': 'child-cipher',
  'weak-dh': 'dh-strength',
  'weak-ike-dh': 'ike-version',
  'weak-integ': 'integrity',
  'weak-ike-integ': 'ike-integrity',
  'weak-ike-cipher': 'ike-cipher',
  'no-pfs': 'pfs',
  'no-integ': 'integrity',
  'no-replay': 'replay',
  'long-sa': 'lifetime',
  ikev1: 'ike-version',
}

/** Category/stride for backend finding ids. */
export function findingTaxonomy(id: string): { category: ThreatCategory; stride: StrideTag } {
  const category = FINDING_CATEGORY[id] ?? 'Protocol'
  const stride = FINDING_STRIDE[id] ?? 'Information Disclosure'
  return { category, stride }
}

const num = (v: unknown, fallback: number): number =>
  typeof v === 'number' && Number.isFinite(v) ? v : fallback

const bool = (v: unknown, fallback: boolean): boolean =>
  typeof v === 'boolean' ? v : fallback

const NOT_OBSERVED_STATUSES: FieldStatus[] = ['UNKNOWN', 'NOT_OBSERVED', 'NOT_APPLICABLE']
const isUnobserved = (f: BackendField): boolean =>
  NOT_OBSERVED_STATUSES.includes(toStatus(f)) || f.value === 'unknown'

/** "not observed" note; components render the literal from status. */
function notObservedNote(field: string, f: BackendField): string {
  if (toStatus(f) === 'NOT_APPLICABLE') return `${field}: not applicable to this capture.`
  return `${field}: not observed in this capture — absence of evidence, not evidence of absence.`
}

interface MappedProtocol {
  protocol: AnalysisResult['protocol']
}

function paramFor<T>(value: T, f: BackendField, note?: string): Param<T> {
  return {
    value,
    provenance: toProvenance(f.source),
    confidence: f.confidence,
    status: toStatus(f),
    ...(note ? { note } : {}),
  }
}

/** Map backend SA objects onto the UI protocol block (status-aware). */
export function mapProtocol(
  ikeSa: Record<string, BackendField>,
  childSa: Record<string, BackendField>,
  meta: Record<string, BackendField>,
): MappedProtocol['protocol'] {
  const missing: BackendField = { value: 'unknown', source: 'none', confidence: 0, status: 'NOT_OBSERVED' }
  const ike = (k: string): BackendField => ikeSa[k] ?? missing
  const child = (k: string): BackendField => childSa[k] ?? missing
  const getMeta = (k: string): BackendField => meta[k] ?? missing
  const ikeVer = str(ike('version').value, '')
  const modeVal = str(child('mode').value, '')
  const protoVal = str(child('proto').value, '')

  const ikeVersion: AnalysisResult['protocol']['ikeVersion'] =
    ikeVer === 'ikev1' || ikeVer === 'ikev2'
      ? {
          value: ikeVer === 'ikev1' ? 'IKEv1' : 'IKEv2',
          provenance: toProvenance(ike('version').source),
          confidence: ike('version').confidence,
          status: toStatus(ike('version')),
          ...(isUnobserved(ike('version')) ? { note: notObservedNote('IKE version', ike('version')) } : {}),
        }
      : {
          value: 'IKEv2',
          provenance: 'observed',
          confidence: 0,
          status: 'NOT_OBSERVED',
          note: 'Not observed — no handshake captured.',
        };

  const modeDetail = child('mode').detail
  const modeNote = isUnobserved(child('mode'))
    ? notObservedNote('Encapsulation mode', child('mode'))
    : modeDetail?.decided_by === 'size-overhead-model'
      ? 'Mode from ESP size overhead (inner headers are encrypted).'
      : modeDetail?.decided_by === 'ah-next-header'
        ? `Mode from AH next header (${modeDetail.header_parse ?? 'n/a'}).`
        : undefined
  const mode: AnalysisResult['protocol']['mode'] =
    modeVal === 'tunnel' || modeVal === 'transport'
      ? {
          value: modeVal,
          provenance: toProvenance(child('mode').source),
          confidence: child('mode').confidence,
          status: toStatus(child('mode')),
          ...(modeNote ? { note: modeNote } : {}),
        }
      : {
          value: 'tunnel',
          provenance: 'observed',
          confidence: 0,
          status: toStatus(child('mode')),
          note: modeNote ?? 'Not observed.',
        };

  const ikeEnc = str(ike('enc_alg').value, '')
  const ikeAuth = str(ike('auth_alg').value, '')
  const ikePrf = str(ike('prf').value, '')
  const ikeDh = ike('dh_group').value
  const childEnc = str(child('enc_alg').value, '')
  const childAuth = str(child('auth_alg').value, '')
  const childPfs = child('pfs').value
  const isAhChild = protoVal === 'ah'

  return {
    ikeVersion,
    exchangeMode:
      ikeVer === 'ikev1'
        ? { value: 'Main Mode', provenance: 'inferred', confidence: 0.5, status: toStatus(ike('version')), note: 'Aggressive mode never observed; backend does not distinguish.' }
        : ikeVer === 'ikev2'
          ? {
              value: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)',
              provenance: toProvenance(ike('version').source),
              confidence: ike('version').confidence,
              status: toStatus(ike('version')),
            }
          : {
              value: 'IKEv2 (IKE_SA_INIT + IKE_AUTH)',
              provenance: 'observed',
              confidence: 0,
              status: 'NOT_OBSERVED',
              note: 'Not observed — no handshake captured.',
            },
    mode,
    ipVersion: (() => {
      const v = getMeta('ip_version')
      const n = num(v.value, 0)
      return n === 4 || n === 6
        ? paramFor(n === 4 ? 'IPv4' : 'IPv6', v, isUnobserved(v) ? notObservedNote('IP version', v) : undefined)
        : paramFor('IPv4', { ...v, confidence: 0 }, notObservedNote('IP version', v))
    })(),
    natTraversal: (() => {
      const f = getMeta('nat_t')
      return paramFor(bool(f.value, false), f, isUnobserved(f) ? notObservedNote('NAT-T', f) : undefined)
    })(),
    ike: {
      encryption: paramFor(
        isUnobserved(ike('enc_alg')) ? '' : (CIPHER_MAP[ikeEnc] ?? ikeEnc),
        ike('enc_alg'),
        isUnobserved(ike('enc_alg')) ? notObservedNote('IKE cipher (responder-selected proposal)', ike('enc_alg')) : undefined,
      ),
      integrity: paramFor(
        isUnobserved(ike('auth_alg')) ? '' : (INTEGRITY_MAP[ikeAuth] ?? ikeAuth),
        ike('auth_alg'),
        isUnobserved(ike('auth_alg')) ? notObservedNote('IKE integrity', ike('auth_alg')) : undefined,
      ),
      prf: paramFor(
        isUnobserved(ike('prf')) ? '' : (INTEGRITY_MAP[ikePrf] ?? ikePrf),
        ike('prf'),
        isUnobserved(ike('prf')) ? notObservedNote('IKE PRF', ike('prf')) : undefined,
      ),
      dhGroup: paramFor(
        typeof ikeDh === 'number' ? ikeDh : 0,
        ike('dh_group'),
        isUnobserved(ike('dh_group')) ? notObservedNote('IKE DH group (IKE SA scope only)', ike('dh_group')) : undefined,
      ),
      lifetimeSec: paramFor(null, missing, 'Lifetimes are never observed in short captures.'),
    },
    child: {
      encryption: paramFor(
        isAhChild ? 'None' : isUnobserved(child('enc_alg')) ? '' : (CIPHER_MAP[childEnc] ?? childEnc),
        child('enc_alg'),
        isAhChild
          ? 'AH provides integrity only (RFC 4302).'
          : isUnobserved(child('enc_alg'))
            ? notObservedNote('Child cipher (CHILD proposals travel encrypted)', child('enc_alg'))
            : 'Inferred from ESP size structure; never read from IKE proposals.',
      ),
      integrity: paramFor(
        isUnobserved(child('auth_alg')) ? '' : (INTEGRITY_MAP[childAuth] ?? childAuth),
        child('auth_alg'),
        isUnobserved(child('auth_alg')) ? notObservedNote('Child integrity', child('auth_alg')) : undefined,
      ),
      pfs: paramFor(
        childPfs === true,
        child('pfs'),
        typeof childPfs !== 'boolean' ? notObservedNote('PFS (needs a rekey on the wire)', child('pfs')) : undefined,
      ),
      pfsGroup: {
        value: null,
        provenance: toProvenance(child('pfs').source),
        confidence: child('pfs').confidence,
        status: toStatus(child('pfs')),
        note: 'The CHILD PFS group is never on the wire (rekeys are encrypted). See the IKE SA group above — it describes the IKE SA only.',
      },
      lifetimeSec: paramFor(null, missing, 'Lifetimes are never observed in short captures.'),
      replayProtection: paramFor(false, missing, 'Replay enforcement is not observable from packet captures.'),
      esn: paramFor(false, missing, 'Not observed in short captures.'),
    },
  }
}

/** Backend finding -> UI finding (1:1, taxonomy mapped + documented). */
export function mapFinding(f: BackendFinding, controls: BackendControl[] = []): Finding {
  const { category, stride } = findingTaxonomy(f.id)
  const verdict: FindingVerdict = f.verdict ?? 'CONFIRMED'
  const controlId = FINDING_CONTROL[f.id]
  const control = controls.find((c) => c.id === controlId)
  return {
    id: f.id,
    ruleId: f.id,
    severity: f.severity,
    category,
    stride,
    title: f.text,
    evidence: `likelihood ${f.likelihood}/5 x impact ${f.impact}/5 (backend assessment, rule ${control?.ruleVersion ?? 'n/a'})`,
    reference: 'Backend rubric docs/review/security-rubric.md',
    recommendation: f.solution,
    status: 'fail',
    verdict,
    confidence: control && control.source === 'inferred' ? control.confidence : null,
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

function headlineOf(a: BackendAssessment): AssessmentHeadline {
  return {
    postureScore: a.posture_score,
    coverage: a.coverage,
    scoreStatus: a.score_status,
    riskScore: a.risk_score,
    riskLevel: a.risk_level,
    ruleVersion: a.rule_version,
  }
}

/** Full backend response -> UI AnalysisResult (honest empties included). */
export function mapAnalyzeResponse(
  file: { name: string },
  resp: BackendAnalyzeResponse,
  analyzedAt = new Date().toISOString(),
): AnalysisResult {
  const detected = resp.detection?.ipsec_detected ?? true
  const f = resp.fields
  const meta = resp.metadata
  const metaNum = (k: string, fallback: number): number => {
    const v = meta[k]?.value
    return typeof v === 'number' && Number.isFinite(v) ? v : fallback
  }
  const tField = f.traffic_type ?? { value: 'unknown', source: 'model', confidence: 0 }
  const trafficLabel = str(tField.value, '')
  const tConf = typeof tField.confidence === 'number' ? tField.confidence : 0
  const headline = headlineOf(resp.assessment)
  const hasIke =
    str(resp.ike_sa?.version?.value, '') === 'ikev1' || str(resp.ike_sa?.version?.value, '') === 'ikev2'
  const protoVal = str(resp.child_sa?.proto?.value, '')
  return {
    id: `live-${Date.now().toString(36)}`,
    fileName: file.name,
    analyzedAt,
    source: 'upload',
    riskScore: headline.riskScore,
    overallConfidence: resp.ai_confidence,
    backendAssessment: {
      securityScore: headline.postureScore,
      riskScore: headline.riskScore,
      riskLevel: headline.riskLevel,
    },
    posture: headline,
    controls: resp.assessment.controls ?? [],
    detection: { ipsecDetected: detected },
    summary: {
      packets: metaNum('n_packets', 0),
      ikeHandshakes: hasIke ? 1 : 0,
      espStreams: protoVal === 'esp' ? 1 : 0,
      ahPackets: protoVal === 'ah' ? 1 : 0,
      durationSec: metaNum('duration_s', 0),
    },
    protocol: mapProtocol(resp.ike_sa ?? {}, resp.child_sa ?? {}, meta),
    trafficClasses: mapTrafficClasses(
      trafficLabel === 'unknown' || trafficLabel === '' ? undefined : trafficLabel,
      tConf,
    ),
    handshake: [],
    findings: (resp.assessment.findings ?? []).map((finding) => mapFinding(finding, resp.assessment.controls ?? [])),
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

/** LIKELY controls still needing evidence, for WITHHELD resolve-by lists. */
export function unknownsNeedingEvidence(controls: BackendControl[]): BackendControl[] {
  return controls.filter((c) => c.status === 'UNKNOWN' || c.status === 'LIKELY')
}

export type { ControlStatus }
