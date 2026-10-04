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

/** Backend control on the wire (snake_case). mapControl converts it. */
export interface BackendControlWire {
  id: unknown
  rule_version: unknown
  title: unknown
  status: unknown
  weight: unknown
  points: unknown
  evidence: unknown
  explanation: unknown
  resolve_by: unknown
  remediation: unknown
  source: unknown
  confidence: unknown
}

export interface BackendAssessment {
  controls: BackendControlWire[]
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
  risk_band: 'LOW' | 'MODERATE' | 'HIGH' | null
}

export interface BackendDetection {
  ipsec_detected: boolean
  evidence?: { n_packets?: number; n_esp?: number; n_ah?: number; n_ike?: number } | null
}

export interface BackendAnalyzeResponse {
  fields: Record<string, BackendField>
  ike_sa: Record<string, BackendField>
  child_sa: Record<string, BackendField>
  detection: BackendDetection
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
export const FINDING_CONTROL: Record<string, string> = {
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

/** Exchange subtitle derived from ike_sa evidence — never hard-coded.
 * OBSERVED: the observed exchange + role + packet ref; NOT_OBSERVED:
 * "IKE handshake not observed (ESP only)". */
export function describeExchange(version: BackendField): Param<string> {
  const st = toStatus(version)
  const ev = (version.evidence ?? {}) as { exchange?: string; role?: string; packet?: number }
  if (st === 'OBSERVED' && typeof ev.exchange === 'string') {
    const role = typeof ev.role === 'string' ? ev.role.replace(/-/g, ' ') : 'observed'
    const pkt = typeof ev.packet === 'number' ? ` (packet ${ev.packet})` : ''
    const exch = ev.exchange === 'ike-sa-init' ? 'IKE_SA_INIT' : ev.exchange === 'ikev1-main-mode' ? 'Main Mode' : ev.exchange
    const ver = str(version.value, '') === 'ikev1' ? 'IKEv1' : 'IKEv2'
    return {
      value: `${ver} · ${exch} ${role}${pkt}`,
      provenance: toProvenance(version.source),
      confidence: version.confidence,
      status: st,
      source: version.source,
    }
  }
  if (st === 'NOT_APPLICABLE') {
    return { value: 'Not applicable (no IPsec)', provenance: 'observed', confidence: 1, status: st, source: version.source }
  }
  return {
    value: 'IKE handshake not observed (ESP only)',
    provenance: 'observed',
    confidence: 1,
    status: st,
    source: version.source,
    note: 'No handshake packets in this capture; CHILD fields are inferred or unknown.',
  }
}

interface MappedProtocol {
  protocol: AnalysisResult['protocol']
}

/** Handshake steps from observed SA evidence (packet index, exchange,
 * role). Only evidence with a packet index becomes a step — times and
 * sizes are unknown (0) and rendered as "packet N". Never invented. */
export function handshakeFromEvidence(
  ikeSa: Record<string, BackendField>,
  childSa: Record<string, BackendField>,
): import('@/types/analysis').HandshakeStep[] {
  const byPacket = new Map<number, { exchange: string; role: string }>()
  const consider = (f: BackendField | undefined): void => {
    if (!f || toStatus(f) !== 'OBSERVED') return
    const ev = (f.evidence ?? {}) as { exchange?: string; role?: string; packet?: number }
    if (typeof ev.packet !== 'number' || typeof ev.exchange !== 'string') return
    if (!byPacket.has(ev.packet)) byPacket.set(ev.packet, { exchange: ev.exchange, role: ev.role ?? 'observed' })
  }
  for (const k of ['version', 'enc_alg', 'auth_alg', 'prf', 'dh_group']) consider(ikeSa[k])
  for (const k of ['proto', 'mode']) consider(childSa[k])
  return [...byPacket.entries()]
    .sort((a, b) => a[0] - b[0])
    .map(([packet, { exchange, role }]) => {
      const name =
        exchange === 'ike-sa-init'
          ? role === 'responder-selected'
            ? 'IKE_SA_INIT response (selected suite)'
            : 'IKE_SA_INIT request (offered suite)'
          : exchange === 'ikev1-main-mode'
            ? 'IKEv1 Main Mode proposal'
            : exchange
      return {
        id: `hs-pkt-${packet}`,
        step: name,
        index: packet,
        timeSec: 0,
        direction: (role.includes('responder') ? 'responder->initiator' : role.includes('initiator') ? 'initiator->responder' : 'n/a') as
          | 'initiator->responder'
          | 'responder->initiator'
          | 'n/a',
        sizeBytes: 0,
        encrypted: false,
        details: { packet: String(packet), role: role.replace(/-/g, ' '), exchange },
      }
    })
}

function paramFor<T>(value: T, f: BackendField, note?: string): Param<T> {
  const detail = f.detail as { decided_by?: string } | null | undefined
  const decided = detail?.decided_by
  return {
    value,
    provenance: toProvenance(f.source),
    confidence: f.confidence,
    status: toStatus(f),
    source: f.source,
    ...(decided === 'size-overhead-model'
      ? { method: 'Size-overhead model' }
      : decided === 'ah-next-header'
        ? { method: 'AH next-header parse' }
        : {}),
    ...(note ? { note } : {}),
  }
}

/** Map backend SA objects onto the UI protocol block (status-aware). */
export function mapProtocol(
  ikeSa: Record<string, BackendField>,
  childSa: Record<string, BackendField>,
  flat: Record<string, BackendField> = {},
): MappedProtocol['protocol'] {
  const missing: BackendField = { value: 'unknown', source: 'none', confidence: 0, status: 'NOT_OBSERVED' }
  const ike = (k: string): BackendField => ikeSa[k] ?? missing
  const child = (k: string): BackendField => childSa[k] ?? missing
  /** Flat compat fields (ip_version, nat_t); absent keys mean an older
   * backend that never sent them — "not provided", not "not observed". */
  const getFlat = (k: string): BackendField | null =>
    Object.prototype.hasOwnProperty.call(flat, k) ? (flat[k] ?? missing) : null
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
          source: ike('version').source,
          ...(isUnobserved(ike('version')) ? { note: notObservedNote('IKE version', ike('version')) } : {}),
        }
      : {
          value: 'IKEv2',
          provenance: 'observed',
          confidence: 0,
          status: 'NOT_OBSERVED',
          source: 'none',
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
          source: child('mode').source,
          ...(modeDetail?.decided_by === 'size-overhead-model'
            ? { method: 'Size-overhead model' }
            : modeDetail?.decided_by === 'ah-next-header'
              ? { method: 'AH next-header parse' }
              : {}),
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
    exchangeMode: describeExchange(ike('version')),
    mode,
    ipVersion: (() => {
      const f = getFlat('ip_version')
      if (f === null) {
        return paramFor('IPv4', { ...missing, status: 'NOT_APPLICABLE' }, 'Not provided by the analysis API.')
      }
      const n = num(f.value, 0)
      return n === 4 || n === 6
        ? paramFor(n === 4 ? 'IPv4' : 'IPv6', f, isUnobserved(f) ? notObservedNote('IP version', f) : undefined)
        : paramFor('IPv4', { ...f, confidence: 0 }, notObservedNote('IP version', f))
    })(),
    natTraversal: (() => {
      const f = getFlat('nat_t')
      if (f === null) {
        return paramFor(false, { ...missing, status: 'NOT_APPLICABLE' }, 'Not provided by the analysis API.')
      }
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
    riskBand: a.risk_band,
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
  const controls = (resp.assessment.controls ?? []).map(mapControl)
  // Capture volume keeps its labels but carries detection.evidence
  // packet counts (n_ike, n_esp, n_ah) — never 1/0 presence markers.
  const evCounts = resp.detection?.evidence ?? null
  const totalPackets = num(evCounts?.n_packets, metaNum('n_packets', 0))
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
    controls: (resp.assessment.controls ?? []).map(mapControl),
    detection: {
      ipsecDetected: detected,
      nPackets: num(resp.detection?.evidence?.n_packets, metaNum('n_packets', 0)),
      nIke: num(resp.detection?.evidence?.n_ike, 0),
      nEsp: num(resp.detection?.evidence?.n_esp, 0),
      nAh: num(resp.detection?.evidence?.n_ah, 0),
    },
    summary: {
      packets: totalPackets,
      ikeHandshakes: num(evCounts?.n_ike, hasIke ? 1 : 0),
      espStreams: num(evCounts?.n_esp, protoVal === 'esp' ? 1 : 0),
      ahPackets: num(evCounts?.n_ah, protoVal === 'ah' ? 1 : 0),
      durationSec: metaNum('duration_s', 0),
    },
    protocol: mapProtocol(resp.ike_sa ?? {}, resp.child_sa ?? {}, resp.fields ?? {}),
    trafficClasses: mapTrafficClasses(
      trafficLabel === 'unknown' || trafficLabel === '' ? undefined : trafficLabel,
      tConf,
    ),
    handshake: handshakeFromEvidence(resp.ike_sa ?? {}, resp.child_sa ?? {}),
    findings: (resp.assessment.findings ?? []).map((finding) => mapFinding(finding, controls)),
    sas: [],
    packets: [],
    flowStats: {
      meanLen: metaNum('mean_bytes', 0),
      stdLen: null,
      meanIatMs: null,
      burstiness: null,
      upDownRatio: metaNum('direction_ratio', 0),
    },
    timeSeries: [],
    lengthHistogram: [],
    featureEvidence: [],
  }
}

/** Backend control (snake_case wire) -> UI control (camelCase). The mapper
 * passes rule_version and resolve_by through — never drops them. */
export function mapControl(c: BackendControlWire): BackendControl {
  const str = (v: unknown): string => (typeof v === 'string' ? v : '')
  const num = (v: unknown): number => (typeof v === 'number' && Number.isFinite(v) ? v : 0)
  const status = str(c.status)
  const source = str(c.source)
  return {
    id: str(c.id),
    ruleVersion: str(c.rule_version),
    title: str(c.title),
    status: (['PASS', 'FAIL', 'LIKELY', 'UNKNOWN', 'NOT_APPLICABLE'].includes(status) ? status : 'UNKNOWN') as BackendControl['status'],
    weight: num(c.weight),
    points: num(c.points),
    evidence: (c.evidence ?? null) as BackendControl['evidence'],
    explanation: str(c.explanation),
    resolveBy: typeof c.resolve_by === 'string' ? (c.resolve_by as string) : null,
    remediation: typeof c.remediation === 'string' ? (c.remediation as string) : null,
    source: (['observed', 'inferred', 'label', 'none'].includes(source) ? source : 'none') as BackendControl['source'],
    confidence: typeof c.confidence === 'number' ? c.confidence : 0,
  }
}

export type { ControlStatus }
