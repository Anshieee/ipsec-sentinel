import type {
  AnalysisResult,
  Finding,
  HandshakeStep,
  PacketRow,
  SecurityAssociation,
  TrafficLabel,
} from '@/types/analysis'
import { computeRiskScore } from '@/lib/risk'
import { FIXTURE_SPECS } from './fixtures/spec'
import { getFixture } from './fixtures'
import { FEATURE_EVIDENCE } from './fixtures/features'
import { buildFlowStats, buildLengthHistogram, buildTimeSeries } from './fixtures/stats'
import { protocolWithReveal } from './liveSim'
import type { RevealedMap } from './liveSim'
import type { FixtureId } from './fixtures/spec'

export interface LiveAnalysisInput {
  sourceId: FixtureId
  revealed: RevealedMap
  classes: { label: TrafficLabel; probability: number }[] | null
  handshake: HandshakeStep[]
  packets: PacketRow[]
  findings: Finding[]
  elapsedSec: number
  counters: { packets: number; ike: number; esp: number; ah: number; other: number }
  id: string
  fileName: string
  analyzedAt: string
  source: 'upload' | 'live'
}

const ikeHandshakeCount = (handshake: HandshakeStep[]): number =>
  handshake.filter((s) => s.step === 'IKE_SA_INIT request' || s.step === 'Phase 1 Aggressive Mode msg 1').length

function meanConfidence(revealed: RevealedMap): number {
  const values = Object.values(revealed).filter((value) => value < 1)
  if (values.length === 0) {
    const observed = Object.values(revealed)
    if (observed.length === 0) return 0
    return 1
  }
  return values.reduce((sum, v) => sum + v, 0) / values.length
}

/** Rebuilds the security associations from the packets seen during the capture. */
function liveSecurityAssociations(
  analysis: AnalysisResult['sas'],
  packets: PacketRow[],
): SecurityAssociation[] {
  return analysis.map((sa) => {
    if (sa.kind === 'IKE SA') {
      const rows = packets.filter((p) => p.proto === 'IKE')
      const bytes = rows.reduce((sum, p) => sum + p.length, 0)
      const times = rows.map((p) => p.timeSec)
      return {
        ...sa,
        packets: rows.length,
        bytes,
        firstSeenSec: times.length > 0 ? Math.min(...times) : 0,
        lastSeenSec: times.length > 0 ? Math.max(...times) : 0,
        seqMin: 0,
        seqMax: Math.max(0, rows.length - 1),
        replayGaps: 0,
      }
    }
    const rows = packets.filter((p) => p.proto === 'ESP' && (p.spi === sa.spiOut || p.spi === sa.spiIn))
    if (rows.length === 0) {
      return { ...sa, packets: 0, bytes: 0, firstSeenSec: 0, lastSeenSec: 0, seqMin: 0, seqMax: 0, replayGaps: 0 }
    }
    const seqs = rows.map((p) => p.seq ?? 0)
    const times = rows.map((p) => p.timeSec)
    return {
      ...sa,
      packets: rows.length,
      bytes: rows.reduce((sum, p) => sum + p.length, 0),
      firstSeenSec: Math.min(...times),
      lastSeenSec: Math.max(...times),
      seqMin: Math.min(...seqs),
      seqMax: Math.max(...seqs),
      replayGaps: 0,
    }
  })
}

/** Builds a complete `AnalysisResult` from the live working state. */
export function buildLiveAnalysis(input: LiveAnalysisInput): AnalysisResult {
  const spec = FIXTURE_SPECS[input.sourceId]
  const fixtureSas = getFixture(input.sourceId).sas
  const packets = [...input.packets]
    .sort((a, b) => a.timeSec - b.timeSec)
    .slice(0, 2000)
    .map((row, index) => ({ ...row, no: index + 1 }))

  const durationSec = Math.max(1, input.elapsedSec)
  const packetCount = Math.max(1, input.counters.packets)
  const statsSpec = { ...spec, durationSec, packets: packetCount }
  const classes = input.classes ?? spec.trafficClasses
  const protocol = protocolWithReveal(spec, input.revealed)
  return {
    id: input.id,
    fileName: input.fileName,
    analyzedAt: input.analyzedAt,
    source: input.source,
    riskScore: computeRiskScore(input.findings),
    overallConfidence: Number(meanConfidence(input.revealed).toFixed(3)),
    summary: {
      packets: input.counters.packets,
      ikeHandshakes: ikeHandshakeCount(input.handshake),
      espStreams: new Set(
        packets.filter((p) => p.proto === 'ESP').map((p) => p.spi).filter((spi): spi is string => Boolean(spi)),
      ).size,
      ahPackets: input.counters.ah,
      durationSec: input.elapsedSec,
    },
    protocol,
    trafficClasses: classes,
    handshake: input.handshake,
    findings: input.findings,
    sas: liveSecurityAssociations(fixtureSas, packets),
    packets,
    flowStats: buildFlowStats(statsSpec, packets),
    timeSeries: buildTimeSeries(statsSpec, packets),
    lengthHistogram: buildLengthHistogram(packets),
    featureEvidence: FEATURE_EVIDENCE,
  }
}
