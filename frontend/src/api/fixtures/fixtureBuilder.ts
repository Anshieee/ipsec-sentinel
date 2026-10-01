import type { AnalysisResult, Param, ProtocolInfo } from '@/types/analysis'
import { evaluate } from '@/lib/rules'
import { computeRiskScore } from '@/lib/risk'
import { dhLabel } from '@/lib/dh'
import { buildHandshake } from './handshake'
import { buildPackets, buildSecurityAssociations } from './capture'
import { buildFlowStats, buildLengthHistogram, buildTimeSeries } from './stats'
import { FEATURE_EVIDENCE } from './features'
import type { FixtureSpec } from './spec'

const observed = <T>(value: T): Param<T> => ({ value, provenance: 'observed', confidence: 1 })
const inferred = <T>(value: T, confidence: number): Param<T> => ({
  value,
  provenance: 'inferred',
  confidence,
})

export function buildProtocol(spec: FixtureSpec): ProtocolInfo {
  return {
    ikeVersion: observed(spec.ikeVersion),
    exchangeMode: observed(spec.exchangeMode),
    mode: inferred(spec.mode.value, spec.mode.confidence),
    ipVersion: observed(spec.ipVersion),
    natTraversal: observed(spec.natTraversal),
    ike: {
      encryption: observed(spec.ike.encryption),
      integrity: observed(spec.ike.integrity),
      prf: observed(spec.ike.prf),
      dhGroup: observed(spec.ike.dhGroup),
      lifetimeSec:
        spec.ike.lifetimeSec === null
          ? { value: null, provenance: 'observed', confidence: 1, note: 'Lifetime attribute not advertised in the capture.' }
          : observed(spec.ike.lifetimeSec),
    },
    child: {
      encryption: inferred(spec.child.encryption.value, spec.child.encryption.confidence),
      integrity: inferred(spec.child.integrity.value, spec.child.integrity.confidence),
      pfs: inferred(spec.child.pfs.value, spec.child.pfs.confidence),
      pfsGroup: inferred(spec.child.pfsGroup.value, spec.child.pfsGroup.confidence),
      lifetimeSec: inferred(spec.child.lifetimeSec.value, spec.child.lifetimeSec.confidence),
      replayProtection: inferred(spec.child.replayProtection.value, spec.child.replayProtection.confidence),
      esn: inferred(spec.child.esn.value, spec.child.esn.confidence),
    },
  }
}

/**
 * Deterministic fixture generation. Every field — parameters, handshake, SAs,
 * packets, statistics and findings — is derived from the spec tables so the
 * numbers stay mutually consistent. Findings come from the rule engine.
 */
export function buildFixture(spec: FixtureSpec): AnalysisResult {
  const protocol = buildProtocol(spec)
  const handshake = buildHandshake(spec)
  const evaluation = evaluate(protocol, spec.trafficClasses)
  const saBundle = buildSecurityAssociations(spec, handshake)
  const packets = buildPackets(spec, handshake, saBundle)

  return {
    id: `fixture-${spec.id}`,
    fileName: spec.fileName,
    analyzedAt: spec.analyzedAt,
    source: 'upload',
    riskScore: computeRiskScore(evaluation.findings),
    overallConfidence: spec.overallConfidence,
    summary: {
      packets: spec.packets,
      ikeHandshakes: spec.ikeHandshakes,
      espStreams: spec.espStreams,
      ahPackets: spec.ahPackets,
      durationSec: spec.durationSec,
    },
    protocol,
    trafficClasses: spec.trafficClasses,
    handshake,
    findings: evaluation.findings,
    sas: saBundle.sas,
    packets,
    flowStats: buildFlowStats(spec, packets),
    timeSeries: buildTimeSeries(spec, packets),
    lengthHistogram: buildLengthHistogram(packets),
    featureEvidence: FEATURE_EVIDENCE,
  }
}

/** One-line configuration summary used by the overview and reports. */
export function describeConfiguration(analysis: AnalysisResult): string {
  const p = analysis.protocol
  return [
    p.ikeVersion.value,
    `${p.mode.value} mode`,
    `IKE ${p.ike.encryption.value}`,
    `CHILD ${p.child.encryption.value}`,
    dhLabel(p.ike.dhGroup.value),
    analysis.summary.ahPackets > 0 ? 'AH' : 'ESP',
  ].join(' · ')
}
