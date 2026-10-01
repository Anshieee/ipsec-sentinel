import type { HandshakeStep, Param, PacketRow, ProtocolInfo, TrafficLabel } from '@/types/analysis'
import { evaluate } from '@/lib/rules'
import { mulberry32, randInt } from '@/lib/prng'
import { espLength } from '@/lib/esp'
import { createPayloadSampler, pickTrafficLabel } from './fixtures/traffic'
import { FIXTURE_SPECS } from './fixtures/spec'
import { espParamsFor, ikeStepInfo } from './fixtures/capture'
import { getFixture } from './fixtures'
import { TRAFFIC_LABELS } from './modelEval'
import type { FixtureId, FixtureSpec } from './fixtures/spec'
import type { ClassificationPayload, LiveMessage, ParamPayload, StatsPayload } from './live'

/** Parameter keys revealed as soon as the cleartext IKE_SA_INIT exchange is parsed. */
export const OBSERVED_PARAM_KEYS = [
  'ikeVersion',
  'exchangeMode',
  'ipVersion',
  'natTraversal',
  'ike.encryption',
  'ike.integrity',
  'ike.prf',
  'ike.dhGroup',
  'ike.lifetimeSec',
] as const

/** ESP packet count at which each inferred parameter is revealed (spec 9.2). */
export const REVEAL_SCHEDULE: { keys: string[]; espPackets: number }[] = [
  { keys: ['mode'], espPackets: 150 },
  { keys: ['child.encryption', 'child.integrity'], espPackets: 300 },
  { keys: ['child.replayProtection', 'child.esn'], espPackets: 600 },
  { keys: ['child.pfs', 'child.pfsGroup'], espPackets: 700 },
]

/** Simulated second at which the time-compressed rekey happens. */
export const REKEY_AT_SEC = 40

export type RevealedMap = Record<string, number>

const PENDING_NOTE = 'Pending…'

/**
 * Protocol parameters for the live working state. Revealed keys keep their
 * fixture provenance and ramping confidence; unrevealed keys are shown as
 * pending (confidence 0) so the rule engine treats them as unknown.
 */
export function protocolWithReveal(spec: FixtureSpec, revealed: RevealedMap): ProtocolInfo {
  const param = <T>(key: string, value: T, provenance: Param<T>['provenance'], finalConfidence: number): Param<T> => {
    const confidence = revealed[key]
    if (confidence === undefined) {
      return { value, provenance: 'inferred', confidence: 0, note: PENDING_NOTE }
    }
    return {
      value,
      provenance,
      confidence: provenance === 'observed' ? 1 : Math.min(finalConfidence, confidence),
    }
  }

  return {
    ikeVersion: param('ikeVersion', spec.ikeVersion, 'observed', 1),
    exchangeMode: param('exchangeMode', spec.exchangeMode, 'observed', 1),
    mode: param('mode', spec.mode.value, 'inferred', spec.mode.confidence),
    ipVersion: param('ipVersion', spec.ipVersion, 'observed', 1),
    natTraversal: param('natTraversal', spec.natTraversal, 'observed', 1),
    ike: {
      encryption: param('ike.encryption', spec.ike.encryption, 'observed', 1),
      integrity: param('ike.integrity', spec.ike.integrity, 'observed', 1),
      prf: param('ike.prf', spec.ike.prf, 'observed', 1),
      dhGroup: param('ike.dhGroup', spec.ike.dhGroup, 'observed', 1),
      lifetimeSec: param('ike.lifetimeSec', spec.ike.lifetimeSec, 'observed', 1),
    },
    child: {
      encryption: param('child.encryption', spec.child.encryption.value, 'inferred', spec.child.encryption.confidence),
      integrity: param('child.integrity', spec.child.integrity.value, 'inferred', spec.child.integrity.confidence),
      pfs: param('child.pfs', spec.child.pfs.value, 'inferred', spec.child.pfs.confidence),
      pfsGroup: param('child.pfsGroup', spec.child.pfsGroup.value, 'inferred', spec.child.pfsGroup.confidence),
      lifetimeSec: param('child.lifetimeSec', spec.child.lifetimeSec.value, 'inferred', spec.child.lifetimeSec.confidence),
      replayProtection: param(
        'child.replayProtection',
        spec.child.replayProtection.value,
        'inferred',
        spec.child.replayProtection.confidence,
      ),
      esn: param('child.esn', spec.child.esn.value, 'inferred', spec.child.esn.confidence),
    },
  }
}

/** Confidence ramp: `final * n / (n + 300)`. */
export function rampConfidence(finalConfidence: number, espPackets: number): number {
  return Number((finalConfidence * (espPackets / (espPackets + 300))).toFixed(4))
}

const uniformClasses = (): { label: TrafficLabel; probability: number }[] =>
  TRAFFIC_LABELS.map((label) => ({ label, probability: 1 / TRAFFIC_LABELS.length }))

const normalize = (values: number[]): number[] => {
  const total = values.reduce((sum, v) => sum + v, 0)
  if (total <= 0) return values.map(() => 1 / values.length)
  return values.map((v) => Math.max(0, v) / total)
}

interface ScheduledStep {
  step: HandshakeStep
  time: number
}

export interface Simulator {
  tick(): LiveMessage[]
}

/** Deterministic live-capture simulator for one fixture. */
export function createSimulator(sourceId: FixtureId): Simulator {
  const spec = FIXTURE_SPECS[sourceId]
  const fixture = getFixture(sourceId)
  const rng = mulberry32((spec.seed ^ 0x11ce) >>> 0)
  const sampler = createPayloadSampler(rng)
  const cfg = espParamsFor(spec)
  const childSas = fixture.sas.filter((sa) => sa.kind === 'CHILD SA')

  const rekeySteps = fixture.handshake.filter((s) => s.id.startsWith('hs-rekey'))
  const schedule: ScheduledStep[] = fixture.handshake.map((step) => {
    const order = rekeySteps.findIndex((s) => s.id === step.id)
    return { step, time: order >= 0 ? REKEY_AT_SEC + order * 0.02 : step.index * 0.25 }
  })

  const revealed: RevealedMap = {}
  let classes = uniformClasses()
  let tickCount = 0
  let seq = 0
  let packetNo = 0
  let espCount = 0
  let ikeCount = 0
  let cursor = 0
  let lastStatsSecond = -1
  let lastClassSecond = -1
  let pendingWork = false
  const emittedFindings = new Set<string>()
  const spiSeq = new Map<string, number>()

  const message = (type: LiveMessage['type'], t: number, payload: unknown): LiveMessage => {
    seq += 1
    return { type, seq, ts: Math.round(t * 1000), payload }
  }

  const revealObserved = (t: number, out: LiveMessage[]): void => {
    for (const key of OBSERVED_PARAM_KEYS) {
      if (revealed[key] !== undefined) continue
      revealed[key] = 1
      const payload: ParamPayload = { key, provenance: 'observed', confidence: 1 }
      out.push(message('param', t, payload))
    }
    pendingWork = true
  }

  const revealInferred = (t: number, keys: string[], out: LiveMessage[]): void => {
    for (const key of keys) {
      if (revealed[key] !== undefined) continue
      const finalConfidence = finalConfidenceFor(spec, key)
      if (finalConfidence === null) continue
      revealed[key] = rampConfidence(finalConfidence, espCount)
      const payload: ParamPayload = { key, provenance: 'inferred', confidence: revealed[key] ?? 0 }
      out.push(message('param', t, payload))
    }
    pendingWork = true
  }

  const refreshConfidences = (t: number, out: LiveMessage[]): void => {
    for (const [key, previous] of Object.entries(revealed)) {
      const finalConfidence = finalConfidenceFor(spec, key)
      if (finalConfidence === null || finalConfidence >= 1) continue
      const next = rampConfidence(finalConfidence, espCount)
      if (Math.abs(next - previous) < 0.001) continue
      revealed[key] = next
      const payload: ParamPayload = { key, provenance: 'inferred', confidence: next }
      out.push(message('param', t, payload))
      pendingWork = true
    }
  }

  const emitFindings = (t: number, out: LiveMessage[]): void => {
    if (!pendingWork) return
    pendingWork = false
    const protocol = protocolWithReveal(spec, revealed)
    const evaluation = evaluate(protocol, classes)
    for (const finding of evaluation.findings) {
      if (emittedFindings.has(finding.ruleId)) continue
      emittedFindings.add(finding.ruleId)
      out.push(message('finding', t, finding))
    }
  }

  const makeIkePacket = (step: HandshakeStep): PacketRow => {
    packetNo += 1
    ikeCount += 1
    const outbound = step.direction !== 'responder->initiator'
    return {
      no: packetNo,
      timeSec: step.timeSec,
      src: outbound ? spec.ips.src : spec.ips.dst,
      dst: outbound ? spec.ips.dst : spec.ips.src,
      proto: 'IKE',
      length: step.sizeBytes,
      info: ikeStepInfo(step),
    }
  }

  const makeEspPacket = (t: number): PacketRow => {
    packetNo += 1
    espCount += 1
    const outbound = rng() < 0.55
    const active =
      childSas.find((sa) => t >= sa.firstSeenSec && t < sa.lastSeenSec) ??
      childSas.find((sa) => t >= sa.firstSeenSec) ??
      childSas[0]
    const spi = active ? (outbound ? active.spiOut : active.spiIn) : '00000000'
    const nextSeq = (spiSeq.get(spi) ?? 0) + 1
    spiSeq.set(spi, nextSeq)
    const label = pickTrafficLabel(rng, spec.trafficClasses, spec.dominantClass)
    const payload = sampler.payloadFor(label)
    return {
      no: packetNo,
      timeSec: t,
      src: outbound ? spec.ips.src : spec.ips.dst,
      dst: outbound ? spec.ips.dst : spec.ips.src,
      proto: 'ESP',
      spi,
      seq: nextSeq,
      length: espLength(payload, cfg),
      info: `ESP (SPI 0x${spi}, seq ${nextSeq})`,
    }
  }

  const emitStats = (t: number, out: LiveMessage[]): void => {
    const payload: StatsPayload = {
      elapsedSec: Number(t.toFixed(1)),
      counters: {
        packets: ikeCount + espCount,
        ike: ikeCount,
        esp: espCount,
        ah: 0,
        other: 0,
      },
    }
    out.push(message('stats', t, payload))
    refreshConfidences(t, out)
  }

  const emitClassification = (t: number, out: LiveMessage[]): void => {
    const target = new Map(spec.trafficClasses.map((entry) => [entry.label, entry.probability]))
    const blended = normalize(
      classes.map((entry) => 0.8 * entry.probability + 0.2 * (target.get(entry.label) ?? 0) + (rng() - 0.5) * 0.04),
    )
    classes = TRAFFIC_LABELS.map((label, index) => ({ label, probability: blended[index] ?? 0 }))
    const payload: ClassificationPayload = {
      classes: classes.map((entry) => ({ label: entry.label, probability: entry.probability })),
    }
    out.push(message('classification', t, payload))
    pendingWork = true
  }

  return {
    tick(): LiveMessage[] {
      tickCount += 1
      const t = Number((tickCount * 0.2).toFixed(3))
      const out: LiveMessage[] = []

      // Handshake steps scheduled by compressed time.
      while (cursor < schedule.length) {
        const entry = schedule[cursor]
        if (!entry || entry.time > t) break
        cursor += 1
        out.push(message('handshake', entry.time, entry.step))
        if (entry.step.step !== 'ESP stream established') {
          out.push(message('packet', entry.time, makeIkePacket(entry.step)))
        }
        if (entry.step.step === 'IKE_SA_INIT response' || entry.step.step === 'Phase 1 Aggressive Mode msg 3') {
          revealObserved(t, out)
        }
        if (entry.step.id.startsWith('hs-rekey')) {
          revealInferred(t, ['child.lifetimeSec'], out)
        }
      }

      // ESP traffic from t = 1.2 s: 6 to 14 packets per tick.
      if (t >= 1.2) {
        const count = randInt(rng, 6, 14)
        for (let i = 0; i < count; i++) out.push(message('packet', t, makeEspPacket(t)))
      }

      for (const item of REVEAL_SCHEDULE) {
        if (espCount >= item.espPackets) revealInferred(t, item.keys, out)
      }

      const second = Math.floor(t)
      if (second >= 1 && second !== lastStatsSecond) {
        lastStatsSecond = second
        emitStats(t, out)
      }
      if (espCount >= 800 && second !== lastClassSecond) {
        lastClassSecond = second
        emitClassification(t, out)
      }

      emitFindings(t, out)
      return out
    },
  }
}

/** Final confidence of an inferred parameter for the fixture, or `null` when the key is observed. */
function finalConfidenceFor(spec: FixtureSpec, key: string): number | null {
  switch (key) {
    case 'mode':
      return spec.mode.confidence
    case 'child.encryption':
      return spec.child.encryption.confidence
    case 'child.integrity':
      return spec.child.integrity.confidence
    case 'child.pfs':
      return spec.child.pfs.confidence
    case 'child.pfsGroup':
      return spec.child.pfsGroup.confidence
    case 'child.lifetimeSec':
      return spec.child.lifetimeSec.confidence
    case 'child.replayProtection':
      return spec.child.replayProtection.confidence
    case 'child.esn':
      return spec.child.esn.confidence
    default:
      return null
  }
}
