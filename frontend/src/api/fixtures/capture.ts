import type { HandshakeStep, PacketRow, SecurityAssociation } from '@/types/analysis'
import { espConfig, espLength } from '@/lib/esp'
import { hexFromRng, mulberry32 } from '@/lib/prng'
import type { FixtureSpec } from './spec'
import { createPayloadSampler, pickTrafficLabel } from './traffic'

/** Sample cap from the data contract (max 2000 packets). */
export const MAX_SAMPLE = 2000

export interface ChildWindow {
  direction: 'out' | 'in'
  spiOut: string
  spiIn: string
  startSec: number
  endSec: number
  seqMin: number
  seqMax: number
}

export interface SaBundle {
  sas: SecurityAssociation[]
  windows: ChildWindow[]
  ikePackets: number
  ikeBytes: number
}

export interface CaptureBundle {
  sas: SaBundle
  packets: PacketRow[]
}

const SA_SHARE = { out: 0.55, in: 0.45 } as const

export function espParamsFor(spec: FixtureSpec) {
  return espConfig({
    encryption: spec.child.encryption.value,
    integrity: spec.child.integrity.value,
    outerIp: spec.ipVersion === 'IPv4' ? 20 : 40,
    mode: spec.mode.value,
  })
}

function ikeStepCount(handshake: HandshakeStep[]): { count: number; bytes: number; lastSec: number } {
  const ikeSteps = handshake.filter((s) => s.step !== 'ESP stream established')
  const bytes = ikeSteps.reduce((sum, step) => sum + step.sizeBytes, 0)
  const lastSec = ikeSteps.reduce((max, step) => Math.max(max, step.timeSec), 0)
  return { count: ikeSteps.length, bytes, lastSec }
}

/** IKE SA plus one CHILD SA per direction and rekey generation. */
export function buildSecurityAssociations(spec: FixtureSpec, handshake: HandshakeStep[]): SaBundle {
  const rng = mulberry32(spec.seed ^ 0x5a17)
  const ike = ikeStepCount(handshake)
  const targetTotal = Math.round(spec.packets * 0.99)
  const espPackets = Math.max(0, targetTotal - ike.count)

  const firstEspSec = handshake.find((s) => s.step === 'ESP stream established')?.timeSec ?? 0.071
  const boundaries: number[] = [firstEspSec, ...spec.rekeyTimes, spec.durationSec]

  interface RawWindow {
    direction: 'out' | 'in'
    startSec: number
    endSec: number
    spiOut: string
    spiIn: string
    packets: number
  }

  const raw: RawWindow[] = []
  for (let i = 0; i < boundaries.length - 1; i++) {
    const startSec = boundaries[i] ?? 0
    const endSec = boundaries[i + 1] ?? spec.durationSec
    for (const direction of ['out', 'in'] as const) {
      raw.push({
        direction,
        startSec,
        endSec,
        spiOut: hexFromRng(rng, 8),
        spiIn: hexFromRng(rng, 8),
        packets: 0,
      })
    }
  }

  const totalWindowSec = raw.reduce((sum, w) => sum + (w.endSec - w.startSec), 0) || 1
  const weights = raw.map((w) => ((w.endSec - w.startSec) / totalWindowSec) * SA_SHARE[w.direction])
  const weightSum = weights.reduce((sum, w) => sum + w, 0) || 1
  let allocated = 0
  raw.forEach((window, index) => {
    const share = weights[index] ?? 0
    window.packets = Math.round((espPackets * share) / weightSum)
    allocated += window.packets
  })
  // Reconcile rounding so the SA totals equal the target exactly.
  const drift = espPackets - allocated
  const last = raw[raw.length - 1]
  if (last) last.packets = Math.max(0, last.packets + drift)

  const cfg = espParamsFor(spec)
  const byteRng = mulberry32(spec.seed ^ 0xb17e5)
  const sampler = createPayloadSampler(byteRng)
  let payloadSum = 0
  const draws = 300
  for (let i = 0; i < draws; i++) payloadSum += sampler.payloadFor(spec.dominantClass)
  const avgLength = espLength(Math.round(payloadSum / draws), cfg)

  const windows: ChildWindow[] = raw.map((window) => ({
    direction: window.direction,
    spiOut: window.spiOut,
    spiIn: window.spiIn,
    startSec: window.startSec,
    endSec: window.endSec,
    seqMin: 1,
    seqMax: Math.max(1, window.packets),
  }))

  const sas: SecurityAssociation[] = [
    {
      id: 'sa-ike',
      kind: 'IKE SA',
      spiOut: hexFromRng(rng, 8),
      spiIn: hexFromRng(rng, 8),
      protocol: 'IKE',
      mode: 'n/a',
      encryption: spec.ike.encryption,
      integrity: spec.ike.integrity,
      packets: ike.count,
      bytes: ike.bytes,
      firstSeenSec: 0,
      lastSeenSec: ike.lastSec,
      seqMin: 0,
      seqMax: Math.max(0, ike.count - 1),
      replayGaps: 0,
    },
    ...raw.map((window, index): SecurityAssociation => {
      const child = windows[index]
      return {
        id: `sa-child-${index + 1}`,
        kind: 'CHILD SA',
        spiOut: window.spiOut,
        spiIn: window.spiIn,
        protocol: 'ESP',
        mode: spec.mode.value,
        encryption: spec.child.encryption.value,
        integrity: spec.child.integrity.value,
        packets: window.packets,
        bytes: window.packets * avgLength,
        firstSeenSec: window.startSec,
        lastSeenSec: window.endSec,
        seqMin: child?.seqMin ?? 1,
        seqMax: child?.seqMax ?? Math.max(1, window.packets),
        replayGaps: index === 0 ? spec.replayGaps : 0,
      }
    }),
  ]

  return { sas, windows, ikePackets: ike.count, ikeBytes: ike.bytes }
}

function ikeInfo(step: HandshakeStep): string {
  if (step.step.startsWith('IKE_SA_INIT')) {
    return `${step.step} (${step.direction === 'initiator->responder' ? 'initiator' : 'responder'})`
  }
  if (step.encrypted) return `${step.step} (encrypted)`
  return step.step
}

/** Human-readable `info` string for an IKE handshake packet row. */
export const ikeStepInfo = ikeInfo

function buildIkeRows(spec: FixtureSpec, handshake: HandshakeStep[]): PacketRow[] {
  return handshake
    .filter((step) => step.step !== 'ESP stream established')
    .map((step, index) => ({
      no: index + 1,
      timeSec: step.timeSec,
      src: step.direction === 'responder->initiator' ? spec.ips.dst : spec.ips.src,
      dst: step.direction === 'responder->initiator' ? spec.ips.src : spec.ips.dst,
      proto: 'IKE' as const,
      length: step.sizeBytes,
      info: ikeInfo(step),
    }))
}

/** Representative packet sample, sorted by time with the handshake first. */
export function buildPackets(spec: FixtureSpec, handshake: HandshakeStep[], bundle: SaBundle): PacketRow[] {
  const rng = mulberry32(spec.seed ^ 0x9a11ce)
  const ikeRows = buildIkeRows(spec, handshake)
  const firstEspSec = handshake.find((s) => s.step === 'ESP stream established')?.timeSec ?? 0.071
  const espRows = Math.max(0, Math.min(MAX_SAMPLE, spec.packets) - ikeRows.length)

  const cfg = espParamsFor(spec)
  const sampler = createPayloadSampler(rng)

  // Deterministic arrival times: random gap weights normalised over the capture window.
  const span = Math.max(0.001, spec.durationSec - firstEspSec)
  const gapWeights: number[] = []
  let gapTotal = 0
  for (let i = 0; i < espRows; i++) {
    const weight = 0.3 + rng()
    gapWeights.push(weight)
    gapTotal += weight
  }

  const rows: PacketRow[] = [...ikeRows]
  const seqBySpi = new Map<string, number>()
  let cursor = firstEspSec

  for (let i = 0; i < espRows; i++) {
    const weight = gapWeights[i] ?? 1
    cursor += (span * weight) / (gapTotal || 1)
    const timeSec = Math.min(spec.durationSec, cursor)
    const window = bundle.windows.find((w) => timeSec >= w.startSec && timeSec < w.endSec) ?? bundle.windows[0]
    const outbound = window ? (window.direction === 'out' ? rng() < 0.55 : rng() >= 0.55) : true
    const direction = outbound ? 'out' : 'in'
    const chosen =
      bundle.windows.find((w) => w.startSec <= timeSec && timeSec < w.endSec && w.direction === direction) ??
      bundle.windows.find((w) => w.startSec <= timeSec && timeSec < w.endSec) ??
      bundle.windows[0]
    const spi = chosen ? (outbound ? chosen.spiOut : chosen.spiIn) : '00000000'
    const previousSeq = seqBySpi.get(spi) ?? 0
    const baseSeq = chosen
      ? Math.round(
          chosen.seqMin +
            ((timeSec - chosen.startSec) / Math.max(1e-9, chosen.endSec - chosen.startSec)) *
              (chosen.seqMax - chosen.seqMin),
        )
      : 1
    const seq = Math.max(1, baseSeq, previousSeq + 1)
    seqBySpi.set(spi, seq)

    const label = pickTrafficLabel(rng, spec.trafficClasses, spec.dominantClass)
    const payload = sampler.payloadFor(label)
    rows.push({
      no: 0,
      timeSec,
      src: outbound ? spec.ips.src : spec.ips.dst,
      dst: outbound ? spec.ips.dst : spec.ips.src,
      proto: 'ESP',
      spi,
      seq,
      length: espLength(payload, cfg),
      info: `ESP (SPI 0x${spi}, seq ${seq})`,
    })
  }

  rows.sort((a, b) => a.timeSec - b.timeSec)
  return rows.map((row, index) => ({ ...row, no: index + 1 }))
}
