import type { AnalysisResult, PacketRow } from '@/types/analysis'
import type { FixtureSpec } from './spec'

type FlowStats = AnalysisResult['flowStats']
type TimeSeries = AnalysisResult['timeSeries']
type Histogram = AnalysisResult['lengthHistogram']

export const TIME_BUCKET_SEC = 10
export const HISTOGRAM_BINS = 12
export const HISTOGRAM_MAX = 1500

function mean(values: number[]): number {
  if (values.length === 0) return 0
  return values.reduce((sum, v) => sum + v, 0) / values.length
}

function stdDev(values: number[], avg: number): number {
  if (values.length === 0) return 0
  const variance = values.reduce((sum, v) => sum + (v - avg) ** 2, 0) / values.length
  return Math.sqrt(variance)
}

/** Flow statistics derived from the generated sample (spec 8.7). */
export function buildFlowStats(spec: FixtureSpec, packets: PacketRow[]): FlowStats {
  const lengths = packets.map((p) => p.length)
  const avgLen = mean(lengths)
  const times = packets.map((p) => p.timeSec)
  const gapsMs: number[] = []
  for (let i = 1; i < times.length; i++) {
    const previous = times[i - 1] ?? 0
    const current = times[i] ?? 0
    gapsMs.push(Math.max(0, (current - previous) * 1000))
  }
  const avgGap = mean(gapsMs)
  const gapStd = stdDev(gapsMs, avgGap)
  const outbound = packets.filter((p) => p.src === spec.ips.src).reduce((sum, p) => sum + p.length, 0)
  const inbound = packets.filter((p) => p.src !== spec.ips.src).reduce((sum, p) => sum + p.length, 0)

  return {
    meanLen: Number(avgLen.toFixed(2)),
    stdLen: Number(stdDev(lengths, avgLen).toFixed(2)),
    // Mean inter-arrival time of the full capture, not of the sparse sample.
    meanIatMs: Number(((spec.durationSec / Math.max(1, spec.packets)) * 1000).toFixed(3)),
    burstiness: avgGap > 0 ? Number((gapStd / avgGap).toFixed(3)) : 0,
    upDownRatio: inbound > 0 ? Number((outbound / inbound).toFixed(3)) : 0,
  }
}

/** Packets per 10 s bucket, scaled from the sample to the full capture. */
export function buildTimeSeries(spec: FixtureSpec, packets: PacketRow[]): TimeSeries {
  const bucketCount = Math.max(1, Math.ceil(spec.durationSec / TIME_BUCKET_SEC))
  const buckets = Array.from({ length: bucketCount }, (_, i) => ({
    t: i * TIME_BUCKET_SEC,
    ike: 0,
    esp: 0,
    other: 0,
  }))
  for (const packet of packets) {
    const index = Math.min(bucketCount - 1, Math.max(0, Math.floor(packet.timeSec / TIME_BUCKET_SEC)))
    const bucket = buckets[index]
    if (!bucket) continue
    if (packet.proto === 'IKE') bucket.ike += 1
    else if (packet.proto === 'ESP') bucket.esp += 1
    else bucket.other += 1
  }
  const scale = spec.packets / Math.max(1, packets.length)
  return buckets.map((bucket) => ({
    t: bucket.t,
    ike: Math.round(bucket.ike * scale),
    esp: Math.round(bucket.esp * scale),
    other: Math.round(bucket.other * scale),
  }))
}

/** 12 equal-width bins from 0 to 1,500 bytes over ESP packet lengths. */
export function buildLengthHistogram(packets: PacketRow[]): Histogram {
  const width = HISTOGRAM_MAX / HISTOGRAM_BINS
  const bins = Array.from({ length: HISTOGRAM_BINS }, (_, i) => ({
    bin: `${Math.round(i * width)}-${Math.round((i + 1) * width)}`,
    count: 0,
  }))
  for (const packet of packets) {
    if (packet.proto !== 'ESP') continue
    const index = Math.min(HISTOGRAM_BINS - 1, Math.max(0, Math.floor(packet.length / width)))
    const bin = bins[index]
    if (bin) bin.count += 1
  }
  return bins
}
