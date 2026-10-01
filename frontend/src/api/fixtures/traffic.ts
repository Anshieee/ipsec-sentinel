import type { TrafficLabel } from '@/types/analysis'
import { randInRange } from '@/lib/prng'
import type { FixtureSpec } from './spec'

export const TRAFFIC_LABELS: TrafficLabel[] = [
  'VoIP',
  'Video Streaming',
  'Web Browsing',
  'ICMP',
  'WhatsApp',
  'E-mail',
  'Other',
]

/**
 * Payload size distributions before ESP (spec 8.5).
 * The generator keeps a small amount of state so WhatsApp traffic arrives in bursts.
 */
export function createPayloadSampler(rng: () => number) {
  let burstRemaining = 0
  let burstBase = 0

  const payloadFor = (label: TrafficLabel): number => {
    switch (label) {
      case 'VoIP':
        // 60 to 200 uniform, 20 ms cadence
        return Math.round(randInRange(rng, 60, 200))
      case 'Video Streaming':
        // 1100 to 1380 (90 %) and 60 to 120 (10 %)
        return rng() < 0.9 ? Math.round(randInRange(rng, 1100, 1380)) : Math.round(randInRange(rng, 60, 120))
      case 'Web Browsing':
        // bimodal 60 to 100 (45 %) and 1300 to 1400 (55 %)
        return rng() < 0.45 ? Math.round(randInRange(rng, 60, 100)) : Math.round(randInRange(rng, 1300, 1400))
      case 'ICMP':
        return 84
      case 'WhatsApp': {
        // 90 to 620 with bursts of similarly sized messages
        if (burstRemaining > 0) {
          burstRemaining -= 1
          return Math.round(Math.min(620, Math.max(90, burstBase + randInRange(rng, -40, 40))))
        }
        if (rng() < 0.35) {
          burstBase = randInRange(rng, 320, 560)
          burstRemaining = 4 + Math.floor(rng() * 8)
          return Math.round(burstBase)
        }
        return Math.round(randInRange(rng, 90, 620))
      }
      case 'E-mail':
        return Math.round(randInRange(rng, 200, 1200))
      case 'Other':
      default:
        return Math.round(randInRange(rng, 60, 1400))
    }
  }

  return { payloadFor }
}

/** Dominant class draws 80 % of its ESP packets; the rest follow the class probabilities. */
export function pickTrafficLabel(rng: () => number, probabilities: { label: TrafficLabel; probability: number }[], dominant: TrafficLabel): TrafficLabel {
  if (rng() < 0.8) return dominant
  const draw = rng()
  let acc = 0
  for (const entry of probabilities) {
    acc += entry.probability
    if (draw <= acc) return entry.label
  }
  return dominant
}

/** Returns true when the label distribution was drawn for the given fixture. */
export function isDominant(label: TrafficLabel, spec: FixtureSpec): boolean {
  return label === spec.dominantClass
}
