import type { LogLevel, LogLine } from '@/types/misc'
import { mulberry32 } from '@/lib/prng'
import { MODEL_REGISTRY } from './models'

const BASE_TS = Date.parse('2026-09-30T09:00:00.000Z')
const INTERVAL_MS = 1200
const LOG_SEED = 0x1061
const MODEL_NAMES = MODEL_REGISTRY.map((m) => m.name)

/** Initial buffer size for the log viewer (spec 10.6). */
export const INITIAL_LOG_LINES = 200

interface Template {
  source: string
  level: LogLevel
  build: (rng: () => number) => string
}

const round = (rng: () => number, min: number, max: number, decimals = 1): number =>
  Number((min + rng() * (max - min)).toFixed(decimals))

const pick = <T>(rng: () => number, items: readonly T[]): T => {
  const item = items[Math.floor(rng() * items.length) % items.length]
  return (item ?? items[0]) as T
}

const hex4 = (rng: () => number): string =>
  Math.floor(rng() * 0xffff)
    .toString(16)
    .padStart(4, '0')

const CIPHERS = ['AES-128-CBC', 'AES-256-GCM-16', '3DES-CBC', 'AES-128-GCM-16'] as const
const CLASSES = ['VoIP', 'Video Streaming', 'Web Browsing', 'ICMP', 'WhatsApp', 'E-mail', 'Other'] as const

const TEMPLATES: Template[] = [
  { source: 'traffic-cnn1d', level: 'INFO', build: (r) => `Inference batch=32 latency=${round(r, 10.4, 13.2)}ms` },
  { source: 'traffic-cnn1d', level: 'DEBUG', build: () => 'Feature window size=512 stride=64 normalised=per-flow' },
  {
    source: 'traffic-cnn1d',
    level: 'INFO',
    build: (r) => `Classified 128 samples as ${pick(r, CLASSES)} (p=${round(r, 0.71, 0.97, 2)})`,
  },
  {
    source: 'cipher-fingerprint-gbm',
    level: 'WARN',
    build: (r) => `Low margin (${round(r, 0.05, 0.09, 2)}) between AES-CBC and 3DES-CBC`,
  },
  {
    source: 'cipher-fingerprint-gbm',
    level: 'INFO',
    build: (r) => `ESP stream spi=0x${hex4(r)}${hex4(r)} classified as ${pick(r, CIPHERS)} (p=${round(r, 0.88, 0.99, 2)})`,
  },
  { source: 'cipher-fingerprint-gbm', level: 'DEBUG', build: (r) => `Margin calibration refreshed samples=${512 + Math.floor(r() * 2048)}` },
  {
    source: 'mode-pfs-replay-gbm',
    level: 'INFO',
    build: (r) => `mode=tunnel pfs=${r() < 0.5 ? 'on' : 'off'} replay=${r() < 0.5 ? 'on' : 'off'} latency=${round(r, 2.1, 3.9)}ms`,
  },
  { source: 'mode-pfs-replay-gbm', level: 'INFO', build: (r) => `PFS detected p=${round(r, 0.86, 0.95, 2)} for spi=0x${hex4(r)}${hex4(r)}` },
  { source: 'mode-pfs-replay-gbm', level: 'WARN', build: (r) => `Confidence below threshold (${round(r, 0.51, 0.59, 2)}) for ESN inference` },
  {
    source: 'traffic-transformer',
    level: 'INFO',
    build: (r) => `Ensemble vote weight=${round(r, 0.32, 0.58, 2)} label=${pick(r, CLASSES)}`,
  },
  { source: 'traffic-transformer', level: 'INFO', build: (r) => `Attention over 256 steps latency=${round(r, 22.1, 27.4)}ms` },
  {
    source: 'ike-parser-rules',
    level: 'INFO',
    build: (r) => `Parsed IKE_SA_INIT proposal: ${pick(r, CIPHERS)} / ${r() < 0.5 ? 'PRF_HMAC_SHA2_384' : 'PRF_HMAC_SHA1'}`,
  },
  {
    source: 'ike-parser-rules',
    level: 'INFO',
    build: (r) => `Rule R0${1 + Math.floor(r() * 9)} evaluated: ${r() < 0.4 ? 'fail' : r() < 0.9 ? 'pass' : 'unknown'}`,
  },
  { source: 'ike-parser-rules', level: 'DEBUG', build: () => 'Decoded payload chain: SA, KE, Nonce, NAT-D' },
  { source: 'ingest', level: 'INFO', build: (r) => `Capture chunk ${1 + Math.floor(r() * 96)} parsed (${2048 + Math.floor(r() * 6144)} packets)` },
  { source: 'ingest', level: 'ERROR', build: (r) => `Malformed ESP header at packet ${1000 + Math.floor(r() * 40000)}; stream skipped` },
  { source: 'ingest', level: 'WARN', build: (r) => `Truncated capture: last ${8 + Math.floor(r() * 512)} bytes ignored` },
  { source: 'engine', level: 'INFO', build: (r) => `Risk score updated ${Math.floor(r() * 60)} -> ${Math.floor(r() * 60)}` },
  { source: 'engine', level: 'INFO', build: (r) => `Live capture source=${pick(r, ['A', 'B', 'C'])} speed=${r() < 0.5 ? 1 : 4}x started` },
  { source: 'engine', level: 'DEBUG', build: (r) => `Working analysis rebuilt in ${round(r, 4, 22)}ms` },
]

/** Pure, index-driven log line so the stream stays deterministic. */
export function logAt(index: number): LogLine {
  const rng = mulberry32((LOG_SEED + Math.imul(index, 2654435761)) >>> 0)
  const template = TEMPLATES[Math.floor(rng() * TEMPLATES.length) % TEMPLATES.length] ?? TEMPLATES[0]
  const chosen = template as Template
  return {
    id: `log-${index}`,
    ts: new Date(BASE_TS + index * INTERVAL_MS).toISOString(),
    level: chosen.level,
    source: chosen.source,
    message: chosen.build(rng),
  }
}

export function logsFrom(index: number, count: number): LogLine[] {
  const lines: LogLine[] = []
  for (let i = 0; i < count; i++) lines.push(logAt(Math.max(0, index) + i))
  return lines
}

export function logIndexById(id: string | undefined): number | undefined {
  if (!id) return undefined
  const match = /^log-(\d+)$/.exec(id)
  if (!match || !match[1]) return undefined
  return Number(match[1])
}

/** Returns the initial 200 lines, or the lines produced after `sinceId`. */
export function nextLogs(sinceId?: string): LogLine[] {
  const index = logIndexById(sinceId)
  if (index === undefined) return logsFrom(0, INITIAL_LOG_LINES)
  return logsFrom(index + 1, 1)
}

export { MODEL_NAMES }
