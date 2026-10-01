import type { FixtureId } from './fixtures/spec'
import { createSimulator } from './liveSim'
import type { Simulator } from './liveSim'

export interface LiveMessage {
  type: 'open' | 'packet' | 'handshake' | 'param' | 'classification' | 'stats' | 'finding' | 'close'
  seq: number
  ts: number
  payload: unknown
}

export interface LiveSocket {
  onmessage: ((m: LiveMessage) => void) | null
  onclose: (() => void) | null
  onerror: ((e: Error) => void) | null
  close(): void
}

/** Payload contracts, exported so the store can narrow `message.payload`. */
export interface ParamPayload {
  key: string
  provenance: 'observed' | 'inferred'
  confidence: number
}

export interface StatsPayload {
  elapsedSec: number
  counters: { packets: number; ike: number; esp: number; ah: number; other: number }
}

export interface ClassificationPayload {
  classes: { label: string; probability: number }[]
}

export const TICK_MS = 200

/**
 * Deterministic mock socket. The sequence depends only on the fixture seed and
 * the number of simulated ticks, so 1x and 4x produce identical streams.
 */
export class MockLiveSocket implements LiveSocket {
  onmessage: ((m: LiveMessage) => void) | null = null
  onclose: (() => void) | null = null
  onerror: ((e: Error) => void) | null = null

  private readonly simulator: Simulator
  private readonly speed: 1 | 4
  private readonly sourceId: FixtureId
  private timer: ReturnType<typeof setInterval> | null = null
  private seq = 0
  private started = false
  private closed = false

  constructor(sourceId: FixtureId, speed: 1 | 4) {
    this.sourceId = sourceId
    this.speed = speed
    this.simulator = createSimulator(sourceId)
    // Start on the next macrotask so the caller can attach handlers first.
    if (typeof setTimeout === 'function') {
      setTimeout(() => this.start(), 0)
    }
  }

  /** Emits `open` and starts the tick interval. */
  start(): void {
    if (this.started || this.closed) return
    this.started = true
    this.emit({ type: 'open', ts: Date.now(), payload: { sourceId: this.sourceId } })
    this.timer = setInterval(() => {
      try {
        const messages = this.simulator.tick()
        for (const message of messages) this.emit(message)
      } catch (error) {
        this.onerror?.(error instanceof Error ? error : new Error(String(error)))
        this.close()
      }
    }, TICK_MS / this.speed)
  }

  close(): void {
    if (this.closed) return
    this.closed = true
    if (this.timer !== null) {
      clearInterval(this.timer)
      this.timer = null
    }
    this.onclose?.()
  }

  private nextSeq(): number {
    this.seq += 1
    return this.seq
  }

  private emit(partial: Omit<LiveMessage, 'seq'>): void {
    if (this.closed) return
    const message: LiveMessage = { ...partial, seq: this.nextSeq() }
    this.onmessage?.(message)
  }
}
