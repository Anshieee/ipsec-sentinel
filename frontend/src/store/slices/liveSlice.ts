import type { AnalysisResult, Finding, HandshakeStep, PacketRow, TrafficLabel } from '@/types/analysis'
import { getActiveApi } from '@/api/client'
import { buildLiveAnalysis } from '@/api/liveAnalysis'
import { fileStampSeconds } from '@/lib/format'
import { TRAFFIC_LABELS } from '@/api/modelEval'
import type { ClassificationPayload, LiveMessage, LiveSocket, ParamPayload, StatsPayload } from '@/api/live'
import type { RevealedMap } from '@/api/liveSim'
import type { SliceCreator } from '../types'
import type { UploadState } from './uploadSlice'

export type LiveStatus = 'idle' | 'connecting' | 'capturing' | 'stopping'

export interface LiveCounters {
  packets: number
  ike: number
  esp: number
  ah: number
  other: number
}

const EMPTY_COUNTERS: LiveCounters = { packets: 0, ike: 0, esp: 0, ah: 0, other: 0 }

/** Ring buffer size for the live packet sample (spec 5). */
export const LIVE_RING_SIZE = 200

/** Spec 5 `LiveState`, extended with the working analysis rebuilt per batch. */
export interface LiveState {
  status: LiveStatus
  sourceId: 'A' | 'B' | 'C'
  speed: 1 | 4
  elapsedSec: number
  counters: LiveCounters
  /** Ring buffer, most recent 200 packets. */
  recent: PacketRow[]
  handshake: HandshakeStep[]
  findings: Finding[]
  revealed: RevealedMap
  classes: { label: TrafficLabel; probability: number }[] | null
  /** Rebuilt from every message batch while capturing. */
  working: AnalysisResult | null
}

export interface LiveSlice {
  live: LiveState
  start: (sourceId?: 'A' | 'B' | 'C', speed?: 1 | 4) => void
  stop: () => void
  reset: () => void
  /** Changes the simulated source/speed used by the next capture. */
  setLiveOptions: (options: { sourceId?: 'A' | 'B' | 'C'; speed?: 1 | 4 }) => void
}

const IDLE_LIVE: LiveState = {
  status: 'idle',
  sourceId: 'A',
  speed: 1,
  elapsedSec: 0,
  counters: { ...EMPTY_COUNTERS },
  recent: [],
  handshake: [],
  findings: [],
  revealed: {},
  classes: null,
  working: null,
}

let activeSocket: LiveSocket | null = null
let rebuildScheduled = false

const uploadBusy = (status: UploadState['status']): boolean =>
  status === 'uploading' || status === 'parsing' || status === 'inferring'

export const createLiveSlice: SliceCreator<LiveSlice> = (set, get) => {
  const patchLive = (patch: Partial<LiveState>): void =>
    set((state) => ({ live: { ...state.live, ...patch } }))

  const scheduleRebuild = (): void => {
    if (rebuildScheduled) return
    rebuildScheduled = true
    queueMicrotask(() => {
      rebuildScheduled = false
      const state = get().live
      if (state.status !== 'capturing' && state.status !== 'stopping') return
      patchLive({
        working: buildLiveAnalysis({
          sourceId: state.sourceId,
          revealed: state.revealed,
          classes: state.classes,
          handshake: state.handshake,
          packets: state.recent,
          findings: state.findings,
          elapsedSec: state.elapsedSec,
          counters: state.counters,
          id: `live-working-${state.sourceId}`,
          fileName: `live-capture-${fileStampSeconds()}`,
          analyzedAt: new Date().toISOString(),
          source: 'live',
        }),
      })
    })
  }

  const finalizeCapture = (): void => {
    const state = get().live
    const captured = state.handshake.length > 0 || state.recent.length > 0 || state.findings.length > 0
    if (captured) {
      const analysis = buildLiveAnalysis({
        sourceId: state.sourceId,
        revealed: state.revealed,
        classes: state.classes,
        handshake: state.handshake,
        packets: state.recent,
        findings: state.findings,
        elapsedSec: state.elapsedSec,
        counters: state.counters,
        id: `live-${Date.now().toString(36)}`,
        fileName: `live-capture-${fileStampSeconds()}`,
        analyzedAt: new Date().toISOString(),
        source: 'live',
      })
      get().setAnalysis(analysis)
      get().notify({ severity: 'success', message: 'Live capture stopped. Analysis ready.' })
    }
    set((state) => ({ live: { ...IDLE_LIVE, sourceId: state.live.sourceId, speed: state.live.speed } }))
  }

  const handleClose = (): void => {
    if (get().live.status === 'idle') return
    finalizeCapture()
  }

  const handleMessage = (message: LiveMessage): void => {
    switch (message.type) {
      case 'open':
        patchLive({ status: 'capturing' })
        get().notify({ severity: 'info', message: 'Live capture started.' })
        scheduleRebuild()
        break
      case 'packet': {
        const packet = message.payload as PacketRow
        set((state) => ({ live: { ...state.live, recent: [...state.live.recent, packet].slice(-LIVE_RING_SIZE) } }))
        scheduleRebuild()
        break
      }
      case 'handshake': {
        const step = message.payload as HandshakeStep
        set((state) => ({ live: { ...state.live, handshake: [...state.live.handshake, step] } }))
        if (step.id.startsWith('hs-rekey')) {
          get().notify({ severity: 'info', message: 'Rekey observed.' })
        }
        scheduleRebuild()
        break
      }
      case 'param': {
        const payload = message.payload as ParamPayload
        set((state) => ({
          live: { ...state.live, revealed: { ...state.live.revealed, [payload.key]: payload.confidence } },
        }))
        scheduleRebuild()
        break
      }
      case 'classification': {
        const payload = message.payload as ClassificationPayload
        const classes = payload.classes
          .filter((entry) => (TRAFFIC_LABELS as string[]).includes(entry.label))
          .map((entry) => ({ label: entry.label as TrafficLabel, probability: entry.probability }))
        patchLive({ classes })
        scheduleRebuild()
        break
      }
      case 'stats': {
        const payload = message.payload as StatsPayload
        patchLive({ counters: payload.counters, elapsedSec: payload.elapsedSec })
        scheduleRebuild()
        break
      }
      case 'finding': {
        const finding = message.payload as Finding
        set((state) =>
          state.live.findings.some((f) => f.ruleId === finding.ruleId)
            ? state
            : { live: { ...state.live, findings: [...state.live.findings, finding] } },
        )
        if (finding.severity === 'critical') {
          get().notify({ severity: 'critical', message: `Critical: ${finding.title}` })
        }
        scheduleRebuild()
        break
      }
      case 'close':
        handleClose()
        break
      default:
        break
    }
  }

  return {
    live: { ...IDLE_LIVE },
    start: (sourceId, speed) => {
      const state = get().live
      if (state.status === 'capturing' || state.status === 'connecting' || state.status === 'stopping') return
      if (uploadBusy(get().upload.status)) return
      const nextSource = sourceId ?? state.sourceId
      const nextSpeed = speed ?? state.speed
      set(() => ({
        live: { ...IDLE_LIVE, sourceId: nextSource, speed: nextSpeed, status: 'connecting' },
      }))
      const socket = getActiveApi().openLiveCapture(nextSource, nextSpeed)
      activeSocket = socket
      socket.onmessage = handleMessage
      socket.onclose = () => {
        activeSocket = null
        handleClose()
      }
      socket.onerror = (error) => {
        get().notify({ severity: 'warn', message: `Live capture error: ${error.message}` })
        patchLive({ status: 'idle' })
        activeSocket = null
      }
    },
    stop: () => {
      const state = get().live
      if (state.status !== 'capturing' && state.status !== 'connecting') return
      patchLive({ status: 'stopping' })
      const socket = activeSocket
      activeSocket = null
      if (socket) {
        socket.close()
      } else {
        finalizeCapture()
      }
    },
    setLiveOptions: ({ sourceId, speed }) => {
      const state = get().live
      if (state.status !== 'idle') return
      set((current) => ({
        live: {
          ...current.live,
          sourceId: sourceId ?? current.live.sourceId,
          speed: speed ?? current.live.speed,
        },
      }))
    },
    reset: () => {
      const socket = activeSocket
      activeSocket = null
      if (socket) {
        socket.onclose = null
        socket.onerror = null
        socket.onmessage = null
        socket.close()
      }
      set((state) => ({ live: { ...IDLE_LIVE, sourceId: state.live.sourceId, speed: state.live.speed } }))
    },
  }
}
