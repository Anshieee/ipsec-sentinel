import { describe, expect, it, vi } from 'vitest'
import { createSimulator } from './liveSim'
import { protocolWithReveal } from './liveSim'
import { FIXTURE_SPECS } from './fixtures/spec'
import { runMockPipeline, PARSE_ERROR, configureMock } from './mock'
import { validateUpload, UPLOAD_ERRORS } from '@/lib/validate'

const collect = (id: 'A' | 'B' | 'C', ticks: number) => {
  const simulator = createSimulator(id)
  const messages = []
  for (let i = 0; i < ticks; i++) messages.push(...simulator.tick())
  return messages
}

describe('live simulator', () => {
  it('produces identical message sequences for the same seed', () => {
    const first = collect('A', 50)
    const second = collect('A', 50)
    expect(JSON.stringify(first)).toEqual(JSON.stringify(second))
    expect(first.length).toBeGreaterThan(50)
    const types = new Set(first.map((m) => m.type))
    expect(types.has('handshake')).toBe(true)
    expect(types.has('packet')).toBe(true)
    expect(types.has('stats')).toBe(true)
    expect(types.has('param')).toBe(true)
    expect([...first.slice(0, 8)].every((m, i) => m.seq === i + 1)).toBe(true)
  })

  it('differs between fixtures', () => {
    expect(collect('A', 10).map((m) => m.type)).not.toEqual(collect('B', 10).map((m) => m.type))
  })

  it('reveals observed parameters after the IKE_SA_INIT response', () => {
    const messages = collect('A', 20)
    const params = messages.filter((m) => m.type === 'param').map((m) => (m.payload as { key: string }).key)
    expect(params).toContain('ikeVersion')
    expect(params).toContain('ike.dhGroup')
    expect(params).not.toContain('mode')
  })

  it('reveals inferred parameters progressively and ramps confidence', () => {
    const messages = collect('C', 260)
    const params = messages
      .filter((m) => m.type === 'param')
      .map((m) => m.payload as { key: string; confidence: number; provenance: string })
    expect(params.some((p) => p.key === 'mode')).toBe(true)
    expect(params.some((p) => p.key === 'child.encryption')).toBe(true)
    const modeValues = params.filter((p) => p.key === 'mode').map((p) => p.confidence)
    expect(modeValues.length).toBeGreaterThan(1)
    expect(modeValues[modeValues.length - 1]).toBeGreaterThan(modeValues[0] ?? 0)
    const observed = params.find((p) => p.key === 'ikeVersion')
    expect(observed?.provenance).toBe('observed')
    expect(observed?.confidence).toBe(1)
  })

  it('emits classification messages once enough ESP packets are seen', () => {
    const messages = collect('A', 160)
    const classification = messages.find((m) => m.type === 'classification')
    expect(classification).toBeDefined()
    if (!classification) return
    const payload = classification.payload as { classes: { label: string; probability: number }[] }
    expect(payload.classes).toHaveLength(7)
    const total = payload.classes.reduce((sum, c) => sum + c.probability, 0)
    expect(total).toBeCloseTo(1, 6)
  })

  it('emits findings produced by the rule engine', () => {
    const messages = collect('C', 260)
    const findings = messages.filter((m) => m.type === 'finding').map((m) => m.payload as { ruleId: string; severity: string })
    expect(findings.length).toBeGreaterThan(0)
    expect(findings.some((f) => f.severity === 'critical')).toBe(true)
  })

  it('marks unrevealed parameters as pending in the working protocol', () => {
    const spec = FIXTURE_SPECS.A
    const protocol = protocolWithReveal(spec, {})
    expect(protocol.mode.note).toBe('Pending…')
    expect(protocol.mode.confidence).toBe(0)
    expect(protocol.mode.provenance).toBe('inferred')
    const revealed = protocolWithReveal(spec, { mode: 0.5, 'ikeVersion': 1 })
    expect(revealed.mode.confidence).toBeCloseTo(0.5, 6)
    expect(revealed.mode.provenance).toBe('inferred')
    expect(revealed.ikeVersion.confidence).toBe(1)
    expect(revealed.ikeVersion.provenance).toBe('observed')
  })
})

describe('mock upload pipeline', () => {
  it('rejects invalid files before any progress is reported', async () => {
    const onProgress = vi.fn()
    const file = new File(['hello'], 'notes.txt', { type: 'text/plain' })
    await expect(runMockPipeline(file, onProgress)).rejects.toThrow(UPLOAD_ERRORS.unsupported)
    expect(onProgress).not.toHaveBeenCalled()
  })

  it('reports staged progress and resolves with a stamped fixture', async () => {
    vi.useFakeTimers()
    try {
      const onProgress = vi.fn()
      const file = new File(['pcap-bytes'], 'office_gcm_capture.pcapng', { type: 'application/octet-stream' })
      const promise = runMockPipeline(file, onProgress)
      await vi.advanceTimersByTimeAsync(4100)
      const analysis = await promise
      expect(analysis.id).toContain('upload-')
      expect(analysis.fileName).toBe('office_gcm_capture.pcapng')
      expect(analysis.source).toBe('upload')
      expect(analysis.riskScore).toBe(9)
      const stages = onProgress.mock.calls.map((call) => (call as [{ stage: string }])[0].stage)
      expect(stages).toContain('uploading')
      expect(stages).toContain('parsing')
      expect(stages).toContain('inferring')
      const last = onProgress.mock.calls.at(-1)?.[0] as { progress: number }
      expect(last.progress).toBe(100)
    } finally {
      vi.useRealTimers()
    }
  })

  it('fails corrupt traces with the parse error', async () => {
    vi.useFakeTimers()
    try {
      const file = new File(['pcap-bytes'], 'corrupt_capture.pcap', { type: 'application/octet-stream' })
      const promise = runMockPipeline(file, vi.fn())
      const assertion = expect(promise).rejects.toThrow(PARSE_ERROR)
      await vi.advanceTimersByTimeAsync(3000)
      await assertion
    } finally {
      vi.useRealTimers()
    }
  })

  it('honours the simulateErrors flag', async () => {
    vi.useFakeTimers()
    try {
      configureMock({ simulateErrors: true })
      const file = new File(['pcap-bytes'], 'anything.pcap', { type: 'application/octet-stream' })
      const promise = runMockPipeline(file, vi.fn())
      const assertion = expect(promise).rejects.toThrow(PARSE_ERROR)
      await vi.advanceTimersByTimeAsync(3000)
      await assertion
      configureMock({ simulateErrors: false })
    } finally {
      vi.useRealTimers()
    }
  })

  it('aborts an in-flight analysis', async () => {
    vi.useFakeTimers()
    try {
      const controller = new AbortController()
      const file = new File(['pcap-bytes'], 'long_trace.pcap', { type: 'application/octet-stream' })
      const promise = runMockPipeline(file, vi.fn(), controller.signal)
      const assertion = expect(promise).rejects.toMatchObject({ name: 'AbortError' })
      await vi.advanceTimersByTimeAsync(200)
      controller.abort()
      await vi.advanceTimersByTimeAsync(100)
      await assertion
    } finally {
      vi.useRealTimers()
    }
  })
})

describe('upload validation contract', () => {
  it('uses the exact messages from the specification', async () => {
    await expect(validateUpload({ name: 'a.txt', size: 1 })).rejects.toThrow(
      'Unsupported file type. Upload a .pcap or .pcapng trace.',
    )
    await expect(validateUpload({ name: 'a.pcap', size: 0 })).rejects.toThrow('The file is empty.')
    await expect(validateUpload({ name: 'a.pcap', size: 201 * 1024 * 1024 })).rejects.toThrow(
      'File exceeds the 200 MB limit.',
    )
  })
})
