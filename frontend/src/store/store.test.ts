import { afterEach, describe, expect, it, vi } from 'vitest'
import { useSentinel } from './useSentinel'
import { cloneFixture } from '@/api/fixtures'

const flush = async () => {
  await Promise.resolve()
  await Promise.resolve()
}

describe('live capture slice', () => {
  afterEach(() => {
    useSentinel.getState().reset()
    useSentinel.getState().clear()
    useSentinel.getState().clearNotifications()
    useSentinel.getState().resetUpload()
    vi.useRealTimers()
  })

  it('yields a valid exportable analysis when the capture stops', async () => {
    vi.useFakeTimers()
    useSentinel.getState().start('C', 1)
    await vi.advanceTimersByTimeAsync(0)
    await vi.advanceTimersByTimeAsync(3000)
    await flush()

    const capturing = useSentinel.getState()
    expect(capturing.live.status).toBe('capturing')
    expect(capturing.live.working).not.toBeNull()
    expect(capturing.live.counters.packets).toBeGreaterThan(0)
    expect(capturing.live.recent.length).toBeGreaterThan(0)
    expect(capturing.live.recent.length).toBeLessThanOrEqual(200)

    useSentinel.getState().stop()
    await flush()

    const stopped = useSentinel.getState()
    expect(stopped.live.status).toBe('idle')
    expect(stopped.live.working).toBeNull()
    const analysis = stopped.current
    expect(analysis).not.toBeNull()
    if (!analysis) return
    expect(analysis.source).toBe('live')
    expect(analysis.fileName).toMatch(/^live-capture-\d{8}-\d{6}$/)
    expect(analysis.packets.length).toBeGreaterThan(0)
    expect(analysis.handshake.length).toBeGreaterThan(0)
    expect(analysis.findings.length).toBeGreaterThan(0)
    expect(analysis.riskScore).toBeGreaterThan(0)
    expect(stopped.notifications.some((n) => n.message === 'Live capture stopped. Analysis ready.')).toBe(true)
    expect(stopped.notifications.some((n) => n.message.startsWith('Critical: '))).toBe(true)
    expect(stopped.notifications.some((n) => n.message === 'Live capture started.')).toBe(true)
  })

  it('does not start while an upload is in progress', () => {
    useSentinel.setState({ upload: { status: 'uploading', progress: 10, fileName: 'x.pcap' } })
    useSentinel.getState().start('A', 1)
    expect(useSentinel.getState().live.status).toBe('idle')
    useSentinel.getState().resetUpload()
  })
})

describe('upload slice', () => {
  afterEach(() => {
    useSentinel.getState().resetUpload()
    useSentinel.getState().clear()
    vi.useRealTimers()
  })

  it('stores an error message for an unsupported file', async () => {
    const file = new File(['x'], 'notes.txt', { type: 'text/plain' })
    await useSentinel.getState().startUpload(file)
    const upload = useSentinel.getState().upload
    expect(upload.status).toBe('error')
    expect(upload.error).toBe('Unsupported file type. Upload a .pcap or .pcapng trace.')
    expect(useSentinel.getState().current).toBeNull()
  })

  it('completes a pipeline and sets the analysis', async () => {
    vi.useFakeTimers()
    const file = new File(['pcap'], 'branch_cbc_trace.pcap', { type: 'application/octet-stream' })
    const promise = useSentinel.getState().startUpload(file)
    await vi.advanceTimersByTimeAsync(4100)
    await promise
    await flush()
    const state = useSentinel.getState()
    expect(state.upload.status).toBe('complete')
    expect(state.current?.riskScore).toBe(78)
    expect(state.notifications.some((n) => n.message === 'Analysis complete.')).toBe(true)
    vi.useRealTimers()
  })
})

describe('demo data and settings', () => {
  it('reset demo data clears analysis and notifications', () => {
    const store = useSentinel.getState()
    store.setAnalysis(cloneFixture('A'))
    store.notify({ severity: 'info', message: 'hello' })
    expect(useSentinel.getState().current).not.toBeNull()
    expect(useSentinel.getState().notifications.length).toBeGreaterThan(0)
    useSentinel.getState().resetDemoData()
    expect(useSentinel.getState().current).toBeNull()
    expect(useSentinel.getState().notifications).toHaveLength(0)
    expect(useSentinel.getState().status).toBe('idle')
  })

  it('records the previous risk score when a new analysis arrives', () => {
    const store = useSentinel.getState()
    store.setAnalysis(cloneFixture('C'))
    expect(useSentinel.getState().previousRiskScore).toBeUndefined()
    store.setAnalysis(cloneFixture('A'))
    expect(useSentinel.getState().previousRiskScore).toBe(94)
    expect(useSentinel.getState().current?.riskScore).toBe(9)
    store.clear()
  })

  it('persists only the settings slice', async () => {
    useSentinel.getState().setSetting('density', 'compact')
    const raw = window.localStorage.getItem('sentinel.settings.v1')
    expect(raw).not.toBeNull()
    if (!raw) return
    const parsed = JSON.parse(raw) as { state: Record<string, unknown> }
    expect((parsed.state.settings as { density: string }).density).toBe('compact')
    expect(parsed.state.current).toBeUndefined()
    expect(parsed.state.notifications).toBeUndefined()

    vi.resetModules()
    const reloaded = await import('./useSentinel')
    expect(reloaded.useSentinel.getState().settings.density).toBe('compact')
    reloaded.useSentinel.getState().resetSettings()
    expect(reloaded.useSentinel.getState().settings.density).toBe('comfortable')
    useSentinel.getState().resetSettings()
  })
})
