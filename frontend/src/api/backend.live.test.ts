/**
 * Live-backend integration (docs/frontend-integration.md, v1.2 contract).
 * Requires the real API on VITE_API_URL (default http://127.0.0.1:8000)
 * with generated data + trained models. Skips cleanly when it is down;
 * run it explicitly before releases with the API serving.
 *
 * Covers v1, v19, v20, v21 (weak IKE), ESP-only, non-IPsec and corrupt
 * inputs; the mapped headline must equal the CLI --json values for the
 * same file (skipped when the CLI is unavailable).
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { Buffer } from 'node:buffer'
import { execFileSync } from 'node:child_process'
import { resolve } from 'node:path'
import { mapAnalyzeResponse, type BackendAnalyzeResponse } from './backend'

const API = process.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const REPO = resolve(__dirname, '../../..')
const SAMPLES = resolve(REPO, 'demo/samples')
const DATA_PCAPS = resolve(REPO, 'data/pcaps/synth')
const CLI = resolve(REPO, '.venv/bin/ipsec-analyze')

async function probe(): Promise<boolean> {
  try {
    const res = await fetch(`${API}/health`)
    return res.ok
  } catch {
    return false
  }
}

const apiUp = await probe()
if (!apiUp) console.info(`[live-integration] API down at ${API}, skipping`)

function cliHeadline(path: string): { posture: number | null; coverage: number; status: string } | null {
  try {
    const raw = execFileSync(CLI, ['analyze', path, '--json'], { timeout: 120000, encoding: 'utf-8' })
    const body = JSON.parse(raw) as {
      assessment: { posture_score: number | null; coverage: number; score_status: string }
    }
    return { posture: body.assessment.posture_score, coverage: body.assessment.coverage, status: body.assessment.score_status }
  } catch {
    return null
  }
}

async function upload(name: string, path: string, bytes?: Uint8Array): Promise<BackendAnalyzeResponse> {
  const data = bytes ?? readFileSync(path)
  // Manual multipart (jsdom FormData does not survive undici fetch).
  const boundary = '----liveboundary'
  const head = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\n` +
      'Content-Type: application/octet-stream\r\n\r\n',
  )
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`)
  const body = Buffer.concat([head, Buffer.from(data), tail])
  let lastError: unknown = null
  // One retry: the single-worker dev server occasionally drops a
  // keep-alive connection between rapid sequential uploads.
  for (let attempt = 0; attempt < 2; attempt++) {
    try {
      const res = await fetch(`${API}/analyze`, {
        method: 'POST',
        headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
        body: body as unknown as BodyInit,
      })
      if (!res.ok) {
        const text = await res.text()
        throw new Error(`upload ${name} failed: ${res.status} ${text.slice(0, 200)}`)
      }
      return (await res.json()) as BackendAnalyzeResponse
    } catch (error) {
      lastError = error
    }
  }
  throw lastError
}

const headlineCases: { file: string; path: string; posture: number | null; coverage: number; status: string }[] = [
  { file: 'v1-voip.pcap', path: resolve(SAMPLES, 'v1-voip.pcap'), posture: 89, coverage: 0.6684, status: 'PUBLISHED' },
  { file: 'v19-voip.pcap', path: resolve(DATA_PCAPS, 'v19/r1/voip.pcap'), posture: 72, coverage: 0.6258, status: 'PUBLISHED' },
  { file: 'v20-voip.pcap', path: resolve(DATA_PCAPS, 'v20/r1/voip.pcap'), posture: 99, coverage: 0.6327, status: 'PUBLISHED' },
  { file: 'v21-voip.pcap', path: resolve(DATA_PCAPS, 'v21/r1/voip.pcap'), posture: 80, coverage: 0.6576, status: 'PUBLISHED' },
]

describe.skipIf(!apiUp)('live backend mapping', () => {
  it.each(headlineCases)('maps $file to posture $posture @ $coverage ($status)', async ({ file, path, posture, coverage, status }) => {
    const resp = await upload(file, path)
    const mapped = mapAnalyzeResponse({ name: file }, resp)
    expect(mapped.posture?.postureScore).toBe(posture)
    expect(mapped.posture?.coverage).toBeCloseTo(coverage, 4)
    expect(mapped.posture?.scoreStatus).toBe(status)
    expect(mapped.riskScore).toBe(status === 'PUBLISHED' && posture !== null ? 100 - posture : null)
    expect(mapped.detection?.ipsecDetected).toBe(true)
    // Displayed headline equals the CLI --json values for the same file.
    const cli = cliHeadline(path)
    if (cli !== null) {
      expect(mapped.posture?.postureScore).toBe(cli.posture)
      expect(mapped.posture?.coverage).toBeCloseTo(cli.coverage, 4)
      expect(mapped.posture?.scoreStatus).toBe(cli.status)
    }
    // IKE SA and CHILD SA are separate cards with per-field status.
    expect(mapped.protocol.ike.encryption.value).not.toBe('')
    expect(mapped.protocol.child.encryption.status).toBe('INFERRED')
  })

  it('flags the weak IKE suite on v21 without touching the strong child', async () => {
    const path = resolve(DATA_PCAPS, 'v21/r1/voip.pcap')
    const resp = await upload('v21-voip.pcap', path)
    const mapped = mapAnalyzeResponse({ name: 'v21-voip.pcap' }, resp)
    const ids = mapped.findings.map((f) => f.id)
    expect(ids).toContain('weak-ike-cipher')
    expect(ids).toContain('weak-ike-integ')
    expect(ids).toContain('weak-ike-dh')
    expect(ids).not.toContain('weak-cipher')
    expect(mapped.protocol.child.encryption.value).toBe('AES-256-GCM-16')
    for (const f of mapped.findings) expect(f.verdict).toBe('CONFIRMED')
  })

  it('marks the v19 weak child as LIKELY (inferred evidence)', async () => {
    const path = resolve(DATA_PCAPS, 'v19/r1/voip.pcap')
    const resp = await upload('v19-voip.pcap', path)
    const mapped = mapAnalyzeResponse({ name: 'v19-voip.pcap' }, resp)
    const weak = mapped.findings.find((f) => f.id === 'weak-cipher')
    expect(weak?.verdict).toBe('LIKELY')
    expect(weak?.severity).toBe('high')
    expect(typeof weak?.confidence).toBe('number')
  })

  it('reports an ESP-only capture as NOT_OBSERVED IKE with no certain no-IKE', async () => {
    const path = resolve(SAMPLES, 'esp-only-v1.pcap')
    const resp = await upload('esp-only-v1.pcap', path)
    const mapped = mapAnalyzeResponse({ name: 'esp-only-v1.pcap' }, resp)
    expect(resp.ike_sa.version.value).toBe('unknown')
    expect(resp.ike_sa.version.status).toBe('NOT_OBSERVED')
    expect(mapped.protocol.ikeVersion.status).toBe('NOT_OBSERVED')
    const cli = cliHeadline(path)
    if (cli !== null) expect(mapped.posture?.scoreStatus).toBe(cli.status)
  })

  it('reports a non-IPsec capture as no-IPsec-detected with no score', async () => {
    const path = resolve(SAMPLES, 'plain-web.pcap')
    const resp = await upload('plain-web.pcap', path)
    const mapped = mapAnalyzeResponse({ name: 'plain-web.pcap' }, resp)
    expect(mapped.detection?.ipsecDetected).toBe(false)
    expect(mapped.posture?.scoreStatus).toBe('WITHHELD')
    expect(mapped.posture?.postureScore).toBeNull()
    expect(mapped.riskScore).toBeNull()
    expect(mapped.findings).toEqual([])
  })

  it.each([
    ['v5-voip.pcap', 'transport'],
    ['v4-voip.pcap', 'tunnel'],
    ['v7-voip.pcap', 'tunnel'],
  ])('maps %s (mode %s)', async (file, mode) => {
    const resp = await upload(file, resolve(SAMPLES, file))
    const mapped = mapAnalyzeResponse({ name: file }, resp)
    expect(mapped.protocol.mode.value).toBe(mode)
    expect(mapped.overallConfidence).toBeGreaterThan(0)
  })

  it('rejects corrupt captures with a friendly error, no traceback', async () => {
    const bytes = new Uint8Array(2048)
    crypto.getRandomValues(bytes)
    const boundary = '----liveboundary'
    const res = await fetch(`${API}/analyze`, {
      method: 'POST',
      headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
      body: Buffer.concat([
        Buffer.from(
          `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="corrupt.pcap"\r\n` +
            'Content-Type: application/octet-stream\r\n\r\n',
        ),
        Buffer.from(bytes),
        Buffer.from(`\r\n--${boundary}--\r\n`),
      ]) as unknown as BodyInit,
    })
    expect(res.status).toBe(422)
    const body = (await res.json()) as { detail?: unknown }
    expect(typeof body.detail).toBe('string')
    expect(String(body.detail)).not.toMatch(/Traceback|File ".*", line/)
  })
})
