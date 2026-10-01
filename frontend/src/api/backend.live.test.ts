/**
 * Live-backend integration (docs/frontend-integration.md).
 * Requires the real API on VITE_API_URL (default http://127.0.0.1:8000)
 * with generated data + trained models. Skips cleanly when it is down;
 * run it explicitly before releases with the API serving.
 */
import { describe, expect, it } from 'vitest'
import { readFileSync } from 'node:fs'
import { Buffer } from 'node:buffer'
import { resolve } from 'node:path'
import { mapAnalyzeResponse, type BackendAnalyzeResponse } from './backend'

const API = process.env.VITE_API_URL ?? 'http://127.0.0.1:8000'
const SAMPLES = resolve(__dirname, '../../../demo/samples')

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

async function upload(name: string, bytes?: Uint8Array): Promise<BackendAnalyzeResponse> {
  const data = bytes ?? readFileSync(resolve(SAMPLES, name))
  // Manual multipart (jsdom FormData does not survive undici fetch).
  const boundary = '----liveboundary';
  const head = Buffer.from(
    `--${boundary}\r\nContent-Disposition: form-data; name="file"; filename="${name}"\r\n` +
      'Content-Type: application/octet-stream\r\n\r\n',
  )
  const tail = Buffer.from(`\r\n--${boundary}--\r\n`)
  const res = await fetch(`${API}/analyze`, {
    method: 'POST',
    headers: { 'Content-Type': `multipart/form-data; boundary=${boundary}` },
    body: Buffer.concat([head, Buffer.from(data), tail]) as unknown as BodyInit,
  })
  if (!res.ok) {
    const text = await res.text()
    throw new Error(`upload ${name} failed: ${res.status} ${text.slice(0, 200)}`)
  }
  return (await res.json()) as BackendAnalyzeResponse
}

describe.skipIf(!apiUp)('live backend mapping', () => {
  it('maps v1 to Security 73 and risk 27', async () => {
    const resp = await upload('v1-voip.pcap')
    const mapped = mapAnalyzeResponse({ name: 'v1-voip.pcap' }, resp)
    expect(mapped.backendAssessment?.securityScore).toBe(73)
    expect(mapped.backendAssessment?.riskScore).toBe(27)
    expect(mapped.riskScore).toBe(27)
    expect(mapped.protocol.ikeVersion.value).toBe('IKEv2')
    expect(mapped.protocol.mode.value).toBe('tunnel')
  })

  it.each([
    ['v5-voip.pcap', 'transport'],
    ['v4-voip.pcap', 'tunnel'],
    ['v7-voip.pcap', 'tunnel'],
    ['plain-web.pcap', 'tunnel'],
  ])('maps %s (mode %s)', async (file, mode) => {
    const resp = await upload(file)
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
