import { describe, expect, it } from 'vitest'
import { mulberry32, hashString, hexFromRng, randInt, FIXTURE_SEEDS } from './prng'
import { DH_GROUPS, dhLabel, securityBits, dhKeBytes, dhStatus } from './dh'
import { espLength, espConfig, espCipherParams, cipherFamily, estimateEspLength } from './esp'
import { fmtBytes, fmtDuration, fmtPct, fmtInt, relTime, fileStamp, fmtClock } from './format'
import { validateUpload, validateUploadSync, UPLOAD_ERRORS, MAX_UPLOAD_BYTES } from './validate'

describe('prng', () => {
  it('is deterministic for a fixed seed', () => {
    const a = mulberry32(42)
    const b = mulberry32(42)
    const first = Array.from({ length: 10 }, () => a())
    const second = Array.from({ length: 10 }, () => b())
    expect(first).toEqual(second)
    expect(first[0]).toBeGreaterThanOrEqual(0)
    expect(first[0]).toBeLessThan(1)
  })

  it('hashes strings stably', () => {
    expect(hashString('gcm')).toBe(hashString('gcm'))
    expect(hashString('gcm')).not.toBe(hashString('cbc'))
    expect(hashString('')).toBe(2166136261)
  })

  it('produces hex strings of the requested length', () => {
    const rng = mulberry32(FIXTURE_SEEDS.A)
    expect(hexFromRng(rng, 16)).toMatch(/^[0-9a-f]{16}$/)
    expect(hexFromRng(mulberry32(1), 8)).toHaveLength(8)
  })

  it('draws integers inside the inclusive range', () => {
    const rng = mulberry32(7)
    for (let i = 0; i < 100; i++) {
      const v = randInt(rng, 6, 14)
      expect(v).toBeGreaterThanOrEqual(6)
      expect(v).toBeLessThanOrEqual(14)
    }
  })
})

describe('dh table', () => {
  it('lists the nine groups with expected values', () => {
    expect(DH_GROUPS).toHaveLength(9)
    expect(DH_GROUPS[0]).toMatchObject({ group: 1, name: 'MODP-768', keBytes: 96, status: 'Broken' })
    expect(DH_GROUPS[6]).toMatchObject({ group: 19, name: 'ECP-256', securityBits: 128, keBytes: 64 })
  })

  it('labels groups for display', () => {
    expect(dhLabel(14)).toBe('Group 14 (MODP-2048)')
    expect(dhLabel(99)).toBe('Group 99 (unknown)')
  })

  it('treats "below 64" as 64 for sorting and charting', () => {
    expect(securityBits(1)).toBe(64)
    expect(securityBits(2)).toBe(80)
    expect(securityBits(21)).toBe(256)
    expect(securityBits(99)).toBe(0)
  })

  it('exposes payload cost and status', () => {
    expect(dhKeBytes(19)).toBe(64)
    expect(dhKeBytes(14)).toBe(256)
    expect(dhStatus(1)).toBe('Broken')
    expect(dhStatus(16)).toBe('Acceptable')
  })
})

describe('esp length model', () => {
  it('matches the AES-GCM example parameters', () => {
    const params = espCipherParams('AES-256-GCM-16', 'AEAD (implicit)')
    expect(params).toEqual({ iv: 8, icv: 16, block: 4 })
    expect(cipherFamily('AES-256-GCM-16')).toBe('AES-GCM')
    expect(cipherFamily('AES-128-CBC')).toBe('AES-CBC')
    expect(cipherFamily('3DES-CBC')).toBe('3DES-CBC')
  })

  it('computes tunnel-mode overhead with the inner IP header', () => {
    const cfg = espConfig({ encryption: 'AES-128-CBC', integrity: 'HMAC-SHA1-96', outerIp: 20, mode: 'tunnel' })
    expect(cfg).toEqual({ outerIp: 20, iv: 16, icv: 12, block: 16, tunnelInnerIp: 20 })
    // payload 100 + inner 20 + 2 -> 122 -> 128 padded; 20 + 8 + 16 + 128 + 12
    expect(espLength(100, cfg)).toBe(184)
  })

  it('computes transport-mode overhead without an inner IP header', () => {
    const cfg = espConfig({ encryption: 'AES-256-GCM-16', integrity: 'AEAD (implicit)', outerIp: 20, mode: 'transport' })
    expect(cfg.tunnelInnerIp).toBe(0)
    // payload 84 + 2 = 86 -> 88 padded to block 4; 20 + 8 + 8 + 88 + 16
    expect(espLength(84, cfg)).toBe(140)
    expect(estimateEspLength(84, { encryption: 'AES-256-GCM-16', integrity: 'AEAD (implicit)', outerIp: 20, mode: 'transport' })).toBe(140)
  })

  it('uses IPv6 outer headers when asked', () => {
    const cfg = espConfig({ encryption: '3DES-CBC', integrity: 'HMAC-SHA1-96', outerIp: 40, mode: 'transport' })
    expect(cfg).toEqual({ outerIp: 40, iv: 8, icv: 12, block: 8, tunnelInnerIp: 0 })
    // payload 100 + 2 = 102 -> 104 padded to block 8; 40 + 8 + 8 + 104 + 12
    expect(espLength(100, cfg)).toBe(172)
  })
})

describe('format helpers', () => {
  it('formats bytes', () => {
    expect(fmtBytes(512)).toBe('512 B')
    expect(fmtBytes(2048)).toBe('2.0 KB')
    expect(fmtBytes(1_048_576)).toBe('1.0 MB')
  })

  it('formats durations', () => {
    expect(fmtDuration(55934)).toBe('15h 32m 14s')
    expect(fmtDuration(1934)).toBe('32m 14s')
    expect(fmtDuration(14)).toBe('14s')
    expect(fmtDuration(0)).toBe('0s')
  })

  it('formats percentages and integers', () => {
    expect(fmtPct(0.964)).toBe('96.4%')
    expect(fmtPct(0.5)).toBe('50.0%')
    expect(fmtInt(48213)).toBe('48,213')
  })

  it('formats relative times', () => {
    const now = Date.parse('2026-09-30T12:00:00.000Z')
    expect(relTime('2026-09-30T11:59:57.000Z', now)).toBe('just now')
    expect(relTime('2026-09-30T11:56:00.000Z', now)).toBe('4 min ago')
    expect(relTime('2026-09-29T12:00:00.000Z', now)).toBe('1 d ago')
    expect(relTime('not-a-date', now)).toBe('—')
  })

  it('formats file stamps and the capture clock', () => {
    expect(fileStamp(new Date('2026-09-30T14:25:07'))).toBe('20260930-1425')
    expect(fmtClock(125)).toBe('02:05')
    expect(fmtClock(0)).toBe('00:00')
  })
})

describe('upload validation', () => {
  it('rejects unsupported extensions with the exact message', async () => {
    expect(validateUploadSync({ name: 'notes.txt', size: 10 })).toBe(UPLOAD_ERRORS.unsupported)
    await expect(validateUpload({ name: 'notes.txt', size: 10 })).rejects.toThrow(UPLOAD_ERRORS.unsupported)
  })

  it('rejects empty files with the exact message', async () => {
    expect(validateUploadSync({ name: 'empty.pcap', size: 0 })).toBe(UPLOAD_ERRORS.empty)
    await expect(validateUpload({ name: 'empty.pcap', size: 0 })).rejects.toThrow(UPLOAD_ERRORS.empty)
  })

  it('rejects files above 200 MB', async () => {
    const name = 'huge.pcapng'
    expect(validateUploadSync({ name, size: MAX_UPLOAD_BYTES + 1 })).toBe(UPLOAD_ERRORS.tooLarge)
    await expect(validateUpload({ name, size: MAX_UPLOAD_BYTES + 1 })).rejects.toThrow(UPLOAD_ERRORS.tooLarge)
  })

  it('accepts a normal trace', async () => {
    expect(validateUploadSync({ name: 'trace.PCAP', size: 1024 })).toBeNull()
    await expect(validateUpload({ name: 'trace.pcapng', size: 1024 })).resolves.toBeUndefined()
  })
})
