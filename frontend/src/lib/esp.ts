/**
 * ESP length model (spec 8.5). Used by the fixture builder and the packet
 * detail estimates, so both sides of the UI agree.
 */

export interface EspCipherConfig {
  outerIp: 20 | 40
  iv: number
  icv: number
  block: number
  /** tunnel mode: inner IP header included (20 or 40); transport mode: 0 */
  tunnelInnerIp: 0 | 20 | 40
}

// tunnel mode: innerBytes includes the inner IP header (20 or 40); transport mode: it does not
export function espLength(
  payload: number,
  c: { outerIp: 20 | 40; iv: number; icv: number; block: number; tunnelInnerIp: 0 | 20 | 40 },
): number {
  const inner = payload + c.tunnelInnerIp
  const padded = Math.ceil((inner + 2) / c.block) * c.block // +2: pad length and next header
  return c.outerIp + 8 + c.iv + padded + c.icv // 8: SPI + sequence number
}

export type CipherFamily = 'AES-GCM' | 'AES-CBC' | '3DES-CBC' | 'unknown'

export function cipherFamily(encryption: string): CipherFamily {
  const name = encryption.trim().toUpperCase()
  if (name.includes('GCM')) return 'AES-GCM'
  if (name.startsWith('3DES') || name.startsWith('DES')) return '3DES-CBC'
  if (name.includes('CBC')) return 'AES-CBC'
  return 'unknown'
}

/** IV, ICV and block size for a cipher suite. */
export function espCipherParams(encryption: string, integrity: string): { iv: number; icv: number; block: number } {
  const family = cipherFamily(encryption)
  const icv = integrity.includes('SHA2-256') || integrity.includes('SHA2-384') ? 16 : 12
  switch (family) {
    case 'AES-GCM':
      // AES-GCM: iv 8, icv 16, block 4
      return { iv: 8, icv: 16, block: 4 }
    case '3DES-CBC':
      // 3DES-CBC + HMAC-SHA1-96: iv 8, icv 12, block 8
      return { iv: 8, icv, block: 8 }
    case 'AES-CBC':
      // AES-CBC: iv 16, block 16 (icv from the integrity algorithm)
      return { iv: 16, icv, block: 16 }
    default:
      return { iv: 8, icv, block: 16 }
  }
}

export interface EspConfigOptions {
  encryption: string
  integrity: string
  outerIp: 20 | 40
  mode: 'tunnel' | 'transport'
}

export function espConfig(opts: EspConfigOptions): EspCipherConfig {
  const params = espCipherParams(opts.encryption, opts.integrity)
  return {
    outerIp: opts.outerIp,
    iv: params.iv,
    icv: params.icv,
    block: params.block,
    tunnelInnerIp: opts.mode === 'tunnel' ? opts.outerIp : 0,
  }
}

/** Estimated ESP wire length for a payload size. */
export function estimateEspLength(payload: number, opts: EspConfigOptions): number {
  return espLength(payload, espConfig(opts))
}
