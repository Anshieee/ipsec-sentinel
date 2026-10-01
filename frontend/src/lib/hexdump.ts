import { mulberry32 } from './prng'
import type { PacketRow } from '@/types/analysis'

export interface HexRow {
  offset: string
  hex: string
  ascii: string
}

/**
 * Deterministic 64-byte payload for the inspector hex dump (spec 10.2 item 4).
 * IKE headers are constructed from the packet fields; ESP starts with SPI and
 * sequence number followed by PRNG bytes (`mulberry32(no)`).
 */
export function packetBytes(packet: PacketRow): Uint8Array {
  const rng = mulberry32(packet.no)
  const bytes = new Uint8Array(64)

  if (packet.proto === 'IKE') {
    // Initiator SPI (8), responder SPI (8), next payload, version, exchange,
    // flags, message id (4), length (4).
    for (let i = 0; i < 8; i += 1) bytes[i] = Math.floor(rng() * 256)
    for (let i = 8; i < 16; i += 1) bytes[i] = Math.floor(rng() * 256)
    bytes[16] = 0x21 // Security Association (v1) / SA payload
    bytes[17] = 0x20 // version 2.0 for IKEv2, 0x10 for v1
    bytes[18] = 0x20 // IKE_SA_INIT
    bytes[19] = 0x00 // flags
    for (let i = 20; i < 24; i += 1) bytes[i] = 0x00
    const length = packet.length & 0xff
    bytes[24] = 0x00
    bytes[25] = 0x00
    bytes[26] = (length >> 8) & 0xff
    bytes[27] = length & 0xff
    for (let i = 28; i < 64; i += 1) bytes[i] = Math.floor(rng() * 256)
    return bytes
  }

  // SPI (4) + sequence number (4), then pseudo-random payload bytes.
  const spiHex = (packet.spi ?? '00000000').replace(/^0x/i, '').padStart(8, '0')
  for (let i = 0; i < 4; i += 1) {
    bytes[i] = Number.parseInt(spiHex.slice(i * 2, i * 2 + 2), 16) & 0xff
  }
  const seq = packet.seq ?? packet.no
  bytes[4] = (seq >>> 24) & 0xff
  bytes[5] = (seq >>> 16) & 0xff
  bytes[6] = (seq >>> 8) & 0xff
  bytes[7] = seq & 0xff
  for (let i = 8; i < 64; i += 1) bytes[i] = Math.floor(rng() * 256)
  return bytes
}

const HEX = '0123456789abcdef'

function hexByte(value: number): string {
  return `${HEX[(value >> 4) & 0xf]}${HEX[value & 0xf]}`
}

/** 64 bytes as 4 rows of 16: offset, hex, ASCII. */
export function hexRows(bytes: Uint8Array): HexRow[] {
  const rows: HexRow[] = []
  for (let base = 0; base < bytes.length; base += 16) {
    const slice = Array.from(bytes.slice(base, base + 16))
    rows.push({
      offset: base.toString(16).padStart(4, '0'),
      hex: slice.map(hexByte).join(' '),
      ascii: slice.map((value) => (value >= 32 && value <= 126 ? String.fromCharCode(value) : '.')).join(''),
    })
  }
  return rows
}

/** Plain-text dump for the copy button. */
export function hexDumpText(bytes: Uint8Array): string {
  return hexRows(bytes)
    .map((row) => `${row.offset}  ${row.hex.padEnd(47, ' ')}  ${row.ascii}`)
    .join('\n')
}
