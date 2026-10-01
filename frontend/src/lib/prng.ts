/** Deterministic PRNG utilities. `Math.random()` is forbidden in `src/lib` and `src/api`. */

export function mulberry32(a: number) {
  return () => {
    a |= 0
    a = (a + 0x6d2b79f5) | 0
    let t = Math.imul(a ^ (a >>> 15), 1 | a)
    t = (t + Math.imul(t ^ (t >>> 7), 61 | t)) ^ t
    return ((t ^ (t >>> 14)) >>> 0) / 4294967296
  }
}

export function hashString(s: string): number {
  let h = 2166136261
  for (let i = 0; i < s.length; i++) {
    h ^= s.charCodeAt(i)
    h = Math.imul(h, 16777619)
  }
  return h >>> 0
}

/** Fixture seeds (spec 8.4). */
export const FIXTURE_SEEDS = { A: 0xa11ce, B: 0xb0b, C: 0xc0ffee } as const

/** Hex string of `length` characters drawn from the PRNG. */
export function hexFromRng(rng: () => number, length: number): string {
  const chars = '0123456789abcdef'
  let out = ''
  for (let i = 0; i < length; i++) {
    out += chars[Math.floor(rng() * 16)]
  }
  return out
}

/** Integer in [min, max] inclusive. */
export function randInt(rng: () => number, min: number, max: number): number {
  return min + Math.floor(rng() * (max - min + 1))
}

/** Float in [min, max). */
export function randInRange(rng: () => number, min: number, max: number): number {
  return min + rng() * (max - min)
}
