/** Formatting helpers. Pure and deterministic (no locale surprises: always en-US). */

export function fmtBytes(bytes: number): string {
  if (!Number.isFinite(bytes)) return '—'
  if (bytes < 1024) return `${bytes} B`
  const units = ['KB', 'MB', 'GB', 'TB']
  let value = bytes / 1024
  let unit = 0
  while (value >= 1024 && unit < units.length - 1) {
    value /= 1024
    unit += 1
  }
  return `${value.toFixed(value >= 100 ? 0 : 1)} ${units[unit]}`
}

/** `1h 32m 14s`, `32m 14s`, `14s`. */
export function fmtDuration(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds)) return '—'
  const total = Math.max(0, Math.floor(totalSeconds))
  const h = Math.floor(total / 3600)
  const m = Math.floor((total % 3600) / 60)
  const s = total % 60
  const parts: string[] = []
  if (h > 0) parts.push(`${h}h`)
  if (h > 0 || m > 0) parts.push(`${m}m`)
  parts.push(`${s}s`)
  return parts.join(' ')
}

/** Short duration for chips: `1 h`, `8 h`, `45 m`. */
export function fmtDurationShort(totalSeconds: number): string {
  if (!Number.isFinite(totalSeconds)) return '—'
  if (totalSeconds >= 3600 && totalSeconds % 3600 === 0) return `${totalSeconds / 3600} h`
  if (totalSeconds >= 3600) return `${(totalSeconds / 3600).toFixed(1)} h`
  if (totalSeconds >= 60) return `${Math.round(totalSeconds / 60)} m`
  return `${totalSeconds} s`
}

/** One decimal percentage from a 0..1 ratio: `96.4%`. */
export function fmtPct(ratio: number, decimals = 1): string {
  if (!Number.isFinite(ratio)) return '—'
  return `${(ratio * 100).toFixed(decimals)}%`
}

/** One decimal percentage number without the sign: `96.4`. */
export function fmtPctValue(ratio: number, decimals = 1): string {
  if (!Number.isFinite(ratio)) return '—'
  return (ratio * 100).toFixed(decimals)
}

export function fmtInt(n: number): string {
  if (!Number.isFinite(n)) return '—'
  return Math.round(n).toLocaleString('en-US')
}

export function fmtNum(n: number, decimals = 2): string {
  if (!Number.isFinite(n)) return '—'
  return n.toFixed(decimals)
}

/** Relative time such as `just now`, `4 min ago`, `2 h ago`, `3 d ago`. */
export function relTime(iso: string, nowMs: number = Date.now()): string {
  const then = Date.parse(iso)
  if (Number.isNaN(then)) return '—'
  const deltaSec = Math.max(0, Math.round((nowMs - then) / 1000))
  if (deltaSec < 5) return 'just now'
  if (deltaSec < 60) return `${deltaSec} s ago`
  const min = Math.floor(deltaSec / 60)
  if (min < 60) return `${min} min ago`
  const hours = Math.floor(min / 60)
  if (hours < 24) return `${hours} h ago`
  const days = Math.floor(hours / 24)
  return `${days} d ago`
}

/** `20260930-1425` style stamp used in export filenames. */
export function fileStamp(date: Date = new Date()): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${date.getFullYear()}${p(date.getMonth() + 1)}${p(date.getDate())}-${p(date.getHours())}${p(date.getMinutes())}`
}

/** `20260930-142530` style stamp used for live capture file names. */
export function fileStampSeconds(date: Date = new Date()): string {
  const p = (n: number) => String(n).padStart(2, '0')
  return `${fileStamp(date)}${p(date.getSeconds())}`
}

export function pad2(n: number): string {
  return String(n).padStart(2, '0')
}

/** `mm:ss` for the capture elapsed timer. */
export function fmtClock(totalSeconds: number): string {
  const total = Math.max(0, Math.floor(totalSeconds))
  return `${pad2(Math.floor(total / 60))}:${pad2(total % 60)}`
}
