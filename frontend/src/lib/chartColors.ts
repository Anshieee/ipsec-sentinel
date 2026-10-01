import type { CSSProperties } from 'react'

/**
 * Chart colour values for SVG and canvas consumers (Recharts reads inline
 * values, not Tailwind classes). Every entry mirrors a token from the table in
 * DESIGN.md — `line`, `muted`, `raised`, `ink`, and the seven-class chart
 * palette — so a chart can never drift away from the rest of the instrument.
 */
export const CHART_PALETTE = [
  '#5A9BF8', // chart-1 instrument blue
  '#41C7E8', // chart-2 cyan
  '#3FC98F', // chart-3 bluish green
  '#EBB13C', // chart-4 amber
  '#B79DF3', // chart-5 violet
  '#EE8260', // chart-6 vermillion
  '#93A3B4', // chart-7 slate
] as const

/** Hairline grid — structural, never a wireframe. */
export const CHART_GRID = '#354753' // line

/** Tick and axis labels: secondary ink, 7.5:1 on the page ground. */
export const CHART_AXIS = '#9DB0BE' // muted

/** Tooltip surface: the raised step plus a hairline ring. */
export const CHART_TOOLTIP: CSSProperties = {
  background: '#1F2A34', // raised
  border: '1px solid #354753', // line
  color: '#E7EEF3', // ink
  fontSize: 12,
}

/** Primary ink, for text that sits directly on a chart surface. */
export const CHART_INK = '#E7EEF3' // ink

/** `#RRGGBB` → `R, G, B`, for `rgba()` fills that must start from a token. */
export const rgbChannels = (hex: string): string => {
  const value = Number.parseInt(hex.slice(1), 16)
  return `${(value >> 16) & 255}, ${(value >> 8) & 255}, ${value & 255}`
}
