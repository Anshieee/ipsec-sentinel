import type { CSSProperties } from 'react'

/**
 * Chart colour values for SVG and canvas consumers (Recharts reads inline
 * values, not Tailwind classes). Series keep distinct hues from the
 * palette (docs/theme-reference.md): blue primary, green secondary,
 * purple, orange, amber, red for errors, neutral grey last.
 */
export const CHART_PALETTE = [
  '#3888ec', // chart-1 primary blue
  '#189f70', // chart-2 green
  '#ad59fc', // chart-3 purple
  '#f08020', // chart-4 orange
  '#f8a008', // chart-5 amber
  '#ff6467', // chart-6 errors red
  '#8a8a8a', // chart-7 neutral grey
] as const

/** Hairline grid — structural, never a wireframe. */
export const CHART_GRID = '#252525' // chart-grid token

/** Tick and axis labels: secondary text. */
export const CHART_AXIS = '#a0a0a0' // text-secondary

/** Tooltip surface: nested card plus a hairline ring. */
export const CHART_TOOLTIP: CSSProperties = {
  background: '#161616', // bg-card
  border: '1px solid #292929', // border
  color: '#f5f5f5', // text-primary
  fontSize: 12,
}

/** Primary ink, for text that sits directly on a chart surface. */
export const CHART_INK = '#f5f5f5' // text-primary

/** `#RRGGBB` → `R, G, B`, for `rgba()` fills that must start from a token. */
export const rgbChannels = (hex: string): string => {
  const value = Number.parseInt(hex.slice(1), 16)
  return `${(value >> 16) & 255}, ${(value >> 8) & 255}, ${value & 255}`
}
