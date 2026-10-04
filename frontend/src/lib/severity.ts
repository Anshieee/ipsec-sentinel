import type { Severity } from '@/types/analysis'

export type Tone = 'neutral' | 'safe' | 'warn' | 'orange' | 'danger' | 'info' | 'cyan'

export const SEVERITIES: Severity[] = ['critical', 'high', 'medium', 'low']

export const SEVERITY_LABEL: Record<Severity, string> = {
  critical: 'Critical',
  high: 'High',
  medium: 'Medium',
  low: 'Low',
}

/** Severity colour mapping (spec 3.1). */
export const SEVERITY_TONE: Record<Severity, Tone> = {
  critical: 'danger',
  high: 'orange',
  medium: 'warn',
  low: 'info',
}

export const TONE_TEXT: Record<Tone, string> = {
  neutral: 'text-text-secondary',
  safe: 'text-green',
  warn: 'text-amber',
  orange: 'text-orange',
  danger: 'text-red',
  info: 'text-blue',
  cyan: 'text-blue',
}

export const TONE_BG: Record<Tone, string> = {
  neutral: 'bg-text-secondary',
  safe: 'bg-green',
  warn: 'bg-amber',
  orange: 'bg-orange',
  danger: 'bg-red',
  info: 'bg-blue',
  cyan: 'bg-blue',
}

export const TONE_BORDER: Record<Tone, string> = {
  neutral: 'border-text-secondary',
  safe: 'border-green',
  warn: 'border-amber',
  orange: 'border-orange',
  danger: 'border-red',
  info: 'border-blue',
  cyan: 'border-blue',
}

/**
 * The same tones as literal values, for SVG and canvas consumers (Recharts
 * takes `fill`/`stroke` strings, not Tailwind classes). Values follow the
 * palette (docs/theme-reference.md): severity critical/high/medium/low,
 * neutral grey for muted marks.
 */
export const TONE_HEX: Record<Tone, string> = {
  neutral: '#8a8a8a', // text-text-secondary-small
  safe: '#189f70', // green
  warn: '#f8a008', // amber
  orange: '#f08020', // orange
  danger: '#ff6467', // red
  info: '#3888ec', // blue
  cyan: '#3888ec', // folded into blue (spec keeps one blue)
}

/** Severity order used for sorting: critical first. */
export const severityRank = (s: Severity): number => SEVERITIES.indexOf(s)

export type RiskBand = 'low' | 'moderate' | 'high'

export const RISK_BAND_LABEL: Record<RiskBand, string> = {
  low: 'LOW RISK',
  moderate: 'MODERATE RISK',
  high: 'HIGH RISK',
}

export const RISK_BAND_TONE: Record<RiskBand, Tone> = {
  low: 'safe',
  moderate: 'warn',
  high: 'danger',
}

/** Confidence display bands: >= 0.85 safe, 0.7..0.85 warn, below 0.7 danger. */
export function confidenceTone(c: number): Tone {
  if (c >= 0.85) return 'safe'
  if (c >= 0.7) return 'warn'
  return 'danger'
}
