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
  neutral: 'text-muted',
  safe: 'text-safe',
  warn: 'text-warn',
  orange: 'text-orange',
  danger: 'text-danger',
  info: 'text-accent',
  cyan: 'text-highlight',
}

export const TONE_BG: Record<Tone, string> = {
  neutral: 'bg-muted',
  safe: 'bg-safe',
  warn: 'bg-warn',
  orange: 'bg-orange',
  danger: 'bg-danger',
  info: 'bg-accent',
  cyan: 'bg-highlight',
}

export const TONE_BORDER: Record<Tone, string> = {
  neutral: 'border-muted',
  safe: 'border-safe',
  warn: 'border-warn',
  orange: 'border-orange',
  danger: 'border-danger',
  info: 'border-accent',
  cyan: 'border-highlight',
}

/**
 * The same tones as literal values, for SVG and canvas consumers (Recharts
 * takes `fill`/`stroke` strings, not Tailwind classes). Each value is the token
 * its `TONE_TEXT`/`TONE_BG`/`TONE_BORDER` entry names, so a tone never splits
 * into two hues between the DOM and a chart.
 */
export const TONE_HEX: Record<Tone, string> = {
  neutral: '#9DB0BE', // muted
  safe: '#34C88F',
  warn: '#F0A63A',
  orange: '#F4763A',
  danger: '#F2665E',
  info: '#5A9BF8', // accent
  cyan: '#22C3D6', // highlight
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
