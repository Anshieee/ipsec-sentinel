import { ShieldX } from 'lucide-react'
import type { AnalysisResult } from '@/types/analysis'

/** True when the backend reported no IPsec in this capture. */
export function isNoIpsec(analysis: AnalysisResult | null): boolean {
  if (!analysis) return false
  if (!analysis.detection) return false
  return analysis.detection.ipsecDetected === false
}

/** Consistent non-IPsec state shown on every page (spec: no score, no gauges, no classifier output). */
export function NoIpsecBanner() {
  return (
    <div
      data-testid="no-ipsec-banner"
      className="flex items-start gap-3 rounded-control border border-border bg-bg-card/50 p-4"
      role="status"
    >
      <ShieldX size={20} className="mt-0.5 shrink-0 text-text-secondary" aria-hidden="true" />
      <div>
        <p className="text-sm font-semibold text-text-primary">No IPsec detected in this capture</p>
        <p className="mt-1 text-[13px] leading-5 text-text-secondary">
          This capture contains no IKE, ESP or AH traffic, so there is nothing IPsec to score and no
          cryptographic parameters to report. Packet counts below describe the raw capture.
        </p>
      </div>
    </div>
  )
}
