import { CircleHelp } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Tooltip } from '@/components/ui/Tooltip'
import { ConfidenceBar } from '@/components/ui/ConfidenceBar'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { RiskGauge } from './RiskGauge'
import { useSentinel, useDerived } from '@/store/useSentinel'
import { fmtDuration, fmtInt, fmtPct } from '@/lib/format'
import { confidenceTone, TONE_TEXT } from '@/lib/severity'
import type { AnalysisResult, Param } from '@/types/analysis'

function ModeBadge({ label, param }: { label: string; param: Param<unknown> }) {
  return (
    <span className="inline-flex items-center gap-1 rounded-full border border-line bg-raised px-2 py-1 text-xs text-ink">
      {label}
      <ProvenanceBadge provenance={param.provenance} iconOnly />
      {param.provenance === 'inferred' ? (
        <span className="tnum text-2xs text-muted">{fmtPct(param.confidence)}</span>
      ) : null}
    </span>
  )
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] text-muted">{label}</dt>
      <dd className="tnum text-sm font-semibold text-ink">{value}</dd>
    </div>
  )
}

/** KPI bar: risk gauge, detected mode, AI confidence, capture volume (spec 10.1 A). */
export function KpiBar({ analysis }: { analysis: AnalysisResult }) {
  const derived = useDerived()
  const previousRiskScore = useSentinel((s) => s.previousRiskScore)
  const delta =
    typeof previousRiskScore === 'number' && previousRiskScore !== derived.riskScore
      ? derived.riskScore - previousRiskScore
      : null

  const esp = analysis.summary.ahPackets > 0 ? 'AH' : 'ESP'
  const confidence = analysis.overallConfidence
  const tone = TONE_TEXT[confidenceTone(confidence)]

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4" data-testid="kpi-bar">
      <Card>
        <CardHeader title="Global Risk Score" />
        <RiskGauge score={derived.riskScore} band={derived.band} delta={delta} />
      </Card>

      <Card data-testid="kpi-mode">
        <CardHeader title="Detected mode" />
        <div className="flex flex-wrap gap-2">
          <ModeBadge label={analysis.protocol.ikeVersion.value} param={analysis.protocol.ikeVersion} />
          <ModeBadge
            label={analysis.protocol.mode.value === 'tunnel' ? 'Tunnel Mode' : 'Transport Mode'}
            param={analysis.protocol.mode}
          />
          <ModeBadge label={esp} param={{ value: esp, provenance: 'observed', confidence: 1 }} />
        </div>
        <p className="mt-3 text-[11px] text-muted">{analysis.protocol.exchangeMode.value}</p>
      </Card>

      <Card data-testid="kpi-confidence">
        <CardHeader
          title="AI Confidence"
          description="Overall AI confidence (calibrated probability)"
          actions={
            <Tooltip content="Mean of inferred-parameter confidences weighted by parameter importance.">
              <span className="inline-flex text-muted" tabIndex={0} aria-label="How confidence is aggregated">
                <CircleHelp size={14} aria-hidden="true" />
              </span>
            </Tooltip>
          }
        />
        <p className="tnum text-kpi font-semibold text-ink">{fmtPct(confidence)}</p>
        <ConfidenceBar value={confidence} showValue={false} ariaLabel="Overall AI confidence" className="mt-2" />
        <p className={`mt-1 text-[11px] ${tone}`}>
          {confidence >= 0.85 ? 'Strong estimate' : confidence >= 0.7 ? 'Moderate estimate' : 'Weak estimate'}
        </p>
      </Card>

      <Card data-testid="kpi-volume">
        <CardHeader title="Capture volume" />
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <MiniStat label="Packets" value={fmtInt(analysis.summary.packets)} />
          <MiniStat label="IKE handshakes" value={fmtInt(analysis.summary.ikeHandshakes)} />
          <MiniStat label="ESP streams" value={fmtInt(analysis.summary.espStreams)} />
          <MiniStat label="Duration" value={fmtDuration(analysis.summary.durationSec)} />
        </dl>
      </Card>
    </div>
  )
}
