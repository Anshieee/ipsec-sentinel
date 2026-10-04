import { CircleHelp } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Tooltip } from '@/components/ui/Tooltip'
import { ConfidenceBar } from '@/components/ui/ConfidenceBar'
import { ProvenanceBadge } from '@/components/ui/ProvenanceBadge'
import { NoIpsecBanner } from '@/components/ui/NoIpsecBanner'
import { RiskGauge } from './RiskGauge'
import { useSentinel, useDerived } from '@/store/useSentinel'
import { fmtDuration, fmtInt, fmtPct } from '@/lib/format'
import { confidenceTone, TONE_TEXT } from '@/lib/severity'
import type { AnalysisResult, Param } from '@/types/analysis'

function ModeBadge({ label, param }: { label: string; param: Param<unknown> }) {
  const unobserved = param.status === 'UNKNOWN' || param.status === 'NOT_OBSERVED' || param.status === 'NOT_APPLICABLE'
  return (
    <span
      className="inline-flex items-center gap-1 rounded-full border border-border bg-bg-card px-2 py-1 text-xs text-text-primary"
      title={unobserved ? (param.note ?? 'Not observed in this capture.') : undefined}
    >
      {unobserved ? 'not observed' : label}
      <ProvenanceBadge provenance={param.provenance} iconOnly />
      {param.provenance === 'inferred' ? (
        <span className="tnum text-2xs text-text-secondary">{fmtPct(param.confidence)}</span>
      ) : null}
    </span>
  )
}

function MiniStat({ label, value }: { label: string; value: string }) {
  return (
    <div>
      <dt className="text-[11px] text-text-secondary">{label}</dt>
      <dd className="tnum text-sm font-semibold text-text-primary">{value}</dd>
    </div>
  )
}

/** KPI bar: risk gauge (backend headline when mapped), detected mode, AI confidence, capture volume. */
export function KpiBar({ analysis }: { analysis: AnalysisResult }) {
  const derived = useDerived()
  const previousRiskScore = useSentinel((s) => s.previousRiskScore)
  // Live mode: uploads are unrelated captures — a "since previous"
  // delta would compare apples to oranges. Mock only.
  const liveMode = useSentinel((s) => s.settings.dataSource === 'live')
  const delta =
    !liveMode && typeof previousRiskScore === 'number' && derived.riskScore !== null && previousRiskScore !== derived.riskScore
      ? derived.riskScore - previousRiskScore
      : null

  const esp = analysis.summary.ahPackets > 0 ? 'AH' : 'ESP'
  const confidence = analysis.overallConfidence
  const tone = TONE_TEXT[confidenceTone(confidence)]
  const withheld = derived.backendHeadline && derived.scoreStatus === 'WITHHELD'
  const noIpsec = derived.backendHeadline && !derived.ipsecDetected
  // Backend responses carry packet counts (n_ike/n_esp), not handshake or
  // stream counts: label them as packets. Fixtures keep their spec labels.
  const backendCounts = analysis.posture !== undefined
  const ikeLabel = backendCounts ? 'IKE packets' : 'IKE handshakes'
  const espLabel = backendCounts ? 'ESP packets' : 'ESP streams'

  return (
    <div className="grid grid-cols-1 gap-4 sm:grid-cols-2 xl:grid-cols-4" data-testid="kpi-bar">
      {noIpsec ? (
        <div className="sm:col-span-2 xl:col-span-4">
          <NoIpsecBanner />
        </div>
      ) : null}
      <Card>
        <CardHeader title="Global Risk Score" />
        {noIpsec ? (
          <p className="text-sm text-text-primary" data-testid="kpi-no-ipsec">
            No IPsec detected in this capture — no score.
          </p>
        ) : withheld ? (
          <p className="text-sm text-text-primary" data-testid="kpi-withheld">
            Score withheld: insufficient evidence (coverage {fmtPct(derived.coverage ?? 0)}). Confirmed findings
            below still apply.
          </p>
        ) : derived.riskScore === null ? null : (
          <>
            <RiskGauge score={derived.riskScore} band={derived.band} delta={delta} />
            {derived.backendHeadline && derived.coverage !== null ? (
              <p className="mt-1 text-[11px] text-text-secondary" data-testid="kpi-coverage">
                Coverage {fmtPct(derived.coverage)} · rule {analysis.posture?.ruleVersion ?? 'n/a'}
              </p>
            ) : null}
          </>
        )}
      </Card>

      <Card data-testid="kpi-mode">
        <CardHeader title="Detected mode" />
        {noIpsec ? (
          <p className="text-[12px] text-text-secondary">Not applicable — no IPsec detected.</p>
        ) : (
          <div className="flex flex-wrap gap-2">
            <ModeBadge label={analysis.protocol.ikeVersion.value} param={analysis.protocol.ikeVersion} />
            <ModeBadge
              label={analysis.protocol.mode.value === 'tunnel' ? 'Tunnel Mode' : 'Transport Mode'}
              param={analysis.protocol.mode}
            />
            <ModeBadge label={esp} param={{ value: esp, provenance: 'observed', confidence: 1 }} />
          </div>
        )}
        {noIpsec ? null : (
          <p className="mt-3 text-[11px] text-text-secondary">{analysis.protocol.exchangeMode.value}</p>
        )}
      </Card>

      {noIpsec ? null : (
        <Card data-testid="kpi-confidence">
          <CardHeader
            title="AI Confidence"
            description="Overall AI confidence (calibrated probability)"
            actions={
              <Tooltip content="Mean of inferred-parameter confidences weighted by parameter importance.">
                <span className="inline-flex text-text-secondary" tabIndex={0} aria-label="How confidence is aggregated">
                  <CircleHelp size={14} aria-hidden="true" />
                </span>
              </Tooltip>
            }
          />
          <p className="tnum text-kpi font-semibold text-text-primary">{fmtPct(confidence)}</p>
          <ConfidenceBar value={confidence} showValue={false} ariaLabel="Overall AI confidence" className="mt-2" />
          <p className={`mt-1 text-[11px] ${tone}`}>
            {confidence >= 0.85 ? 'Strong estimate' : confidence >= 0.7 ? 'Moderate estimate' : 'Weak estimate'}
          </p>
        </Card>
      )}

      <Card data-testid="kpi-volume">
        <CardHeader title="Capture volume" />
        <dl className="grid grid-cols-2 gap-x-4 gap-y-3">
          <MiniStat label="Packets" value={fmtInt(analysis.summary.packets)} />
          <MiniStat label={ikeLabel} value={fmtInt(analysis.summary.ikeHandshakes)} />
          <MiniStat label={espLabel} value={fmtInt(analysis.summary.espStreams)} />
          <MiniStat label="Duration" value={fmtDuration(analysis.summary.durationSec)} />
        </dl>
      </Card>
    </div>
  )
}
