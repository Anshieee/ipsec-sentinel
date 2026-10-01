import { Card, CardHeader } from '@/components/ui/Card'
import { RiskGauge } from '@/components/overview/RiskGauge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { useDerived, useSentinel, useAnalysis } from '@/store/useSentinel'
import { fmtInt } from '@/lib/format'
import { SEVERITIES } from '@/lib/severity'

/** Score derivation sentence from the rule weights (spec 10.4 item 1). */
export function scoreDerivation(): string {
  return '25 x critical + 12 x high + 5 x medium + 2 x low, capped at 100'
}

/** Audit header summary: gauge, band, severity counts and score derivation. */
export function AuditSummary() {
  const derived = useDerived()
  const previousRiskScore = useSentinel((s) => s.previousRiskScore)
  const backend = useAnalysis()?.backendAssessment
  const delta =
    typeof previousRiskScore === 'number' && previousRiskScore !== derived.riskScore
      ? derived.riskScore - previousRiskScore
      : null

  return (
    <Card data-testid="audit-summary">
      <CardHeader title="Security audit summary" description="Findings from the baseline policy rule engine" />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        <RiskGauge score={derived.riskScore} band={derived.band} delta={delta} />
        <div>
          <dl className="grid grid-cols-2 gap-3">
            {SEVERITIES.map((severity) => (
              <div key={severity} className="rounded-control border border-line bg-raised/50 p-2">
                <dt className="flex items-center gap-1.5 text-[11px] text-muted">
                  <SeverityBadge severity={severity} />
                </dt>
                <dd className="tnum mt-1 text-lg font-semibold text-ink">
                  {fmtInt(derived.severityCounts[severity])}
                </dd>
              </div>
            ))}
          </dl>
          <p className="mt-3 text-[12px] leading-5 text-muted" data-testid="score-derivation">
            Score derivation: <span className="text-ink">{scoreDerivation()}</span>
          </p>
          {backend ? (
            <p className="mt-1 text-[12px] leading-5 text-muted" data-testid="backend-assessment">
              Backend assessment:{' '}
              <span className="tnum text-ink">
                Security {backend.securityScore}/100 · Risk {backend.riskScore} ({backend.riskLevel})
              </span>
            </p>
          ) : null}
        </div>
      </div>
    </Card>
  )
}
