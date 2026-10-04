import { Card, CardHeader } from '@/components/ui/Card'
import { RiskGauge } from '@/components/overview/RiskGauge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { useDerived, useSentinel, useAnalysis } from '@/store/useSentinel'
import { fmtInt, fmtPct } from '@/lib/format'
import { SEVERITIES } from '@/lib/severity'

/** Score derivation sentence from the rule weights (spec 10.4 item 1). */
export function scoreDerivation(): string {
  return '25 x critical + 12 x high + 5 x medium + 2 x low, capped at 100'
}

/** Headline band sentence: numeric risk with the backend band, naming
 * the raise when CONFIRMED findings floored it. Never prints a numeric
 * band apart from the headline band. */
export function bandSentence(risk: number | null, band: string | null, findings: { severity: string; verdict?: string }[]): string | null {
  if (risk === null || band === null) return null
  const raised =
    (band === 'HIGH' && risk < 50) || (band === 'MODERATE' && risk < 25)
      ? (() => {
          const worst = findings
            .filter((f) => (f.verdict ?? 'CONFIRMED') === 'CONFIRMED')
            .map((f) => f.severity)
          if (worst.includes('critical')) return 'raised by confirmed critical finding'
          if (worst.includes('high')) return 'raised by confirmed high finding'
          return 'raised by confirmed findings'
        })()
      : null
  return raised ? `Risk ${risk} → ${band} (${raised})` : `Risk ${risk} → ${band}`
}

/** Audit header summary: backend headline (when mapped) or client rule-engine gauge, severity counts. */
export function AuditSummary() {
  const derived = useDerived()
  const previousRiskScore = useSentinel((s) => s.previousRiskScore)
  const analysis = useAnalysis()
  const backend = analysis?.posture
  const liveMode = useSentinel((s) => s.settings.dataSource === 'live')
  const delta =
    !liveMode && typeof previousRiskScore === 'number' && derived.riskScore !== null && previousRiskScore !== derived.riskScore
      ? derived.riskScore - previousRiskScore
      : null
  const withheld = derived.backendHeadline && derived.scoreStatus === 'WITHHELD'
  const noIpsec = derived.backendHeadline && !derived.ipsecDetected

  return (
    <Card data-testid="audit-summary">
      <CardHeader
        title="Security audit summary"
        description={
          derived.backendHeadline
            ? `Backend assessment (rule ${backend?.ruleVersion ?? 'n/a'}) — confirmed findings only`
            : 'Findings from the baseline policy rule engine'
        }
      />
      <div className="grid grid-cols-1 gap-4 sm:grid-cols-2">
        {noIpsec ? (
          <p className="text-sm text-ink" data-testid="audit-no-ipsec">
            No IPsec detected in this capture — nothing to score.
          </p>
        ) : withheld ? (
          <p className="text-sm text-ink" data-testid="audit-withheld">
            Score withheld: insufficient evidence (coverage {fmtPct(derived.coverage ?? 0)}). Confirmed findings
            below still apply; each unknown lists the measurement that would resolve it.
          </p>
        ) : derived.riskScore === null ? null : (
          <RiskGauge score={derived.riskScore} band={derived.band} delta={delta} />
        )}
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
          {derived.backendHeadline ? (
            <p className="mt-3 text-[12px] leading-5 text-muted" data-testid="score-derivation">
              Score derivation:{' '}
              <span className="text-ink">
                backend posture {backend?.postureScore ?? 'withheld'}/100 at coverage{' '}
                {fmtPct(derived.coverage ?? 0)} (rule {backend?.ruleVersion ?? 'n/a'})
              </span>
            </p>
          ) : (
            <p className="mt-3 text-[12px] leading-5 text-muted" data-testid="score-derivation">
              Score derivation: <span className="text-ink">{scoreDerivation()}</span>
            </p>
          )}
          {backend && derived.scoreStatus === 'PUBLISHED' ? (
            <p className="mt-1 text-[12px] leading-5 text-muted" data-testid="backend-assessment">
              Backend assessment:{' '}
              <span className="tnum text-ink">
                Posture {backend.postureScore}/100 ·{' '}
                {bandSentence(backend.riskScore, backend.riskBand, derived.findings) ?? 'Score withheld'}
                {' · '}Coverage {fmtPct(backend.coverage)}
              </span>
            </p>
          ) : null}
        </div>
      </div>
    </Card>
  )
}
