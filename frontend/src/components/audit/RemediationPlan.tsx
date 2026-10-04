import { useMemo, useState } from 'react'
import { CheckCircle2, Circle } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { Badge } from '@/components/ui/Badge'
import { cn } from '@/components/ui/cn'
import { fmtInt } from '@/lib/format'
import { severityRank } from '@/lib/severity'
import { computeRiskScore } from '@/lib/risk'
import type { Finding, Severity } from '@/types/analysis'

export type RemediationGroup = 'Immediate (critical)' | 'Short term (high)' | 'Planned (medium and low)'

export const REMEDIATION_GROUPS: RemediationGroup[] = [
  'Immediate (critical)',
  'Short term (high)',
  'Planned (medium and low)',
]

export function remediationGroup(severity: Severity): RemediationGroup {
  if (severity === 'critical') return 'Immediate (critical)'
  if (severity === 'high') return 'Short term (high)'
  return 'Planned (medium and low)'
}

/** Findings in remediation order: group order, then severity rank, then rule id. */
export function orderRemediation(findings: Finding[]): Finding[] {
  return [...findings].sort((a, b) => {
    const groupDelta =
      REMEDIATION_GROUPS.indexOf(remediationGroup(a.severity)) -
      REMEDIATION_GROUPS.indexOf(remediationGroup(b.severity))
    if (groupDelta !== 0) return groupDelta
    const rank = severityRank(a.severity) - severityRank(b.severity)
    if (rank !== 0) return rank
    return a.ruleId.localeCompare(b.ruleId)
  })
}

export interface RemediationPlanProps {
  findings: Finding[]
  /** Current risk score, shown for comparison; null when WITHHELD. */
  currentScore: number | null
  /** Backend-mapped result: projections use client weights and are hidden. */
  backend?: boolean
}

/**
 * Remediation checklist grouped by urgency with a progress bar and the
 * projected risk score over unticked findings (spec 10.4 item 7).
 * Ticked state is local in-memory state only.
 */
export function RemediationPlan({ findings, currentScore, backend }: RemediationPlanProps) {
  const [ticked, setTicked] = useState<Set<string>>(() => new Set())
  const ordered = useMemo(() => orderRemediation(findings), [findings])

  const projected = useMemo(() => computeRiskScore(ordered.filter((f) => !ticked.has(f.id))), [ordered, ticked])

  const completed = ordered.filter((finding) => ticked.has(finding.id)).length
  const total = ordered.length
  const percent = total === 0 ? 0 : Math.round((completed / total) * 100)

  const toggle = (id: string): void => {
    setTicked((current) => {
      const next = new Set(current)
      if (next.has(id)) next.delete(id)
      else next.add(id)
      return next
    })
  }

  if (total === 0) {
    return (
      <Card data-testid="remediation-plan">
        <CardHeader title="Remediation plan" description="No findings to remediate." />
        <p className="text-[13px] text-green">No findings. This configuration meets the baseline policy.</p>
      </Card>
    )
  }

  return (
    <Card data-testid="remediation-plan">
      <CardHeader
        title="Remediation plan"
        description="Ordered checklist built from the rule recommendations"
        actions={
          backend ? (
            <Badge tone="info" title="Client-side projections use different weights than the backend posture and are hidden for backend results.">
              projection n/a (backend score)
            </Badge>
          ) : (
            <Badge tone="info">{fmtInt(projected)} projected</Badge>
          )
        }
      />

      <div className="space-y-1.5">
        <div className="flex items-center justify-between text-[12px] text-text-secondary">
          <span data-testid="remediation-progress">
            {fmtInt(completed)} of {fmtInt(total)} completed
          </span>
          <span className="tnum">{percent}%</span>
        </div>
        <div
          role="progressbar"
          aria-valuemin={0}
          aria-valuemax={total}
          aria-valuenow={completed}
          aria-label="Remediation progress"
          className="h-2 w-full overflow-hidden rounded-full bg-border"
        >
          <div
            className="h-full rounded-full bg-blue transition-[width] duration-slow ease-out"
            style={{ width: `${percent}%` }}
          />
        </div>
      </div>

      <ol className="mt-4 space-y-4">
        {REMEDIATION_GROUPS.map((group) => {
          const items = ordered.filter((finding) => remediationGroup(finding.severity) === group)
          if (items.length === 0) return null
          return (
            <li key={group}>
              <p className="text-2xs font-semibold uppercase tracking-wide text-text-secondary" data-testid={`remediation-group-${group}`}>
                {group}
              </p>
              <ul className="mt-2 space-y-2">
                {items.map((finding) => {
                  const done = ticked.has(finding.id)
                  return (
                    <li key={finding.id}>
                      <label
                        className={cn(
                          'flex cursor-pointer items-start gap-2.5 rounded-control border p-2.5',
                          done ? 'border-green/40 bg-green/10' : 'border-border bg-bg-card/40 hover:bg-bg-card',
                        )}
                      >
                        <input
                          type="checkbox"
                          checked={done}
                          data-testid={`remediation-check-${finding.ruleId}`}
                          onChange={() => toggle(finding.id)}
                          className="mt-0.5 h-4 w-4 shrink-0 accent-blue"
                        />
                        {done ? (
                          <CheckCircle2 size={16} className="mt-0.5 shrink-0 text-green" aria-hidden="true" />
                        ) : (
                          <Circle size={16} className="mt-0.5 shrink-0 text-text-secondary" aria-hidden="true" />
                        )}
                        <span className="min-w-0 flex-1">
                          <span className="flex flex-wrap items-center gap-2">
                            <SeverityBadge severity={finding.severity} />
                            <span className="font-mono text-[11px] text-text-secondary">{finding.ruleId}</span>
                            <span className="text-[13px] font-medium text-text-primary">{finding.title}</span>
                          </span>
                          <span className={cn('mt-1 block text-[13px] leading-5', done ? 'text-text-secondary line-through' : 'text-text-primary')}>
                            {finding.recommendation}
                          </span>
                        </span>
                      </label>
                    </li>
                  )
                })}
              </ul>
            </li>
          )
        })}
      </ol>

      <div className="mt-4 flex flex-wrap items-center justify-between gap-3 border-t border-border pt-3">
        <p className="text-[13px] text-text-secondary">
          Current risk score:{' '}
          <span className="tnum font-semibold text-text-primary">
            {currentScore === null ? 'withheld (insufficient evidence)' : fmtInt(currentScore)}
          </span>
          {backend ? (
            <span> · projections use client weights and are hidden for backend results.</span>
          ) : (
            <>
              {' · '}
              <span data-testid="projected-score">
                Projected risk score: <span className="tnum font-semibold text-text-primary">{fmtInt(projected)}</span>
              </span>
            </>
          )}
        </p>
        <Button variant="ghost" size="sm" disabled={ticked.size === 0} onClick={() => setTicked(new Set())}>
          Reset ticks
        </Button>
      </div>
    </Card>
  )
}
