import { Card } from '@/components/ui/Card'
import { StatusChip } from '@/components/ui/StatusChip'
import { Badge } from '@/components/ui/Badge'
import { useSentinel } from '@/store/useSentinel'
import { fmtPct } from '@/lib/format'
import type { AnalysisResult, Param } from '@/types/analysis'

/** `3600` → `1 h`; falls back to seconds below one hour. */
export function fmtLifetime(seconds: number | null): string {
  if (seconds === null) return 'Unknown'
  if (seconds % 3600 === 0) return `${seconds / 3600} h`
  if (seconds % 60 === 0) return `${seconds / 60} min`
  return `${seconds} s`
}

const POLICY_MAX_SECONDS = 28_800

function unknownParam(param: Param<unknown>, minConfidence: number): boolean {
  return param.provenance === 'inferred' && param.confidence < minConfidence
}

/** Status chips row (spec 10.1 B.3). */
export function StatusChipsRow({ analysis }: { analysis: AnalysisResult }) {
  const minRuleConfidence = useSentinel((s) => s.settings.minRuleConfidence)
  const p = analysis.protocol

  const replayUnknown = unknownParam(p.child.replayProtection, minRuleConfidence)
  const childLifetimeUnknown = unknownParam(p.child.lifetimeSec, minRuleConfidence)
  const ikeLifetimeUnknown = unknownParam(p.ike.lifetimeSec, minRuleConfidence)
  const natUnknown = unknownParam(p.natTraversal, minRuleConfidence)

  const childLifetime = p.child.lifetimeSec.value
  const exceeds = childLifetime !== null && childLifetime > POLICY_MAX_SECONDS

  return (
    <Card data-testid="status-chips">
      <div className="flex flex-wrap items-center gap-2">
        {replayUnknown ? (
          <StatusChip status="unknown" label="Replay protection" />
        ) : (
          <StatusChip
            status={p.child.replayProtection.value ? 'enabled' : 'disabled'}
            label="Replay protection"
            sub={p.child.replayProtection.value ? (p.child.esn.value ? 'ESN on' : 'ESN off') : undefined}
          />
        )}

        {ikeLifetimeUnknown ? (
          <StatusChip status="unknown" label="IKE lifetime" />
        ) : (
          <StatusChip status="enabled" label="IKE lifetime" sub={fmtLifetime(p.ike.lifetimeSec.value)} />
        )}

        {childLifetimeUnknown ? (
          <StatusChip status="unknown" label="CHILD lifetime" />
        ) : (
          <StatusChip
            status={exceeds ? 'disabled' : 'enabled'}
            label="CHILD lifetime"
            sub={fmtLifetime(childLifetime)}
          >
            <Badge tone={exceeds ? 'danger' : 'safe'}>
              {exceeds ? 'Exceeds policy (max 8 h)' : 'Within policy'}
            </Badge>
          </StatusChip>
        )}

        {natUnknown ? (
          <StatusChip status="unknown" label="NAT-T" />
        ) : (
          <StatusChip
            status={p.natTraversal.value ? 'enabled' : 'disabled'}
            label="NAT-T"
            sub={p.natTraversal.value ? 'Detected' : 'Not detected'}
          />
        )}

        <span className="text-[11px] text-muted">
          Threshold {fmtPct(minRuleConfidence)}
        </span>
      </div>
    </Card>
  )
}
