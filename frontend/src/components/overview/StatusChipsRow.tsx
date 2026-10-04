import { Card } from '@/components/ui/Card'
import { StatusChip } from '@/components/ui/StatusChip'
import type { AnalysisResult, ControlStatus, Param } from '@/types/analysis'

const UNOBSERVED = ['UNKNOWN', 'NOT_OBSERVED', 'NOT_APPLICABLE']
const isUnobservedParam = (param: Param<unknown>): boolean =>
  (param.status !== undefined && UNOBSERVED.includes(param.status)) || param.value === 'unknown'

/** Chip state from a backend control status (backend-mapped results). */
function chipForControl(status: ControlStatus | undefined): 'enabled' | 'disabled' | 'neutral' | 'unknown' {
  if (status === 'PASS') return 'enabled'
  if (status === 'FAIL' || status === 'LIKELY') return 'disabled'
  return 'neutral'
}

function controlOf(analysis: AnalysisResult, id: string): { status: ControlStatus } | null {
  const found = (analysis.controls ?? []).find((c) => c.id === id)
  return found ? { status: found.status } : null
}

/** Status chips row: every chip driven by backend control/field status.
 * UNKNOWN or NOT_OBSERVED render a neutral "not observed" chip (no red x,
 * no green check, no policy text). NAT-T "Not detected" is informational
 * (neutral), never a failure. */
export function StatusChipsRow({ analysis }: { analysis: AnalysisResult }) {
  const backend = analysis.posture !== undefined
  const p = analysis.protocol

  const replayCtl = backend ? controlOf(analysis, 'replay') : null
  const lifetimeCtl = backend ? controlOf(analysis, 'lifetime') : null

  const replayUnobserved = replayCtl ? replayCtl.status === 'UNKNOWN' || replayCtl.status === 'NOT_APPLICABLE' : isUnobservedParam(p.child.replayProtection)
  const lifetimeUnobserved = lifetimeCtl
    ? lifetimeCtl.status === 'UNKNOWN' || lifetimeCtl.status === 'NOT_APPLICABLE'
    : isUnobservedParam(p.child.lifetimeSec)
  const ikeLifetimeUnobserved = isUnobservedParam(p.ike.lifetimeSec)
  const natDetected = !isUnobservedParam(p.natTraversal) && p.natTraversal.value === true

  const replayChip = replayCtl ? chipForControl(replayCtl.status) : p.child.replayProtection.value ? 'enabled' : 'disabled'
  const lifetimeChip = lifetimeCtl ? chipForControl(lifetimeCtl.status) : 'unknown'

  return (
    <Card data-testid="status-chips">
      <div className="flex flex-wrap items-center gap-2">
        {replayUnobserved ? (
          <StatusChip status="neutral" label="Replay protection" sub="not observed" />
        ) : (
          <StatusChip
            status={replayChip === 'neutral' ? 'neutral' : replayChip}
            label="Replay protection"
            sub={replayChip === 'enabled' ? 'On' : replayChip === 'disabled' ? 'Off' : 'not observed'}
          />
        )}

        {ikeLifetimeUnobserved ? (
          <StatusChip status="neutral" label="IKE lifetime" sub="not observed" />
        ) : (
          <StatusChip status="enabled" label="IKE lifetime" />
        )}

        {lifetimeUnobserved ? (
          <StatusChip status="neutral" label="CHILD lifetime" sub="not observed" />
        ) : (
          <StatusChip status={lifetimeChip === 'neutral' ? 'neutral' : lifetimeChip} label="CHILD lifetime" />
        )}

        <StatusChip status="neutral" label="NAT-T" sub={natDetected ? 'Detected' : 'Not detected'} />
      </div>
    </Card>
  )
}
