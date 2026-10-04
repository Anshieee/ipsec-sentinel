import { useState } from 'react'
import { PageScaffold } from './PageScaffold'
import { AuditSummary } from '@/components/audit/AuditSummary'
import { ScoreWaterfall } from '@/components/audit/ScoreWaterfall'
import { CategoryRadar } from '@/components/audit/CategoryRadar'
import { CategoryBars } from '@/components/audit/CategoryBars'
import { FindingsTable } from '@/components/audit/FindingsTable'
import { StrideBreakdown } from '@/components/audit/StrideBreakdown'
import { RemediationPlan } from '@/components/audit/RemediationPlan'
import { ThreatMatrixCard } from '@/components/overview/ThreatMatrixCard'
import { useDerived } from '@/store/useSentinel'
import { NoIpsecBanner, isNoIpsec } from '@/components/ui/NoIpsecBanner'
import type { MatrixSelection } from '@/components/overview/ThreatMatrixCard'

/** Security Audit & Threat Matrix (`/audit`), spec 10.4. */
export function AuditPage() {
  const derived = useDerived()
  const [selection, setSelection] = useState<MatrixSelection | null>(null)
  const noIpsec = isNoIpsec(derived.analysis)

  return (
    <PageScaffold
      title="Security Audit"
      description={
        derived.backendHeadline
          ? 'Backend findings, threat matrix and the remediation plan.'
          : 'Backend findings, threat matrix and the remediation plan (fixtures use the client rule engine).'
      }
      testId="page-audit"
    >
      <div className="grid grid-cols-12 gap-4">
        {noIpsec ? (
          <div className="col-span-12">
            <NoIpsecBanner />
          </div>
        ) : null}
        <div className="col-span-12">
          <AuditSummary />
        </div>

        <div className="col-span-12">
          <ThreatMatrixCard matrix={derived.matrix} selection={selection} onSelect={setSelection} />
        </div>

        <div className="col-span-12 grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-7">
            <ScoreWaterfall
              findings={derived.findings}
              total={derived.riskScore}
              backend={derived.backendHeadline}
              ruleVersion={derived.analysis?.posture?.ruleVersion ?? null}
              controls={derived.analysis?.controls}
            />
          </div>
          <div className="col-span-12 lg:col-span-5">
            {derived.backendHeadline && derived.analysis ? (
              <CategoryBars analysis={derived.analysis} />
            ) : (
              <CategoryRadar scores={derived.categoryScores} />
            )}
          </div>
        </div>

        <div className="col-span-12">
          <FindingsTable findings={derived.findings} selection={selection} />
        </div>

        <div className="col-span-12">
          <StrideBreakdown findings={derived.findings} />
        </div>

        <div className="col-span-12">
          <RemediationPlan findings={derived.findings} currentScore={derived.riskScore} backend={derived.backendHeadline} />
        </div>
      </div>
    </PageScaffold>
  )
}
