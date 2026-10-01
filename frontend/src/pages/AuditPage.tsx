import { useState } from 'react'
import { PageScaffold } from './PageScaffold'
import { AuditSummary } from '@/components/audit/AuditSummary'
import { ScoreWaterfall } from '@/components/audit/ScoreWaterfall'
import { CategoryRadar } from '@/components/audit/CategoryRadar'
import { FindingsTable } from '@/components/audit/FindingsTable'
import { StrideBreakdown } from '@/components/audit/StrideBreakdown'
import { RemediationPlan } from '@/components/audit/RemediationPlan'
import { ThreatMatrixCard } from '@/components/overview/ThreatMatrixCard'
import { useDerived } from '@/store/useSentinel'
import type { MatrixSelection } from '@/components/overview/ThreatMatrixCard'

/** Security Audit & Threat Matrix (`/audit`), spec 10.4. */
export function AuditPage() {
  const derived = useDerived()
  const [selection, setSelection] = useState<MatrixSelection | null>(null)

  return (
    <PageScaffold
      title="Security Audit"
      description="Findings from the rule engine, threat matrix and the remediation plan."
      testId="page-audit"
    >
      <div className="grid grid-cols-12 gap-4">
        <div className="col-span-12">
          <AuditSummary />
        </div>

        <div className="col-span-12">
          <ThreatMatrixCard matrix={derived.matrix} selection={selection} onSelect={setSelection} />
        </div>

        <div className="col-span-12 grid grid-cols-12 gap-4">
          <div className="col-span-12 lg:col-span-7">
            <ScoreWaterfall findings={derived.findings} total={derived.riskScore} />
          </div>
          <div className="col-span-12 lg:col-span-5">
            <CategoryRadar scores={derived.categoryScores} />
          </div>
        </div>

        <div className="col-span-12">
          <FindingsTable findings={derived.findings} selection={selection} />
        </div>

        <div className="col-span-12">
          <StrideBreakdown findings={derived.findings} />
        </div>

        <div className="col-span-12">
          <RemediationPlan findings={derived.findings} currentScore={derived.riskScore} />
        </div>
      </div>
    </PageScaffold>
  )
}
