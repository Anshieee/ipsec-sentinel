import { PageScaffold } from './PageScaffold'
import { Card } from '@/components/ui/Card'
import { useAnalysis } from '@/store/useSentinel'
import { NoIpsecBanner, isNoIpsec } from '@/components/ui/NoIpsecBanner'
import { dhLabel } from '@/lib/dh'

/** Config Compliance & DH Key Lab (`/compliance`). Populated in phase P10. */
export function CompliancePage() {
  const analysis = useAnalysis()
  const noIpsec = isNoIpsec(analysis)
  return (
    <PageScaffold
      title="Config Compliance"
      description="Policy compliance table, DH key lab and the what-if configuration evaluator."
      testId="page-compliance"
    >
      {analysis ? (
        noIpsec ? (
          <NoIpsecBanner />
        ) : (
          <Card>
            <p className="text-sm font-semibold text-ink">Detected key exchange</p>
            <p className="mt-1 text-[13px] text-muted">{dhLabel(analysis.protocol.ike.dhGroup.value)}</p>
          </Card>
        )
      ) : null}
    </PageScaffold>
  )
}
