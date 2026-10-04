import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { PageScaffold } from './PageScaffold'
import { useAnalysis } from '@/store/useSentinel'
import { NoIpsecBanner, isNoIpsec } from '@/components/ui/NoIpsecBanner'
import { dhLabel } from '@/lib/dh'
import type { ControlStatus } from '@/types/analysis'

const STATUS_TONE: Record<ControlStatus, 'safe' | 'danger' | 'warn' | 'info' | 'neutral'> = {
  PASS: 'safe',
  FAIL: 'danger',
  LIKELY: 'warn',
  UNKNOWN: 'info',
  NOT_APPLICABLE: 'neutral',
}

/** Config Compliance: backend controls table (Live) or the DH stub (fixtures). */
export function CompliancePage() {
  const analysis = useAnalysis()
  const noIpsec = isNoIpsec(analysis)
  const controls = analysis?.controls ?? []
  const backend = analysis?.posture !== undefined && controls.length > 0
  return (
    <PageScaffold
      title="Config Compliance"
      description={
        backend
          ? 'Backend assessment controls with evidence status and resolve-by hints.'
          : 'Policy compliance table, DH key lab and the what-if configuration evaluator.'
      }
      testId="page-compliance"
    >
      {analysis ? (
        noIpsec ? (
          <NoIpsecBanner />
        ) : backend ? (
          <Card data-testid="controls-table">
            <CardHeader
              title="Assessment controls"
              description={`Rule ${analysis.posture?.ruleVersion ?? 'n/a'} · posture ${analysis.posture?.postureScore ?? 'withheld'}/100 at coverage ${analysis.posture ? Math.round(analysis.posture.coverage * 1000) / 10 : 0}%`}
            />
            <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Assessment controls">
              <table className="w-full border-collapse text-xs">
                <caption className="sr-only">Backend assessment controls with results and evidence</caption>
                <thead>
                  <tr className="bg-bg-card text-left text-text-secondary">
                    <th scope="col" className="px-3 py-2 font-medium">Rule</th>
                    <th scope="col" className="px-3 py-2 font-medium">Version</th>
                    <th scope="col" className="px-3 py-2 font-medium">Result</th>
                    <th scope="col" className="px-3 py-2 font-medium">Evidence</th>
                    <th scope="col" className="px-3 py-2 font-medium">Explanation</th>
                    <th scope="col" className="px-3 py-2 font-medium">To resolve</th>
                  </tr>
                </thead>
                <tbody>
                  {controls.map((control) => (
                    <tr key={control.id} className="border-t border-border/60 align-top">
                      <td className="px-3 py-2 font-mono text-text-primary">{control.id}</td>
                      <td className="tnum px-3 py-2 text-text-secondary">{control.ruleVersion}</td>
                      <td className="px-3 py-2">
                        <Badge tone={STATUS_TONE[control.status]}>{control.status}</Badge>
                      </td>
                      <td className="px-3 py-2 text-text-secondary">
                        {control.source}
                        {control.source === 'inferred' ? ` (${Math.round(control.confidence * 100)}%)` : ''}
                      </td>
                      <td className="px-3 py-2 text-text-primary">{control.explanation}</td>
                      <td className="px-3 py-2 text-text-secondary">{control.resolveBy ?? '—'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          </Card>
        ) : (
          <Card>
            <p className="text-sm font-semibold text-text-primary">Detected key exchange</p>
            <p className="mt-1 text-[13px] text-text-secondary">{dhLabel(analysis.protocol.ike.dhGroup.value)}</p>
          </Card>
        )
      ) : null}
    </PageScaffold>
  )
}
