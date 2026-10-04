import { PageHeader } from '@/components/PageHeader'
import { Card, CardHeader } from '@/components/ui/Card'
import { SegmentedControl } from '@/components/ui/SegmentedControl'
import { useAnalysis, useSentinel } from '@/store/useSentinel'
import { APP_VERSION } from '@/lib/version'
import type { DataSource } from '@/api/client'

/** Settings & AI Model Logs (`/settings`). Populated in phase P11. */
export function SettingsPage() {
  const dataSource = useSentinel((s) => s.settings.dataSource)
  const setSetting = useSentinel((s) => s.setSetting)
  const ruleVersion = useAnalysis()?.posture?.ruleVersion ?? null
  return (
    <div data-testid="page-settings">
      <PageHeader
        title="Settings"
        description="Model registry, AI model logs and build information."
      />
      <div className="grid gap-4 lg:grid-cols-2">
        <Card>
          <CardHeader title="Data source" description="Mock uses built-in fixtures. Live calls the real analysis API." />
          <SegmentedControl<DataSource>
            value={dataSource}
            onChange={(value) => setSetting('dataSource', value)}
            ariaLabel="Data source"
            data-testid="datasource-toggle"
            options={[
              { value: 'mock', label: 'Mock' },
              { value: 'live', label: 'Live' },
            ]}
          />
          {dataSource === 'live' ? (
            <p className="mt-2 text-[12px] leading-5 text-muted">
              Live mode: uploads go to the real API. Simulated surfaces (live capture stream, model registry) carry a SIMULATED badge.
            </p>
          ) : null}
        </Card>
        <Card>
          <CardHeader title="About" description="Build and contract information." />
          <p className="text-[13px] text-muted">IPsec-AI Sentinel v{APP_VERSION}</p>
          {ruleVersion ? (
            <p className="mt-1 text-[13px] text-muted">Backend assessment rule {ruleVersion} (current analysis).</p>
          ) : null}
        </Card>
      </div>
    </div>
  )
}
