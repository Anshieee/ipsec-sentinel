import { PageHeader } from '@/components/PageHeader'
import { Card, CardHeader } from '@/components/ui/Card'
import { SegmentedControl } from '@/components/ui/SegmentedControl'
import { useSentinel } from '@/store/useSentinel'
import type { DataSource } from '@/api/client'

/** Settings & AI Model Logs (`/settings`). Populated in phase P11. */
export function SettingsPage() {
  const dataSource = useSentinel((s) => s.settings.dataSource)
  const setSetting = useSentinel((s) => s.setSetting)
  return (
    <div data-testid="page-settings">
      <PageHeader
        title="Settings"
        description="Preferences, model registry, AI model logs and build information."
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
          <CardHeader title="Preferences" description="Persisted locally in this browser." />
          <p className="text-[13px] text-muted">Preference controls arrive with the settings phase.</p>
        </Card>
        <Card>
          <CardHeader title="About" description="Build and contract information." />
          <p className="text-[13px] text-muted">IPsec-AI Sentinel v0.1.0</p>
        </Card>
      </div>
    </div>
  )
}
