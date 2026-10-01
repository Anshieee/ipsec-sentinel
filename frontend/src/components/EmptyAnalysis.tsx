import { useState } from 'react'
import { Play, Upload } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/States'
import { Popover } from '@/components/ui/Popover'
import { useSentinel } from '@/store/useSentinel'
import { openFilePicker } from '@/lib/filePicker'
import { cloneFixture } from '@/api/fixtures'
import type { FixtureId } from '@/api/fixtures'

export interface EmptyAnalysisProps {
  /** Extra card styling hook for the page that embeds it. */
  className?: string
}

const FIXTURE_LABEL: Record<FixtureId, string> = {
  A: 'Fixture A — strong (9)',
  B: 'Fixture B — typical (78)',
  C: 'Fixture C — weak (94)',
}

/**
 * The single empty state shared by Overview, Inspector, Inferences, Audit and
 * Compliance (spec 13 and 15, copy deck verbatim).
 */
export function EmptyAnalysis({ className }: EmptyAnalysisProps) {
  const start = useSentinel((s) => s.start)
  const setAnalysis = useSentinel((s) => s.setAnalysis)
  const defaultSource = useSentinel((s) => s.settings.defaultSource)
  const [menuOpen, setMenuOpen] = useState(false)

  const loadFixture = (id: FixtureId): void => {
    setAnalysis({ ...cloneFixture(id), source: 'upload' })
    setMenuOpen(false)
  }

  const actions = (
    <>
      <Button variant="primary" onClick={openFilePicker}>
        <Upload size={14} aria-hidden="true" />
        Upload a trace
      </Button>
      <Button variant="secondary" onClick={() => start(defaultSource)}>
        <Play size={14} aria-hidden="true" />
        Start live capture
      </Button>
      {import.meta.env.DEV ? (
        <Popover
          open={menuOpen}
          onOpenChange={setMenuOpen}
          label="Load sample analysis"
          trigger={
            <Button variant="ghost" size="sm">
              Load sample analysis
            </Button>
          }
        >
          <div className="flex flex-col gap-1" role="menu" aria-label="Sample fixtures">
            {(['A', 'B', 'C'] as FixtureId[]).map((id) => (
              <button
                key={id}
                type="button"
                role="menuitem"
                className="rounded-control px-2 py-1.5 text-left text-xs text-ink hover:bg-raised"
                onClick={() => loadFixture(id)}
              >
                {FIXTURE_LABEL[id]}
              </button>
            ))}
          </div>
        </Popover>
      ) : null}
    </>
  )

  return (
    <EmptyState
      title="No analysis loaded"
      body="Upload a .pcap or .pcapng trace, or start a simulated live capture, to generate a security posture assessment."
      actions={actions}
      className={className}
      testId="empty-analysis"
    />
  )
}
