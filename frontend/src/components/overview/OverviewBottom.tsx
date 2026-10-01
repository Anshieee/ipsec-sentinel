import { useState } from 'react'
import { FileText } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { ThreatMatrixCard } from './ThreatMatrixCard'
import { FindingsList } from './FindingsList'
import { useSentinel, useDerived } from '@/store/useSentinel'
import type { MatrixSelection } from './ThreatMatrixCard'

/** Bottom row: threat matrix, findings list and the report preview button. */
export function OverviewBottom() {
  const derived = useDerived()
  const setReportOpen = useSentinel((s) => s.setReportOpen)
  const [selection, setSelection] = useState<MatrixSelection | null>(null)

  return (
    <div className="grid grid-cols-12 gap-4">
      <div className="col-span-12">
        <ThreatMatrixCard matrix={derived.matrix} selection={selection} onSelect={setSelection} />
      </div>
      <div className="col-span-12">
        <FindingsList findings={derived.findings} selection={selection} />
      </div>
      <div className="col-span-12 flex justify-end">
        <Button variant="secondary" onClick={() => setReportOpen(true)} data-testid="open-report-preview">
          <FileText size={14} aria-hidden="true" />
          Open report preview
        </Button>
      </div>
    </div>
  )
}
