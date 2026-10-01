import { Download, FileText } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Tooltip } from '@/components/ui/Tooltip'
import { useSentinel, useAnalysis } from '@/store/useSentinel'
import { usePrint } from '@/hooks/usePrint'
import { downloadText } from '@/components/report/buildMarkdown'
import { pad2 } from '@/lib/format'

/** `sentinel-<fileName>-<yyyymmdd-hhmm>.json` (spec 4.7). */
export function jsonFileName(fileName: string, now: Date = new Date()): string {
  const base = fileName.replace(/\.(pcap|pcapng)$/i, '')
  const stamp = `${now.getFullYear()}${pad2(now.getMonth() + 1)}${pad2(now.getDate())}-${pad2(now.getHours())}${pad2(now.getMinutes())}`
  return `sentinel-${base}-${stamp}.json`
}

/** Export group: Export PDF (print) and Export JSON (Blob download). */
export function ExportGroup({ inline = false, disabledReason }: { inline?: boolean; disabledReason?: string }) {
  const analysis = useAnalysis()
  const reportTab = useSentinel((s) => s.reportTab)
  const notify = useSentinel((s) => s.notify)
  const print = usePrint()

  const disabled = !analysis
  const tooltip = disabled ? (disabledReason ?? 'Run an analysis first') : undefined

  const exportJson = (): void => {
    if (!analysis) return
    downloadText(jsonFileName(analysis.fileName), JSON.stringify(analysis, null, 2), 'application/json;charset=utf-8')
    notify({ severity: 'success', message: 'Exported analysis JSON.' })
  }

  const printReport = (): void => {
    if (!analysis) return
    print(reportTab)
  }

  return (
    <div
      className={inline ? 'flex items-center gap-2' : 'hidden items-center gap-2 lg:flex'}
      data-testid="export-group"
    >
      <Tooltip content={tooltip ?? 'Open the report and print it'}>
        <Button variant="secondary" size="sm" onClick={printReport} disabled={disabled} data-testid="export-pdf">
          <FileText size={14} aria-hidden="true" />
          Export PDF
        </Button>
      </Tooltip>
      <Tooltip content={tooltip ?? 'Download the analysis as JSON'}>
        <Button variant="secondary" size="sm" onClick={exportJson} disabled={disabled} data-testid="export-json">
          <Download size={14} aria-hidden="true" />
          Export JSON
        </Button>
      </Tooltip>
    </div>
  )
}
