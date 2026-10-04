import { useEffect, useState } from 'react'
import { Download, Printer, X } from 'lucide-react'
import { Drawer } from '@/components/ui/Drawer'
import { Tabs, tabPanelProps } from '@/components/ui/Tabs'
import { Button } from '@/components/ui/Button'
import { EmptyState } from '@/components/ui/States'
import { ReportView } from './ReportView'
import { buildReportMarkdown, downloadText, reportFileName } from './buildMarkdown'
import { useSentinel, useAnalysis } from '@/store/useSentinel'
import { usePrint } from '@/hooks/usePrint'
import type { ReportTab } from '@/store/slices/uiSlice'

export interface ReportDrawerProps {
  open: boolean
  onClose: () => void
}

const TAB_ITEMS = [
  { id: 'executive', label: 'Executive' },
  { id: 'technical', label: 'Technical' },
]

/**
 * Report drawer (spec 9.4): Executive/Technical tabs, `Copy Markdown`,
 * `Download .md` and `Print / Save as PDF`, rendered from `react-markdown`
 * with `remark-gfm`.
 */
export function ReportDrawer({ open, onClose }: ReportDrawerProps) {
  const analysis = useAnalysis()
  const reportTab = useSentinel((s) => s.reportTab)
  const setReportTab = useSentinel((s) => s.setReportTab)
  const notify = useSentinel((s) => s.notify)
  const print = usePrint()
  const [copied, setCopied] = useState(false)

  useEffect(() => {
    if (!open) setCopied(false)
  }, [open])

  const markdown = analysis ? buildReportMarkdown(reportTab, analysis) : ''

  const handleCopyError = (): void => {
    notify({ severity: 'warn', message: 'Clipboard unavailable in this browser.' })
  }

  const handleDownload = (): void => {
    if (!markdown) return
    downloadText(reportFileName(reportTab), markdown)
    notify({ severity: 'success', message: `Downloaded ${reportFileName(reportTab)}` })
  }

  return (
    <Drawer
      open={open}
      onClose={onClose}
      title="Report"
      description="Generated from the rule engine output and the model inference."
      testId="report-drawer"
      footer={
        <>
          <Button variant="ghost" onClick={onClose}>
            <X size={14} aria-hidden="true" />
            Close report
          </Button>
          <Button variant="secondary" onClick={handleDownload} disabled={!markdown}>
            <Download size={14} aria-hidden="true" />
            Download .md
          </Button>
          <Button variant="secondary" onClick={() => print(reportTab)} disabled={!markdown}>
            <Printer size={14} aria-hidden="true" />
            Print / Save as PDF
          </Button>
        </>
      }
    >
      <Tabs
        items={TAB_ITEMS}
        value={reportTab}
        onChange={(id) => setReportTab(id as ReportTab)}
        ariaLabel="Report type"
        idPrefix="report"
        className="mb-3"
      />
      {analysis && markdown ? (
        <div {...tabPanelProps('report', reportTab, true)}>
          <ReportView
            markdown={markdown}
            copied={copied}
            onCopied={() => setCopied(true)}
            onError={handleCopyError}
          />
        </div>
      ) : (
        <EmptyState
          title="No analysis yet"
          body="Upload a trace or start a live capture to generate a report."
          testId="report-empty"
        />
      )}
    </Drawer>
  )
}
