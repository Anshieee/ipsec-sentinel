import { useMemo } from 'react'
import { useSentinel } from '@/store/useSentinel'
import { PrintPortal } from './PrintPortal'
import { ReactMarkdown, markdownComponents, remarkGfm } from './markdown'
import { buildReportMarkdown } from './buildMarkdown'

/**
 * Renders the active report Markdown into `#print-root` while the drawer is
 * open or a print job is in flight. On screen the portal is hidden by CSS; in
 * `@media print` the screen app is hidden and only this document prints.
 */
export function PrintReport() {
  const reportOpen = useSentinel((s) => s.reportOpen)
  const reportTab = useSentinel((s) => s.reportTab)
  const printJob = useSentinel((s) => s.printJob)
  const analysis = useSentinel((s) => s.current)

  const active = (reportOpen || printJob.active) && Boolean(analysis || printJob.markdown)
  const markdown = useMemo(() => {
    if (printJob.active && printJob.markdown) return printJob.markdown
    if (analysis) return buildReportMarkdown(reportTab, analysis)
    return ''
  }, [analysis, printJob.active, printJob.markdown, reportTab])

  if (!active || markdown.length === 0) return <PrintPortal active={false} />

  return (
    <PrintPortal active>
      <article className="print-report" data-testid="print-report">
        <ReactMarkdown remarkPlugins={[remarkGfm]} components={markdownComponents}>
          {markdown}
        </ReactMarkdown>
      </article>
    </PrintPortal>
  )
}
