import { useCallback } from 'react'
import { useSentinel } from '@/store/useSentinel'
import type { ReportTab } from '@/store/slices/uiSlice'

/**
 * Export PDF (spec 4.7): open the report drawer on the selected tab, wait one
 * animation frame so the print document is mounted, then call `window.print()`.
 */
export function usePrint(): (tab?: ReportTab) => void {
  const setReportOpen = useSentinel((s) => s.setReportOpen)
  const setReportTab = useSentinel((s) => s.setReportTab)
  const setPrintJob = useSentinel((s) => s.setPrintJob)

  return useCallback(
    (tab?: ReportTab) => {
      if (tab) setReportTab(tab)
      setReportOpen(true)
      setPrintJob({ active: true, kind: tab ?? 'executive', markdown: '' })
      const run = (): void => {
        try {
          window.print()
        } finally {
          setPrintJob({ active: false, kind: tab ?? 'executive', markdown: '' })
        }
      }
      if (typeof requestAnimationFrame === 'function') {
        requestAnimationFrame(() => requestAnimationFrame(run))
      } else {
        setTimeout(run, 0)
      }
    },
    [setPrintJob, setReportOpen, setReportTab],
  )
}
