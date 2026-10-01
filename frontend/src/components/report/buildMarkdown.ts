import type { AnalysisResult } from '@/types/analysis'
import { buildExecutiveReport, buildTechnicalReport } from '@/lib/report'
import type { ReportTab } from '@/store/slices/uiSlice'

/** Markdown for the active report tab. */
export function buildReportMarkdown(tab: ReportTab, analysis: AnalysisResult): string {
  return tab === 'technical' ? buildTechnicalReport(analysis) : buildExecutiveReport(analysis)
}

/** `sentinel-<tab>-report-<yyyymmdd>.md` (spec 4.7 / 9.4). */
export function reportFileName(tab: ReportTab, now: Date = new Date()): string {
  const y = now.getFullYear()
  const m = `${now.getMonth() + 1}`.padStart(2, '0')
  const d = `${now.getDate()}`.padStart(2, '0')
  return `sentinel-${tab}-report-${y}${m}${d}.md`
}

/** Triggers a client-side download of `contents` without any network access. */
export function downloadText(fileName: string, contents: string, mime = 'text/markdown;charset=utf-8'): void {
  const blob = new Blob([contents], { type: mime })
  const url = URL.createObjectURL(blob)
  const link = document.createElement('a')
  link.href = url
  link.download = fileName
  document.body.appendChild(link)
  link.click()
  document.body.removeChild(link)
  URL.revokeObjectURL(url)
}
