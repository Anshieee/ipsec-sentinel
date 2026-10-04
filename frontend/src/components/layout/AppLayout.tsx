import { useEffect, useRef } from 'react'
import { Outlet, useLocation } from 'react-router-dom'
import { Header } from './Header'
import { Sidebar } from './Sidebar'
import { Footer } from './Footer'
import { HelpDialog } from './HelpDialog'
import { ReportDrawer } from '@/components/report/ReportDrawer'
import { PrintReport } from '@/components/report/PrintReport'
import { useSentinel } from '@/store/useSentinel'
import { useHotkeys } from '@/hooks/useHotkeys'
import { registerFileInput, openFilePicker } from '@/lib/filePicker'

const PAGE_TITLES: Record<string, string> = {
  '/': 'Overview',
  '/inspector': 'Inspector',
  '/inferences': 'Inferences',
  '/audit': 'Audit',
  '/compliance': 'Compliance',
  '/settings': 'Settings',
}

/** Application shell: header, sidebar, routed outlet, footer and overlays (spec 4). */
export function AppLayout() {
  const location = useLocation()
  const fileInputRef = useRef<HTMLInputElement | null>(null)

  const reportOpen = useSentinel((s) => s.reportOpen)
  const setReportOpen = useSentinel((s) => s.setReportOpen)
  const helpOpen = useSentinel((s) => s.helpOpen)
  const setHelpOpen = useSentinel((s) => s.setHelpOpen)
  const startUpload = useSentinel((s) => s.startUpload)
  const startLive = useSentinel((s) => s.start)
  const stopLive = useSentinel((s) => s.stop)
  const liveStatus = useSentinel((s) => s.live.status)

  useEffect(() => {
    registerFileInput(fileInputRef.current)
    return () => registerFileInput(null)
  }, [])

  useEffect(() => {
    const page = PAGE_TITLES[location.pathname] ?? 'Not found'
    document.title = `${page} | IPsec-AI Sentinel`
  }, [location.pathname])

  const focusSearch = (): void => {
    const input = document.querySelector<HTMLInputElement>('[data-testid="global-search-input"]')
    input?.focus()
  }

  useHotkeys({
    onSearch: focusSearch,
    onUpload: () => openFilePicker(),
    onToggleLive: () => {
      if (liveStatus === 'idle') startLive()
      else stopLive()
    },
    onToggleReport: () => setReportOpen(!reportOpen),
    onHelp: () => setHelpOpen(true),
    onEscape: () => {
      if (helpOpen) setHelpOpen(false)
      else if (reportOpen) setReportOpen(false)
    },
  })

  return (
    <div className="flex min-h-screen flex-col bg-bg">
      <a
        href="#main-content"
        className="sr-only z-50 rounded-control bg-blue px-3 py-2 text-white focus:not-sr-only focus:absolute focus:left-3 focus:top-3"
      >
        Skip to main content
      </a>

      <Header />
      <div className="flex flex-1">
        <Sidebar />
        <main id="main-content" tabIndex={-1} className="min-w-0 flex-1 px-6 py-6">
          <div className="mb-4 rounded-card border border-border bg-bg-card px-4 py-3 text-[13px] text-text-secondary md:hidden">
            This workbench is optimised for tablet and desktop widths.
          </div>
          <Outlet />
        </main>
      </div>
      <Footer />

      <input
        ref={fileInputRef}
        type="file"
        accept=".pcap,.pcapng"
        className="sr-only"
        aria-hidden="true"
        tabIndex={-1}
        data-testid="file-input"
        onChange={(event) => {
          const file = event.target.files?.[0]
          if (file) void startUpload(file)
          event.target.value = ''
        }}
      />

      <ReportDrawer open={reportOpen} onClose={() => setReportOpen(false)} />
      <HelpDialog />
      <PrintReport />
    </div>
  )
}
