import { useRef, useState } from 'react'
import { Menu, PanelLeftClose, PanelLeftOpen, ShieldCheck, Upload } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { IconButton } from '@/components/ui/IconButton'
import { Popover } from '@/components/ui/Popover'
import { Tooltip } from '@/components/ui/Tooltip'
import { MonitorPill } from './MonitorPill'
import { SearchBox } from './SearchBox'
import { NotificationBell } from './NotificationBell'
import { ExportGroup } from './ExportGroup'
import { AnalystMenu } from './AnalystMenu'
import { useSentinel } from '@/store/useSentinel'
import { openFilePicker } from '@/lib/filePicker'
import { useMediaQuery } from '@/hooks/useMediaQuery'

/** Sticky 56 px application header (spec 4.2). */
export function Header() {
  const sidebarCollapsed = useSentinel((s) => s.sidebarCollapsed)
  const toggleSidebar = useSentinel((s) => s.toggleSidebar)
  const searchRef = useRef<HTMLInputElement | null>(null)
  const [overflowOpen, setOverflowOpen] = useState(false)
  const narrow = !useMediaQuery('(min-width: 1024px)', true)

  return (
    <header className="sticky top-0 z-40 flex h-header items-center gap-2 border-b border-line bg-raised px-3">
      <IconButton
        label={sidebarCollapsed ? 'Expand sidebar' : 'Collapse sidebar'}
        onClick={toggleSidebar}
        size="sm"
        className="shrink-0"
      >
        {sidebarCollapsed ? <PanelLeftOpen size={16} aria-hidden="true" /> : <PanelLeftClose size={16} aria-hidden="true" />}
      </IconButton>

      <div className="flex shrink-0 items-center gap-2">
        <span className="flex size-7 items-center justify-center rounded-control bg-accent/15 text-accent">
          <ShieldCheck size={16} aria-hidden="true" />
        </span>
        <span className="leading-tight">
          <span className="block text-sm font-semibold text-ink">IPsec-AI Sentinel</span>
          <span className="hidden text-2xs text-muted sm:block">Workbench</span>
        </span>
      </div>

      <div className="ml-1 hidden shrink-0 md:block">
        <MonitorPill />
      </div>

      <Button variant="primary" size="sm" onClick={openFilePicker} data-testid="header-upload">
        <Upload size={14} aria-hidden="true" />
        <span className="hidden lg:inline">Upload .pcap / .pcapng trace</span>
        <span className="lg:hidden">Upload</span>
      </Button>

      <div className="hidden min-w-0 flex-1 justify-center px-2 lg:flex">{!narrow ? <SearchBox inputRef={searchRef} /> : null}</div>

      <div className="ml-auto flex shrink-0 items-center gap-2">
        {!narrow ? <ExportGroup /> : null}

        {narrow ? (
          <Popover
            open={overflowOpen}
            onOpenChange={setOverflowOpen}
            label="Search and export"
            align="end"
            trigger={
              <span className="inline-flex" title="Search and export">
                <IconButton label="Search and export" size="sm">
                  <Menu size={16} aria-hidden="true" />
                </IconButton>
              </span>
            }
          >
            <div className="flex w-72 flex-col gap-2">
              <SearchBox />
              <ExportGroup inline disabledReason="Run an analysis first" />
            </div>
          </Popover>
        ) : null}

        <NotificationBell />

        <Tooltip content="Analyst account">
          <AnalystMenu />
        </Tooltip>
      </div>
    </header>
  )
}
