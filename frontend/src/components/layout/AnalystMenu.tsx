import { useState } from 'react'
import { useNavigate } from 'react-router-dom'
import { ChevronDown, RotateCcw, Settings, Keyboard } from 'lucide-react'
import { Popover } from '@/components/ui/Popover'
import { useSentinel } from '@/store/useSentinel'

/** Analyst menu: identity plus Settings, Keyboard shortcuts and Reset demo data. */
export function AnalystMenu() {
  const navigate = useNavigate()
  const setHelpOpen = useSentinel((s) => s.setHelpOpen)
  const resetDemoData = useSentinel((s) => s.resetDemoData)
  const notify = useSentinel((s) => s.notify)
  const [open, setOpen] = useState(false)

  const itemClass = 'flex w-full items-center gap-2 rounded-control px-2 py-1.5 text-left text-xs text-text-primary hover:bg-bg-card'

  return (
    <Popover
      open={open}
      onOpenChange={setOpen}
      label="Analyst menu"
      align="end"
      trigger={
        <button
          type="button"
          className="inline-flex h-8 items-center gap-1.5 rounded-control px-1.5 text-text-secondary hover:bg-bg-card hover:text-text-primary"
          data-testid="analyst-menu"
        >
          <span className="flex size-6 items-center justify-center rounded-full bg-blue text-2xs font-semibold text-white">
            AN
          </span>
          <span className="hidden text-left xl:block">
            <span className="block text-xs leading-3 text-text-primary">Analyst</span>
            <span className="block text-2xs leading-3 text-text-secondary">SOC Tier 2</span>
          </span>
          <ChevronDown size={14} aria-hidden="true" />
        </button>
      }
    >
      <div className="w-56">
        <p className="border-b border-border px-2 pb-2 pt-1 text-xs">
          <span className="block font-medium text-text-primary">Analyst</span>
          <span className="block text-text-secondary">SOC Tier 2</span>
        </p>
        <div className="mt-1 flex flex-col gap-0.5">
          <button
            type="button"
            className={itemClass}
            onClick={() => {
              setOpen(false)
              navigate('/settings')
            }}
          >
            <Settings size={14} aria-hidden="true" />
            Settings
          </button>
          <button
            type="button"
            className={itemClass}
            onClick={() => {
              setOpen(false)
              setHelpOpen(true)
            }}
          >
            <Keyboard size={14} aria-hidden="true" />
            Keyboard shortcuts
          </button>
          <button
            type="button"
            className={itemClass}
            data-testid="reset-demo-data"
            onClick={() => {
              setOpen(false)
              resetDemoData()
              notify({ severity: 'info', message: 'Demo data reset.' })
            }}
          >
            <RotateCcw size={14} aria-hidden="true" />
            Reset demo data
          </button>
        </div>
      </div>
    </Popover>
  )
}
