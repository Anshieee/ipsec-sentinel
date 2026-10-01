import { useState } from 'react'
import { ChevronDown, Radio } from 'lucide-react'
import { Popover } from '@/components/ui/Popover'
import { Kbd } from '@/components/ui/Kbd'
import { Badge } from '@/components/ui/Badge'
import { cn } from '@/components/ui/cn'
import { useSentinel } from '@/store/useSentinel'
import { useReducedMotionSafe } from '@/hooks/useReducedMotionSafe'
import { pad2 } from '@/lib/format'

const SOURCE_LABEL: Record<'A' | 'B' | 'C', string> = {
  A: 'Fixture A',
  B: 'Fixture B',
  C: 'Fixture C',
}

/** `mm:ss` elapsed formatter for the live pill. */
function elapsedClock(totalSeconds: number): string {
  const seconds = Math.max(0, Math.floor(totalSeconds))
  return `${pad2(Math.floor(seconds / 60))}:${pad2(seconds % 60)}`
}

/**
 * Monitor status pill (spec 4.2 item 3): toggles the simulated live capture;
 * the chevron opens a popover to pick source and speed (disabled while capturing).
 */
export function MonitorPill() {
  const live = useSentinel((s) => s.live)
  const start = useSentinel((s) => s.start)
  const stop = useSentinel((s) => s.stop)
  const setLiveOptions = useSentinel((s) => s.setLiveOptions)
  const liveMode = useSentinel((s) => s.settings.dataSource) === 'live'
  const reducedMotion = useReducedMotionSafe()
  const [menuOpen, setMenuOpen] = useState(false)

  const capturing = live.status === 'capturing' || live.status === 'connecting' || live.status === 'stopping'
  const active = live.status === 'capturing'

  const toggle = (): void => {
    if (capturing) stop()
    else start()
  }

  return (
    <div className="inline-flex items-center rounded-control border border-line bg-raised">
      <button
        type="button"
        onClick={toggle}
        data-testid="monitor-pill"
        aria-pressed={active}
        className="inline-flex h-8 items-center gap-2 px-2.5 text-xs font-medium text-ink hover:bg-surface"
      >
        <span
          className={cn(
            'inline-block size-2 rounded-full',
            active ? 'bg-highlight' : 'bg-muted',
            active && !reducedMotion ? 'animate-pulse' : '',
          )}
          aria-hidden="true"
        />
        <Radio size={14} aria-hidden="true" />
        {active ? (
          <span data-testid="monitor-active">
            Active Capture <span className="tnum text-muted">{elapsedClock(live.elapsedSec)}</span>
          </span>
        ) : (
          <span data-testid="monitor-idle">Live Monitoring: Idle</span>
        )}
        {liveMode ? (
          <Badge tone="warn" title="The live capture stream is simulated; upload a pcap for real analysis.">
            SIMULATED
          </Badge>
        ) : null}
        <span className="sr-only">{active ? 'Stop live capture' : 'Start live capture'}</span>
      </button>
      <Popover
        open={menuOpen}
        onOpenChange={setMenuOpen}
        label="Live capture source"
        align="start"
        trigger={
          <span
            className={cn(
              'flex h-8 items-center border-l border-line px-2 text-muted hover:text-ink',
              capturing ? 'cursor-not-allowed opacity-50' : '',
            )}
            aria-disabled={capturing}
            title={capturing ? 'Stop the capture to change the source' : 'Choose simulated source'}
          >
            <ChevronDown size={14} aria-hidden="true" />
            <span className="sr-only">Choose simulated source</span>
          </span>
        }
      >
        <div className="w-52 space-y-2 text-xs">
          <p className="text-[11px] font-semibold uppercase tracking-wide text-muted">Simulated source</p>
          <div role="radiogroup" aria-label="Simulated source" className="flex flex-col gap-1">
            {(['A', 'B', 'C'] as const).map((id) => (
              <button
                key={id}
                type="button"
                role="radio"
                aria-checked={live.sourceId === id}
                disabled={capturing}
                onClick={() => setLiveOptions({ sourceId: id })}
                className={cn(
                  'rounded-control px-2 py-1.5 text-left',
                  live.sourceId === id ? 'bg-surface text-ink' : 'text-muted hover:text-ink',
                )}
              >
                {SOURCE_LABEL[id]}
              </button>
            ))}
          </div>
          <p className="text-[11px] font-semibold uppercase tracking-wide text-muted">Speed</p>
          <div role="radiogroup" aria-label="Capture speed" className="flex gap-1">
            {([1, 4] as const).map((speed) => (
              <button
                key={speed}
                type="button"
                role="radio"
                aria-checked={live.speed === speed}
                disabled={capturing}
                onClick={() => setLiveOptions({ speed })}
                className={cn(
                  'rounded-control px-2 py-1',
                  live.speed === speed ? 'bg-surface text-ink' : 'text-muted hover:text-ink',
                )}
              >
                {speed}x
              </button>
            ))}
          </div>
          <p className="pt-1 text-[11px] leading-4 text-muted">
            Toggle with <Kbd>l</Kbd> while the source menu is closed.
          </p>
        </div>
      </Popover>
    </div>
  )
}
