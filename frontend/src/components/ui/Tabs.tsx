import { useRef } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import type { LucideIcon } from 'lucide-react'
import { cn } from './cn'

export interface TabItem {
  id: string
  label: ReactNode
  icon?: LucideIcon
}

export interface TabsProps {
  items: TabItem[]
  value: string
  onChange: (id: string) => void
  /** Accessible name of the tablist. */
  ariaLabel: string
  /** Stable prefix used for `*-tab-*` and `*-panel-*` ids. */
  idPrefix: string
  className?: string
}

/**
 * `role="tablist"` with roving tabindex and arrow-key navigation
 * (Left/Right/Home/End). Automatic activation: focus also selects.
 */
export function Tabs({ items, value, onChange, ariaLabel, idPrefix, className }: TabsProps) {
  const baseId = idPrefix
  const refs = useRef<Record<string, HTMLButtonElement | null>>({})

  const focusIndex = (index: number) => {
    const bounded = (index + items.length) % items.length
    const item = items[bounded]
    if (!item) return
    onChange(item.id)
    refs.current[item.id]?.focus()
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const current = items.findIndex((i) => i.id === value)
    if (e.key === 'ArrowRight') {
      e.preventDefault()
      focusIndex(current + 1)
    } else if (e.key === 'ArrowLeft') {
      e.preventDefault()
      focusIndex(current - 1)
    } else if (e.key === 'Home') {
      e.preventDefault()
      focusIndex(0)
    } else if (e.key === 'End') {
      e.preventDefault()
      focusIndex(items.length - 1)
    }
  }

  return (
    <div role="tablist" aria-label={ariaLabel} onKeyDown={handleKeyDown} className={cn('flex items-center gap-1 border-b border-line', className)}>
      {items.map((item) => {
        const selected = item.id === value
        const Icon = item.icon
        return (
          <button
            key={item.id}
            type="button"
            role="tab"
            id={`${baseId}-tab-${item.id}`}
            aria-selected={selected}
            aria-controls={`${baseId}-panel-${item.id}`}
            tabIndex={selected ? 0 : -1}
            ref={(el) => {
              refs.current[item.id] = el
            }}
            onClick={() => onChange(item.id)}
            className={cn(
              'inline-flex items-center gap-1.5 px-3 py-2 text-sm transition-colors',
              'border-b-2 -mb-px focus-visible:rounded-t-control',
              selected
                ? 'border-accent font-semibold text-ink'
                : 'border-transparent font-medium text-muted hover:text-ink',
            )}
          >
            {Icon ? <Icon size={16} aria-hidden="true" /> : null}
            {item.label}
          </button>
        )
      })}
    </div>
  )
}

/** Props for the panel that belongs to a `Tabs` instance with the same `idPrefix`. */
export function tabPanelProps(baseId: string, id: string, active: boolean): {
  id: string
  role: 'tabpanel'
  'aria-labelledby': string
  hidden?: boolean
  tabIndex?: number
} {
  return {
    id: `${baseId}-panel-${id}`,
    role: 'tabpanel',
    'aria-labelledby': `${baseId}-tab-${id}`,
    ...(active ? {} : { hidden: true }),
    ...(active ? { tabIndex: 0 } : {}),
  }
}
