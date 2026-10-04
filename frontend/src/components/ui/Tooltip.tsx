import { useId, useState } from 'react'
import type { FocusEvent, KeyboardEvent, MouseEvent, ReactNode } from 'react'
import { cn } from './cn'

export interface TooltipProps {
  content: ReactNode
  children: ReactNode
  className?: string
  /** Adds a tab stop when the child is not itself focusable. */
  focusable?: boolean
  side?: 'top' | 'bottom'
}

const SIDE_CLASS = {
  top: 'bottom-full mb-1.5',
  bottom: 'top-full mt-1.5',
}

/**
 * Accessible tooltip: opens on hover and on keyboard focus, closes on Escape.
 * The content is linked with `aria-describedby`.
 */
export function Tooltip({ content, children, className, focusable = false, side = 'top' }: TooltipProps) {
  const [open, setOpen] = useState(false)
  const id = useId()

  const show = () => setOpen(true)
  const hide = () => setOpen(false)

  const handleFocus = (_e: FocusEvent<HTMLSpanElement>) => show()
  const handleBlur = (_e: FocusEvent<HTMLSpanElement>) => hide()
  const handleMouseEnter = (_e: MouseEvent<HTMLSpanElement>) => show()
  const handleMouseLeave = (_e: MouseEvent<HTMLSpanElement>) => hide()
  const handleKeyDown = (e: KeyboardEvent<HTMLSpanElement>) => {
    if (e.key === 'Escape' && open) {
      e.stopPropagation()
      hide()
    }
  }

  return (
    <span
      className={cn('relative inline-flex', className)}
      tabIndex={focusable ? 0 : undefined}
      onFocus={handleFocus}
      onBlur={handleBlur}
      onMouseEnter={handleMouseEnter}
      onMouseLeave={handleMouseLeave}
      onKeyDown={handleKeyDown}
      aria-describedby={open ? id : undefined}
    >
      {children}
      {open ? (
        <span
          id={id}
          role="tooltip"
          className={cn(
            'pointer-events-none absolute left-1/2 z-tooltip w-max max-w-[260px] -translate-x-1/2 rounded-control border border-border-strong bg-bg-card px-2 py-1 text-center text-2xs leading-4 text-text-primary shadow-overlay',
            SIDE_CLASS[side],
          )}
        >
          {content}
        </span>
      ) : null}
    </span>
  )
}
