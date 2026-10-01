import { useEffect, useRef } from 'react'
import type { KeyboardEvent, MouseEvent, ReactNode } from 'react'
import { cn } from './cn'

export interface PopoverProps {
  open: boolean
  onOpenChange: (open: boolean) => void
  /** Accessible name for the popover surface. */
  label: string
  /** The control that toggles the popover. */
  trigger: ReactNode
  children: ReactNode
  align?: 'start' | 'end'
  className?: string
  triggerClassName?: string
}

/** Lightweight anchored surface: Escape and outside clicks close it. */
export function Popover({
  open,
  onOpenChange,
  label,
  trigger,
  children,
  align = 'start',
  className,
  triggerClassName,
}: PopoverProps) {
  const wrapRef = useRef<HTMLDivElement | null>(null)
  const contentRef = useRef<HTMLDivElement | null>(null)

  useEffect(() => {
    if (!open) return undefined
    contentRef.current?.focus()
    const onDocMouseDown = (e: globalThis.MouseEvent) => {
      if (!wrapRef.current?.contains(e.target as Node)) onOpenChange(false)
    }
    const onDocKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        onOpenChange(false)
        wrapRef.current?.querySelector<HTMLElement>('button')?.focus()
      }
    }
    document.addEventListener('mousedown', onDocMouseDown)
    document.addEventListener('keydown', onDocKeyDown)
    return () => {
      document.removeEventListener('mousedown', onDocMouseDown)
      document.removeEventListener('keydown', onDocKeyDown)
    }
  }, [open, onOpenChange])

  const handleTriggerClick = (e: MouseEvent<HTMLSpanElement>) => {
    e.preventDefault()
    onOpenChange(!open)
  }

  const handleKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Enter' || e.key === ' ') {
      // Space on the trigger span toggles as well.
      if ((e.target as HTMLElement).tagName === 'SPAN') {
        e.preventDefault()
        onOpenChange(!open)
      }
    }
  }

  return (
    <div
      ref={wrapRef}
      className={cn('relative inline-flex', className)}
      onKeyDown={handleKeyDown}
    >
      <span
        role="button"
        tabIndex={0}
        aria-haspopup="dialog"
        aria-expanded={open}
        onClick={handleTriggerClick}
        className={cn('inline-flex cursor-pointer items-center', triggerClassName)}
      >
        {trigger}
      </span>
      {open ? (
        <div
          ref={contentRef}
          role="dialog"
          aria-label={label}
          tabIndex={-1}
          className={cn(
            'absolute top-full z-dropdown mt-1 min-w-[220px] rounded-card border border-line bg-surface p-2 shadow-overlay',
            align === 'end' ? 'right-0' : 'left-0',
          )}
        >
          {children}
        </div>
      ) : null}
    </div>
  )
}
