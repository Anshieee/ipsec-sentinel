import { useEffect, useRef } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import { createPortal } from 'react-dom'
import { AnimatePresence, motion, useReducedMotion } from 'framer-motion'
import { X } from 'lucide-react'
import { IconButton } from './IconButton'
import { cn } from './cn'

const FOCUSABLE =
  'a[href], button:not([disabled]), textarea:not([disabled]), input:not([disabled]), select:not([disabled]), [tabindex]:not([tabindex="-1"])'

export interface DrawerProps {
  open: boolean
  onClose: () => void
  title: string
  description?: string
  children: ReactNode
  footer?: ReactNode
  testId?: string
  className?: string
}

/**
 * Right-side drawer: focus trap, Escape closes, `aria-modal`, focus restored
 * to the element that opened it.
 */
export function Drawer({ open, onClose, title, description, children, footer, testId, className }: DrawerProps) {
  const panelRef = useRef<HTMLDivElement | null>(null)
  const previouslyFocused = useRef<HTMLElement | null>(null)
  const reduceMotion = useReducedMotion()

  useEffect(() => {
    if (!open) return undefined
    previouslyFocused.current = document.activeElement instanceof HTMLElement ? document.activeElement : null
    const panel = panelRef.current
    const first = panel?.querySelector<HTMLElement>(FOCUSABLE)
    ;(first ?? panel)?.focus()

    const onKeyDown = (e: globalThis.KeyboardEvent) => {
      if (e.key === 'Escape') {
        e.preventDefault()
        onClose()
        return
      }
      if (e.key !== 'Tab' || !panel) return
      const nodes = Array.from(panel.querySelectorAll<HTMLElement>(FOCUSABLE)).filter(
        (el) => el.offsetParent !== null || el === document.activeElement,
      )
      if (nodes.length === 0) {
        e.preventDefault()
        return
      }
      const firstEl = nodes[0]
      const lastEl = nodes[nodes.length - 1]
      const active = document.activeElement
      if (!e.shiftKey && active === lastEl) {
        e.preventDefault()
        firstEl.focus()
      } else if (e.shiftKey && active === firstEl) {
        e.preventDefault()
        lastEl.focus()
      }
    }

    document.addEventListener('keydown', onKeyDown)
    const overflow = document.body.style.overflow
    document.body.style.overflow = 'hidden'
    return () => {
      document.removeEventListener('keydown', onKeyDown)
      document.body.style.overflow = overflow
      previouslyFocused.current?.focus()
    }
  }, [open, onClose])

  const handlePanelKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    if (e.key === 'Escape') {
      e.stopPropagation()
      onClose()
    }
  }

  return createPortal(
    <AnimatePresence>
      {open ? (
        <div className="fixed inset-0 z-drawer flex justify-end">
          <motion.div
            className="absolute inset-0 bg-base/70 backdrop-blur-md"
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            exit={{ opacity: 0 }}
            transition={{ duration: reduceMotion ? 0 : 0.15 }}
            onClick={onClose}
            aria-hidden="true"
          />
          <motion.div
            ref={panelRef}
            role="dialog"
            aria-modal="true"
            aria-label={title}
            data-testid={testId}
            tabIndex={-1}
            onKeyDown={handlePanelKeyDown}
            className={cn(
              'relative flex h-full w-full max-w-[min(560px,calc(100vw-24px))] flex-col border-l border-line bg-surface shadow-overlay',
              className,
            )}
            initial={{ x: reduceMotion ? 0 : '100%' }}
            animate={{ x: 0 }}
            exit={{ x: reduceMotion ? 0 : '100%' }}
            transition={{ duration: reduceMotion ? 0 : 0.2, ease: 'easeOut' }}
          >
            <header className="flex items-start justify-between gap-3 border-b border-line px-4 py-3">
              <div className="min-w-0">
                <h2 className="truncate text-base font-semibold text-ink">{title}</h2>
                {description ? <p className="mt-0.5 text-xs text-muted">{description}</p> : null}
              </div>
              <IconButton label="Close drawer" onClick={onClose} size="sm">
                <X size={16} aria-hidden="true" />
              </IconButton>
            </header>
            <div className="scroll-thin flex-1 overflow-y-auto px-4 py-4">{children}</div>
            {footer ? <footer className="flex items-center justify-end gap-2 border-t border-line px-4 py-3">{footer}</footer> : null}
          </motion.div>
        </div>
      ) : null}
    </AnimatePresence>,
    document.body,
  )
}
