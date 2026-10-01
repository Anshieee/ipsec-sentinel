import { useEffect, useState, type ReactNode } from 'react'
import { createPortal } from 'react-dom'

export interface PrintPortalProps {
  /** true while the report drawer is open or a print job is running. */
  active: boolean
  /** Print-only report document. */
  children?: ReactNode
}

/**
 * Renders the active report into a `div#print-root` appended to document.body
 * (outside `#root`) only while printing or while the drawer is open (spec 12).
 * The screen hides it, `@media print` hides `#root` and shows it instead.
 */
export function PrintPortal({ active, children }: PrintPortalProps) {
  const [mounted, setMounted] = useState(false)

  useEffect(() => {
    setMounted(true)
  }, [])

  useEffect(() => {
    if (!active) return undefined
    document.documentElement.classList.add('print-report-active')
    return () => {
      document.documentElement.classList.remove('print-report-active')
    }
  }, [active])

  if (!mounted) return null
  return createPortal(<div id="print-root" data-testid="print-root">{children}</div>, document.body)
}
