import { useEffect, useRef } from 'react'

export interface HotkeyHandlers {
  /** `/` — focus search. */
  onSearch: () => void
  /** `u` — open the file picker. */
  onUpload: () => void
  /** `l` — toggle the simulated live capture. */
  onToggleLive: () => void
  /** `r` — toggle the report drawer. */
  onToggleReport: () => void
  /** `?` — open the help dialog. */
  onHelp: () => void
  /** `Escape` — close the topmost overlay. */
  onEscape: () => void
}

/** True when the event originates from a text-entry surface. */
export function isEditableTarget(target: EventTarget | null): boolean {
  if (!(target instanceof HTMLElement)) return false
  const tag = target.tagName.toUpperCase()
  if (tag === 'INPUT' || tag === 'TEXTAREA' || tag === 'SELECT') return true
  return target.isContentEditable
}

/**
 * Single global hotkey hook (spec 4.6). Shortcuts are ignored while focus is
 * inside an input, textarea or contenteditable element.
 */
export function useHotkeys(handlers: HotkeyHandlers, enabled = true): void {
  const handlersRef = useRef(handlers)
  handlersRef.current = handlers

  useEffect(() => {
    if (!enabled) return undefined
    const onKeyDown = (event: KeyboardEvent) => {
      if (event.metaKey || event.ctrlKey || event.altKey) return
      const handlerSet = handlersRef.current
      if (event.key === 'Escape') {
        handlerSet.onEscape()
        return
      }
      if (isEditableTarget(event.target)) return
      switch (event.key) {
        case '/':
          event.preventDefault()
          handlerSet.onSearch()
          break
        case 'u':
        case 'U':
          event.preventDefault()
          handlerSet.onUpload()
          break
        case 'l':
        case 'L':
          event.preventDefault()
          handlerSet.onToggleLive()
          break
        case 'r':
        case 'R':
          event.preventDefault()
          handlerSet.onToggleReport()
          break
        case '?':
          event.preventDefault()
          handlerSet.onHelp()
          break
        default:
          break
      }
    }
    document.addEventListener('keydown', onKeyDown)
    return () => document.removeEventListener('keydown', onKeyDown)
  }, [enabled])
}
