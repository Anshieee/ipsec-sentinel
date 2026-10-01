import { useSentinel } from '@/store/useSentinel'

/**
 * Marks a row for the 2 s accent outline: cross-links call this before the
 * router navigates, and pages scroll the matching `data-row-id` into view.
 */
export function setHighlightAndNavigate(id: string): void {
  useSentinel.getState().setHighlightId(id)
}

export function clearHighlight(): void {
  useSentinel.getState().setHighlightId(undefined)
}
