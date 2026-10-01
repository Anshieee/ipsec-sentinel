import { useEffect, useState } from 'react'

/**
 * Reactive `window.matchMedia` listener with a server/jsdom-safe default.
 */
export function useMediaQuery(query: string, defaultValue = false): boolean {
  const [matches, setMatches] = useState(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return defaultValue
    return window.matchMedia(query).matches
  })

  useEffect(() => {
    if (typeof window === 'undefined' || typeof window.matchMedia !== 'function') return undefined
    const list = window.matchMedia(query)
    const onChange = (event: MediaQueryListEvent): void => setMatches(event.matches)
    setMatches(list.matches)
    if (typeof list.addEventListener === 'function') {
      list.addEventListener('change', onChange)
      return () => list.removeEventListener('change', onChange)
    }
    return undefined
  }, [query])

  return matches
}
