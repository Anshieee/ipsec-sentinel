import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type MutableRefObject } from 'react'
import { useNavigate } from 'react-router-dom'
import { Search } from 'lucide-react'
import { Kbd } from '@/components/ui/Kbd'
import { fieldClasses } from '@/components/ui/Field'
import { cn } from '@/components/ui/cn'
import { useSentinel, useAnalysis } from '@/store/useSentinel'
import { buildSearchIndex, searchIndex, SEARCH_GROUP_LABEL } from '@/lib/searchIndex'
import { useDebounce } from '@/hooks/useDebounce'
import type { SearchHit } from '@/lib/searchIndex'

/**
 * Global search input and grouped dropdown (spec 4.5): case-insensitive
 * substring match, 3 results per group, 9 overall, arrow keys move, Enter
 * navigates and sets `highlightId`, Esc closes.
 */
export function SearchBox({ inputRef }: { inputRef?: MutableRefObject<HTMLInputElement | null> }) {
  const navigate = useNavigate()
  const analysis = useAnalysis()
  const searchQuery = useSentinel((s) => s.searchQuery)
  const setSearchQuery = useSentinel((s) => s.setSearchQuery)
  const setHighlightId = useSentinel((s) => s.setHighlightId)
  const [open, setOpen] = useState(false)
  const [activeIndex, setActiveIndex] = useState(0)
  const localRef = useRef<HTMLInputElement | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)
  const debounced = useDebounce(searchQuery, 120)

  const index = useMemo(() => (analysis ? buildSearchIndex(analysis) : []), [analysis])
  const results = useMemo(() => searchIndex(index, debounced), [index, debounced])
  const flat = useMemo(() => results.groups.flatMap((entry) => entry.hits), [results])

  useEffect(() => {
    setActiveIndex(0)
  }, [debounced])

  useEffect(() => {
    if (!open) return undefined
    const onDocMouseDown = (event: MouseEvent): void => {
      if (!containerRef.current?.contains(event.target as Node)) setOpen(false)
    }
    document.addEventListener('mousedown', onDocMouseDown)
    return () => document.removeEventListener('mousedown', onDocMouseDown)
  }, [open])

  const go = (hit: SearchHit): void => {
    setOpen(false)
    setSearchQuery('')
    setHighlightId(hit.id)
    navigate(hit.route)
  }

  const onKeyDown = (event: KeyboardEvent<HTMLInputElement>): void => {
    if (event.key === 'ArrowDown') {
      event.preventDefault()
      setOpen(true)
      setActiveIndex((i) => (flat.length === 0 ? 0 : (i + 1) % flat.length))
    } else if (event.key === 'ArrowUp') {
      event.preventDefault()
      setActiveIndex((i) => (flat.length === 0 ? 0 : (i - 1 + flat.length) % flat.length))
    } else if (event.key === 'Enter') {
      const hit = flat[activeIndex]
      if (open && hit) {
        event.preventDefault()
        go(hit)
      }
    } else if (event.key === 'Escape') {
      if (open) {
        event.preventDefault()
        event.stopPropagation()
        setOpen(false)
      } else if (searchQuery) {
        setSearchQuery('')
      }
    }
  }

  const showDropdown = open
  const noAnalysis = !analysis
  const noMatches = !noAnalysis && searchQuery.trim().length > 0 && results.total === 0

  return (
    <div ref={containerRef} className="relative min-w-0 flex-1 max-w-md">
      <div className="relative flex items-center">
        <Search size={16} className="pointer-events-none absolute left-2.5 text-text-secondary" aria-hidden="true" />
        <input
          ref={(node) => {
            localRef.current = node
            if (inputRef) inputRef.current = node
          }}
          type="search"
          role="combobox"
          aria-expanded={showDropdown}
          aria-controls="global-search-results"
          aria-autocomplete="list"
          aria-label="Search findings, packets, steps"
          placeholder="Search findings, packets, steps…"
          value={searchQuery}
          data-testid="global-search-input"
          onChange={(event) => {
            setSearchQuery(event.target.value)
            setOpen(true)
          }}
          onFocus={() => setOpen(true)}
          onKeyDown={onKeyDown}
          className={fieldClasses('md', 'w-full pl-8 pr-9')}
        />
        <span className="pointer-events-none absolute right-2">
          <Kbd>/</Kbd>
        </span>
      </div>

      {showDropdown ? (
        <div
          id="global-search-results"
          role="listbox"
          aria-label="Search results"
          data-testid="search-results"
          className="absolute left-0 right-0 top-full z-50 mt-1 max-h-80 overflow-y-auto rounded-card border border-border bg-bg-elevated p-1 shadow-overlay"
        >
          {noAnalysis ? (
            <p className="px-2 py-3 text-xs text-text-secondary">No analysis loaded</p>
          ) : noMatches ? (
            <p className="px-2 py-3 text-xs text-text-secondary">No matches for “{searchQuery.trim()}”.</p>
          ) : results.total === 0 ? (
            <p className="px-2 py-3 text-xs text-text-secondary">Type to search the current analysis.</p>
          ) : (
            results.groups.map((entry) => (
              <div key={entry.group} className="mb-1 last:mb-0">
                <p className="px-2 py-1 text-2xs font-semibold uppercase tracking-wide text-text-secondary">
                  {SEARCH_GROUP_LABEL[entry.group]}
                </p>
                {entry.hits.map((hit) => {
                  const flatIndex = flat.findIndex((candidate) => candidate.id === hit.id)
                  const active = flatIndex === activeIndex
                  return (
                    <button
                      key={`${entry.group}-${hit.id}`}
                      type="button"
                      role="option"
                      aria-selected={active}
                      data-testid={`search-hit-${hit.id}`}
                      onMouseEnter={() => setActiveIndex(flatIndex)}
                      onClick={() => go(hit)}
                      className={cn(
                        'flex w-full items-center justify-between gap-2 rounded-control px-2 py-1.5 text-left',
                        active ? 'bg-bg-card text-text-primary' : 'text-text-secondary hover:bg-bg-card/60 hover:text-text-primary',
                      )}
                    >
                      <span className="min-w-0 truncate text-xs">{hit.title}</span>
                      {hit.subtitle ? <span className="shrink-0 font-mono text-2xs text-text-secondary">{hit.subtitle}</span> : null}
                    </button>
                  )
                })}
              </div>
            ))
          )}
        </div>
      ) : null}
    </div>
  )
}
