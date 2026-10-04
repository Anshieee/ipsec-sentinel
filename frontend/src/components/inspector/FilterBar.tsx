import { useEffect, useRef, useState } from 'react'
import { RotateCcw, Search } from 'lucide-react'
import { Button } from '@/components/ui/Button'
import { Card } from '@/components/ui/Card'
import { fieldClasses } from '@/components/ui/Field'
import { CHIP_ACTION_CLASS } from '@/components/ui/Chip'
import { cn } from '@/components/ui/cn'
import { useDebounce } from '@/hooks/useDebounce'
import type { PacketRow } from '@/types/analysis'

export const PROTOCOLS: PacketRow['proto'][] = ['IKE', 'ESP', 'AH', 'UDP', 'OTHER']

export type Direction = 'All' | 'Outbound' | 'Inbound'

export interface PacketFilters {
  protocols: PacketRow['proto'][]
  query: string
  direction: Direction
}

export const EMPTY_FILTERS: PacketFilters = { protocols: [], query: '', direction: 'All' }

export interface FilterBarProps {
  filters: PacketFilters
  onChange: (filters: PacketFilters) => void
}

/** Protocol chips, debounced text filter, direction select and reset (spec 10.2 item 2). */
export function FilterBar({ filters, onChange }: FilterBarProps) {
  const [draft, setDraft] = useState(filters.query)
  const debouncedQuery = useDebounce(draft, 150)

  const lastApplied = useRef(filters.query)
  useEffect(() => {
    if (debouncedQuery === lastApplied.current) return
    lastApplied.current = debouncedQuery
    onChange({ ...filters, query: debouncedQuery })
  }, [debouncedQuery, filters, onChange])

  const toggleProtocol = (protocol: PacketRow['proto']): void => {
    const next = filters.protocols.includes(protocol)
      ? filters.protocols.filter((entry) => entry !== protocol)
      : [...filters.protocols, protocol]
    onChange({ ...filters, protocols: next })
  }

  const active = filters.protocols.length > 0 || filters.query.length > 0 || filters.direction !== 'All'

  return (
    <Card data-testid="packet-filters">
      <div className="flex flex-wrap items-center gap-3">
        <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Protocol filters">
          {PROTOCOLS.map((protocol) => {
            const selected = filters.protocols.includes(protocol)
            return (
              <button
                key={protocol}
                type="button"
                aria-pressed={selected}
                data-testid={`protocol-chip-${protocol}`}
                onClick={() => toggleProtocol(protocol)}
                className={cn(
                  CHIP_ACTION_CLASS,
                  selected
                    ? 'border-blue/50 bg-blue/15 text-blue'
                    : 'border-border-strong bg-bg-card text-text-secondary hover:text-text-primary active:bg-border/40',
                )}
              >
                {protocol}
              </button>
            )
          })}
        </div>

        <div className="relative min-w-[200px] flex-1">
          <Search size={16} className="pointer-events-none absolute left-2.5 text-text-secondary" aria-hidden="true" />
          <input
            type="search"
            value={draft}
            aria-label="Filter packets by source, destination, SPI or info"
            placeholder="Filter by src, dst, SPI, info…"
            data-testid="packet-query"
            onChange={(event) => setDraft(event.target.value)}
            className={fieldClasses('sm', 'w-full pl-8 pr-2')}
          />
        </div>

        <label className="flex items-center gap-2 text-2xs text-text-secondary">
          Direction
          <select
            value={filters.direction}
            onChange={(event) => onChange({ ...filters, direction: event.target.value as Direction })}
            className={fieldClasses('sm')}
          >
            <option value="All">All</option>
            <option value="Outbound">Outbound</option>
            <option value="Inbound">Inbound</option>
          </select>
        </label>

        <Button variant="ghost" size="sm" onClick={() => onChange(EMPTY_FILTERS)} disabled={!active}>
          <RotateCcw size={16} aria-hidden="true" />
          Reset filters
        </Button>
      </div>
    </Card>
  )
}
