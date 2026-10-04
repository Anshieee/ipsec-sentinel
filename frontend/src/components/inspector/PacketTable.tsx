import { useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react'
import { ChevronDown, ChevronUp, ChevronsLeft, ChevronsRight, ChevronLeft, ChevronRight } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { fieldClasses } from '@/components/ui/Field'
import { cn } from '@/components/ui/cn'
import { fmtInt } from '@/lib/format'
import type { PacketRow } from '@/types/analysis'

type SortKey = 'no' | 'timeSec' | 'length'
type Direction = 'asc' | 'desc'

const PAGE_SIZES = [50, 100, 250]

const PROTO_TONE: Record<PacketRow['proto'], 'info' | 'cyan' | 'warn' | 'neutral' | 'danger'> = {
  IKE: 'info',
  ESP: 'cyan',
  AH: 'warn',
  UDP: 'neutral',
  OTHER: 'danger',
}

export interface PacketTableProps {
  rows: PacketRow[]
  /** Packets in the representative sample before filtering. */
  sampledTotal: number
  /** Packets in the capture overall (`summary.packets`). */
  captureTotal: number
  selectedNo: number | null
  onSelect: (packet: PacketRow) => void
  density: 'comfortable' | 'compact'
}

/** Paginated, sortable packet table (spec 10.2 item 3). */
export function PacketTable({ rows, sampledTotal, captureTotal, selectedNo, onSelect, density }: PacketTableProps) {
  const [sort, setSort] = useState<{ key: SortKey; direction: Direction }>({ key: 'no', direction: 'asc' })
  const [pageIndex, setPageIndex] = useState(0)
  const [pageSize, setPageSize] = useState(100)
  const bodyRef = useRef<HTMLTableSectionElement | null>(null)

  const sorted = useMemo(() => {
    const factor = sort.direction === 'asc' ? 1 : -1
    return [...rows].sort((a, b) => {
      const left = a[sort.key]
      const right = b[sort.key]
      if (typeof left === 'number' && typeof right === 'number') return (left - right) * factor
      return String(left).localeCompare(String(right)) * factor
    })
  }, [rows, sort])

  const pageCount = Math.max(1, Math.ceil(sorted.length / pageSize))
  const safeIndex = Math.min(pageIndex, pageCount - 1)
  const pageRows = sorted.slice(safeIndex * pageSize, safeIndex * pageSize + pageSize)
  const start = sorted.length === 0 ? 0 : safeIndex * pageSize + 1
  const end = Math.min(sorted.length, (safeIndex + 1) * pageSize)

  const toggleSort = (key: SortKey): void => {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === 'asc' ? 'desc' : 'asc' }
        : { key, direction: 'asc' },
    )
    setPageIndex(0)
  }

  const sortIcon = (key: SortKey): ReactNode => {
    if (sort.key !== key) return null
    return sort.direction === 'asc' ? (
      <ChevronUp size={12} aria-hidden="true" />
    ) : (
      <ChevronDown size={12} aria-hidden="true" />
    )
  }

  const onKeyDown = (event: ReactKeyboardEvent<HTMLTableSectionElement>): void => {
    if (event.key !== 'ArrowDown' && event.key !== 'ArrowUp') return
    event.preventDefault()
    const active = document.activeElement
    const row = active instanceof HTMLElement ? active.closest('tr[data-row]') : null
    if (!row) return
    const target = event.key === 'ArrowDown' ? row.nextElementSibling : row.previousElementSibling
    const button = target?.querySelector<HTMLButtonElement>('button.row-select')
    button?.focus()
  }

  const rowHeight = density === 'compact' ? 'h-8' : 'h-10'

  return (
    <Card flush data-testid="packet-table">
      <div className="flex flex-wrap items-center justify-between gap-2 border-b border-border px-4 py-3">
        <CardHeader
          title="Packets"
          description={`Showing ${fmtInt(start)} to ${fmtInt(end)} of ${fmtInt(sorted.length)} sampled packets (of ${fmtInt(captureTotal)} total)`}
          className="mb-0"
        />
        <div className="flex items-center gap-2 text-2xs text-text-secondary">
          <label className="flex items-center gap-1.5">
            Rows
            <select
              value={pageSize}
              aria-label="Rows per page"
              data-testid="page-size"
              onChange={(event) => {
                setPageSize(Number(event.target.value))
                setPageIndex(0)
              }}
              className={fieldClasses('sm')}
            >
              {PAGE_SIZES.map((size) => (
                <option key={size} value={size}>
                  {size}
                </option>
              ))}
            </select>
          </label>
          <span className="tnum">
            Page {safeIndex + 1} of {pageCount}
          </span>
        </div>
      </div>

      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Packet table scroll area">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">
            Sampled packets, {sampledTotal} rows before filtering
          </caption>
          <thead className="sticky top-0 z-10 bg-bg-card">
            <tr className="text-left text-text-secondary">
              <th scope="col" className="px-3 py-2 font-medium">
                <button type="button" onClick={() => toggleSort('no')} className="inline-flex items-center gap-1">
                  No. {sortIcon('no')}
                </button>
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                <button type="button" onClick={() => toggleSort('timeSec')} className="inline-flex items-center gap-1">
                  Time (s) {sortIcon('timeSec')}
                </button>
              </th>
              <th scope="col" className="px-3 py-2 font-medium">Source</th>
              <th scope="col" className="px-3 py-2 font-medium">Destination</th>
              <th scope="col" className="px-3 py-2 font-medium">Proto</th>
              <th scope="col" className="px-3 py-2 font-medium">SPI</th>
              <th scope="col" className="px-3 py-2 font-medium">Seq</th>
              <th scope="col" className="px-3 py-2 font-medium">
                <button type="button" onClick={() => toggleSort('length')} className="inline-flex items-center gap-1">
                  Length {sortIcon('length')}
                </button>
              </th>
              <th scope="col" className="px-3 py-2 font-medium">Info</th>
            </tr>
          </thead>
          <tbody ref={bodyRef} onKeyDown={onKeyDown}>
            {pageRows.length === 0 ? (
              <tr>
                <td colSpan={9} className="px-3 py-6 text-center text-text-secondary">
                  No packets match the current filters.
                </td>
              </tr>
            ) : (
              pageRows.map((packet) => {
                const selected = selectedNo === packet.no
                return (
                  <tr
                    key={packet.no}
                    data-row
                    className={cn('border-t border-border/60', selected ? 'bg-blue/10' : 'hover:bg-bg-card/50')}
                  >
                    <td className={cn('px-3', rowHeight)}>
                      <button
                        type="button"
                        className="row-select tnum flex w-full items-center text-left text-text-primary"
                        aria-pressed={selected}
                        onClick={() => onSelect(packet)}
                      >
                        {fmtInt(packet.no)}
                      </button>
                    </td>
                    <td className="tnum px-3 text-text-secondary">{packet.timeSec.toFixed(6)}</td>
                    <td className="px-3 font-mono text-text-secondary">{packet.src}</td>
                    <td className="px-3 font-mono text-text-secondary">{packet.dst}</td>
                    <td className="px-3">
                      <Badge tone={PROTO_TONE[packet.proto]}>{packet.proto}</Badge>
                    </td>
                    <td className="px-3 font-mono text-text-secondary">{packet.spi ?? '—'}</td>
                    <td className="tnum px-3 text-text-secondary">{packet.seq ?? '—'}</td>
                    <td className="tnum px-3 text-text-primary">{fmtInt(packet.length)}</td>
                    <td className="max-w-[280px] truncate px-3 text-text-secondary" title={packet.info}>
                      {packet.info}
                    </td>
                  </tr>
                )
              })
            )}
          </tbody>
        </table>
      </div>

      <div className="flex items-center justify-between gap-2 border-t border-border px-4 py-2">
        <p className="text-[11px] text-text-secondary" data-testid="pagination-status">
          Showing {fmtInt(start)} to {fmtInt(end)} of {fmtInt(sorted.length)} sampled packets (of {fmtInt(captureTotal)}{' '}
          total)
        </p>
        <div className="flex items-center gap-1">
          <Button
            variant="ghost"
            size="sm"
            aria-label="First page"
            disabled={safeIndex === 0}
            onClick={() => setPageIndex(0)}
          >
            <ChevronsLeft size={14} aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            aria-label="Previous page"
            disabled={safeIndex === 0}
            onClick={() => setPageIndex(safeIndex - 1)}
          >
            <ChevronLeft size={14} aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            aria-label="Next page"
            disabled={safeIndex >= pageCount - 1}
            data-testid="next-page"
            onClick={() => setPageIndex(safeIndex + 1)}
          >
            <ChevronRight size={14} aria-hidden="true" />
          </Button>
          <Button
            variant="ghost"
            size="sm"
            aria-label="Last page"
            disabled={safeIndex >= pageCount - 1}
            onClick={() => setPageIndex(pageCount - 1)}
          >
            <ChevronsRight size={14} aria-hidden="true" />
          </Button>
        </div>
      </div>
    </Card>
  )
}
