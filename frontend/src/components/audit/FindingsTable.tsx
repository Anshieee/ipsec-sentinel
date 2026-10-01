import { useMemo, useState, type ReactNode } from 'react'
import { ChevronDown, ChevronUp, Download, FilterX } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { Badge } from '@/components/ui/Badge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { CHIP_ACTION_CLASS } from '@/components/ui/Chip'
import { cn } from '@/components/ui/cn'
import { SEVERITIES, SEVERITY_LABEL, severityRank } from '@/lib/severity'
import { STRIDE_TAGS } from '@/lib/threat'
import { downloadText } from '@/components/report/buildMarkdown'
import type { Finding, Severity, ThreatCategory } from '@/types/analysis'
import type { StrideTag } from '@/lib/threat'

export type FindingsSortKey = 'severity' | 'category' | 'ruleId' | 'stride'
export type SortDirection = 'asc' | 'desc'

export interface FindingsFilters {
  severities: Severity[]
  strides: StrideTag[]
}

export const EMPTY_FINDINGS_FILTERS: FindingsFilters = { severities: [], strides: [] }

/** True when any severity or STRIDE chip is active. */
export const hasFindingsFilters = (filters: FindingsFilters): boolean =>
  filters.severities.length > 0 || filters.strides.length > 0

/** Applies severity and STRIDE chip filters (spec 10.4 item 5). */
export function filterFindings(findings: Finding[], filters: FindingsFilters): Finding[] {
  return findings.filter((finding) => {
    if (filters.severities.length > 0 && !filters.severities.includes(finding.severity)) return false
    if (filters.strides.length > 0 && !filters.strides.includes(finding.stride)) return false
    return true
  })
}

/** Sorts by the four table columns; severity uses the critical-first rank. */
export function sortFindings(
  findings: Finding[],
  key: FindingsSortKey,
  direction: SortDirection,
): Finding[] {
  const factor = direction === 'asc' ? 1 : -1
  return [...findings].sort((a, b) => {
    const left = key === 'severity' ? severityRank(a.severity) : a[key]
    const right = key === 'severity' ? severityRank(b.severity) : b[key]
    if (typeof left === 'number' && typeof right === 'number') return (left - right) * factor
    return String(left).localeCompare(String(right)) * factor
  })
}

const csvCell = (value: string): string => {
  if (/[",\n]/.test(value)) return `"${value.replace(/"/g, '""')}"`
  return value
}

/** RFC 4180 style CSV for the filtered findings list. */
export function findingsToCsv(findings: Finding[]): string {
  const header = ['Rule ID', 'Severity', 'Category', 'STRIDE', 'Title', 'Evidence', 'Reference', 'Recommendation']
  const rows = findings.map((finding) =>
    [
      finding.ruleId,
      finding.severity,
      finding.category,
      finding.stride,
      finding.title,
      finding.evidence,
      finding.reference,
      finding.recommendation,
    ]
      .map(csvCell)
      .join(','),
  )
  return [header.join(','), ...rows].join('\n')
}

export interface MatrixCell {
  severity: Severity
  category: ThreatCategory
}

export interface FindingsTableProps {
  findings: Finding[]
  /** Optional threat-matrix cell selection, applied on top of the chips. */
  selection?: MatrixCell | null
}

/** Sortable, filterable, expandable findings table with CSV export (spec 10.4 item 5). */
export function FindingsTable({ findings, selection = null }: FindingsTableProps) {
  const [filters, setFilters] = useState<FindingsFilters>(EMPTY_FINDINGS_FILTERS)
  const [sort, setSort] = useState<{ key: FindingsSortKey; direction: SortDirection }>({
    key: 'severity',
    direction: 'asc',
  })
  const [expandedId, setExpandedId] = useState<string | null>(null)

  const visible = useMemo(() => {
    const filtered = filterFindings(findings, filters).filter(
      (finding) =>
        !selection || (finding.severity === selection.severity && finding.category === selection.category),
    )
    return sortFindings(filtered, sort.key, sort.direction)
  }, [findings, filters, selection, sort])

  const toggleSeverity = (severity: Severity): void => {
    setFilters((current) => ({
      ...current,
      severities: current.severities.includes(severity)
        ? current.severities.filter((entry) => entry !== severity)
        : [...current.severities, severity],
    }))
  }

  const toggleStride = (stride: StrideTag): void => {
    setFilters((current) => ({
      ...current,
      strides: current.strides.includes(stride)
        ? current.strides.filter((entry) => entry !== stride)
        : [...current.strides, stride],
    }))
  }

  const toggleSort = (key: FindingsSortKey): void => {
    setSort((current) =>
      current.key === key
        ? { key, direction: current.direction === 'asc' ? 'desc' : 'asc' }
        : { key, direction: 'asc' },
    )
  }

  const sortIcon = (key: FindingsSortKey): ReactNode => {
    if (sort.key !== key) return null
    return sort.direction === 'asc' ? (
      <ChevronUp size={12} aria-hidden="true" />
    ) : (
      <ChevronDown size={12} aria-hidden="true" />
    )
  }

  const active = hasFindingsFilters(filters)

  return (
    <Card flush data-testid="findings-table">
      <div className="space-y-3 border-b border-line px-4 py-3">
        <CardHeader
          title="Findings"
          description={`${visible.length} of ${findings.length} findings shown`}
          className="mb-0"
        />

        <div className="flex flex-wrap items-center gap-3">
          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by severity">
            {SEVERITIES.map((severity) => {
              const selected = filters.severities.includes(severity)
              return (
                <button
                  key={severity}
                  type="button"
                  aria-pressed={selected}
                  data-testid={`severity-chip-${severity}`}
                  onClick={() => toggleSeverity(severity)}
                  className={cn(
                    CHIP_ACTION_CLASS,
                    selected
                      ? 'border-accent/50 bg-accent/15 text-accent'
                      : 'border-line-strong bg-raised text-muted hover:text-ink active:bg-line/40',
                  )}
                >
                  {SEVERITY_LABEL[severity]}
                </button>
              )
            })}
          </div>

          <div className="flex flex-wrap items-center gap-1.5" role="group" aria-label="Filter by STRIDE tag">
            {STRIDE_TAGS.map((stride) => {
              const selected = filters.strides.includes(stride)
              return (
                <button
                  key={stride}
                  type="button"
                  aria-pressed={selected}
                  data-testid={`stride-chip-${stride}`.replace(/\s+/g, '-').toLowerCase()}
                  onClick={() => toggleStride(stride)}
                  className={cn(
                    CHIP_ACTION_CLASS,
                    selected
                      ? 'border-highlight/50 bg-highlight/15 text-highlight'
                      : 'border-line-strong bg-raised text-muted hover:text-ink active:bg-line/40',
                  )}
                >
                  {stride}
                </button>
              )
            })}
          </div>

          <div className="ml-auto flex items-center gap-2">
            <Button
              variant="ghost"
              size="sm"
              disabled={!active}
              onClick={() => setFilters(EMPTY_FINDINGS_FILTERS)}
            >
              <FilterX size={14} aria-hidden="true" />
              Clear filters
            </Button>
            <Button
              variant="secondary"
              size="sm"
              data-testid="export-findings-csv"
              disabled={visible.length === 0}
              onClick={() => downloadText('findings.csv', findingsToCsv(visible), 'text/csv;charset=utf-8')}
            >
              <Download size={14} aria-hidden="true" />
              Export CSV
            </Button>
          </div>
        </div>
      </div>

      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Findings table scroll area">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">Rule findings with severity, category and STRIDE tag</caption>
          <thead className="bg-raised">
            <tr className="text-left text-muted">
              <th scope="col" className="px-3 py-2 font-medium">
                <button type="button" onClick={() => toggleSort('severity')} className="inline-flex items-center gap-1">
                  Severity {sortIcon('severity')}
                </button>
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                <button
                  type="button"
                  onClick={() => toggleSort('ruleId')}
                  className="inline-flex items-center gap-1"
                >
                  Rule {sortIcon('ruleId')}
                </button>
              </th>
              <th scope="col" className="px-3 py-2 font-medium">Title</th>
              <th scope="col" className="px-3 py-2 font-medium">
                <button
                  type="button"
                  onClick={() => toggleSort('category')}
                  className="inline-flex items-center gap-1"
                >
                  Category {sortIcon('category')}
                </button>
              </th>
              <th scope="col" className="px-3 py-2 font-medium">
                <button type="button" onClick={() => toggleSort('stride')} className="inline-flex items-center gap-1">
                  STRIDE {sortIcon('stride')}
                </button>
              </th>
            </tr>
          </thead>
          <tbody>
            {visible.length === 0 ? (
              <tr>
                <td colSpan={5} className="px-3 py-6 text-center text-muted">
                  No findings match the current filters.
                </td>
              </tr>
            ) : (
              visible.map((finding) => {
                const expanded = expandedId === finding.id
                return (
                  <FindingRow
                    key={finding.id}
                    finding={finding}
                    expanded={expanded}
                    onToggle={() => setExpandedId(expanded ? null : finding.id)}
                  />
                )
              })
            )}
          </tbody>
        </table>
      </div>
    </Card>
  )
}

interface FindingRowProps {
  finding: Finding
  expanded: boolean
  onToggle: () => void
}

/** One finding row plus its expandable evidence / reference / recommendation panel. */
function FindingRow({ finding, expanded, onToggle }: FindingRowProps) {
  return (
    <>
      <tr className={cn('border-t border-line/60', expanded ? 'bg-accent/10' : 'hover:bg-raised/50')}>
        <td className="px-3 py-2"><SeverityBadge severity={finding.severity} /></td>
        <td className="px-3 py-2 font-mono text-muted">{finding.ruleId}</td>
        <td className="px-3 py-2">
          <button
            type="button"
            aria-expanded={expanded}
            aria-controls={`finding-panel-${finding.id}`}
            data-testid={`finding-toggle-${finding.ruleId}`}
            onClick={onToggle}
            className="flex items-center gap-1.5 text-left text-ink hover:text-accent"
          >
            {expanded ? (
              <ChevronDown size={12} aria-hidden="true" />
            ) : (
              <ChevronUp size={12} aria-hidden="true" />
            )}
            {finding.title}
          </button>
        </td>
        <td className="px-3 py-2"><Badge>{finding.category}</Badge></td>
        <td className="px-3 py-2"><Badge tone="cyan">{finding.stride}</Badge></td>
      </tr>
      {expanded ? (
        <tr id={`finding-panel-${finding.id}`} data-testid={`finding-panel-${finding.ruleId}`}>
          <td colSpan={5} className="border-t border-line/60 bg-base/60 px-3 py-3">
            <dl className="space-y-2">
              <div>
                <dt className="text-2xs font-semibold uppercase tracking-wide text-muted">Evidence</dt>
                <dd className="mt-0.5 rounded-control bg-raised/60 p-2 font-mono text-[11px] leading-4 text-muted">
                  {finding.evidence}
                </dd>
              </div>
              <div>
                <dt className="text-2xs font-semibold uppercase tracking-wide text-muted">Reference</dt>
                <dd className="mt-0.5 text-[12px] text-ink">{finding.reference}</dd>
              </div>
              <div>
                <dt className="text-2xs font-semibold uppercase tracking-wide text-muted">Recommendation</dt>
                <dd className="mt-0.5 text-[13px] leading-5 text-ink">{finding.recommendation}</dd>
              </div>
            </dl>
          </td>
        </tr>
      ) : null}
    </>
  )
}
