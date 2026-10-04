import type { CSSProperties } from 'react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Button } from '@/components/ui/Button'
import { cn } from '@/components/ui/cn'
import { SEVERITIES, SEVERITY_LABEL } from '@/lib/severity'
import { THREAT_CATEGORIES, matrixColumnTotal, matrixGrandTotal, matrixRowTotal } from '@/lib/threat'
import type { ThreatMatrix } from '@/lib/threat'
import type { Severity, ThreatCategory } from '@/types/analysis'

export interface MatrixSelection {
  severity: Severity
  category: ThreatCategory
}

export interface ThreatMatrixCardProps {
  matrix: ThreatMatrix
  selection: MatrixSelection | null
  onSelect: (selection: MatrixSelection | null) => void
  /** Backend-mapped result: note points at the Compliance controls. */
  backend?: boolean
}

/** Severity colour at 15 % opacity for a non-zero count; zero stays uncoloured. */
const CELL_BACKGROUND: Record<Severity, string> = {
  critical: 'rgba(239, 68, 68, 0.15)',
  high: 'rgba(249, 115, 22, 0.15)',
  medium: 'rgba(245, 158, 11, 0.15)',
  low: 'rgba(59, 130, 246, 0.15)',
}

function cellStyle(severity: Severity, count: number): CSSProperties | undefined {
  if (count === 0) return undefined
  return { backgroundColor: CELL_BACKGROUND[severity] }
}

/** Threat matrix with click-to-filter cells (spec 10.1 D.1). */
export function ThreatMatrixCard({ matrix, selection, onSelect, backend }: ThreatMatrixCardProps) {
  const total = matrixGrandTotal(matrix)

  return (
    <Card data-testid="threat-matrix">
      <CardHeader
        title="Threat matrix"
        description={`${total} finding${total === 1 ? '' : 's'} — click a non-zero cell to filter the list below`}
        actions={
          selection ? (
            <Button variant="ghost" size="sm" onClick={() => onSelect(null)} data-testid="clear-matrix-filter">
              Clear filter
            </Button>
          ) : null
        }
      />
      <p className="mb-2 text-[11px] text-muted" data-testid="matrix-note">
        Counts confirmed and likely findings only
        {backend ? '; unknown controls are listed under Compliance.' : '.'}
      </p>
      <div className="overflow-x-auto" tabIndex={0} role="region" aria-label="Threat matrix table">
        <table className="w-full border-collapse text-xs">
          <caption className="sr-only">
            Findings by severity (rows) and threat category (columns)
          </caption>
          <thead>
            <tr>
              <th scope="col" className="border border-line bg-raised px-2 py-1.5 text-left text-muted">
                Severity
              </th>
              {THREAT_CATEGORIES.map((category) => (
                <th
                  key={category}
                  scope="col"
                  className="border border-line bg-raised px-2 py-1.5 text-center font-medium text-ink"
                >
                  {category}
                </th>
              ))}
              <th scope="col" className="border border-line bg-raised px-2 py-1.5 text-center text-muted">
                Total
              </th>
            </tr>
          </thead>
          <tbody>
            {SEVERITIES.map((severity) => (
              <tr key={severity}>
                <th scope="row" className="border border-line px-2 py-1.5 text-left font-medium text-ink">
                  {SEVERITY_LABEL[severity]}
                </th>
                {THREAT_CATEGORIES.map((category) => {
                  const count = matrix[severity][category]
                  const active = selection?.severity === severity && selection?.category === category
                  return (
                    <td key={category} className="border border-line p-0 text-center">
                      <button
                        type="button"
                        aria-pressed={active}
                        disabled={count === 0}
                        data-testid={`matrix-cell-${severity}-${category}`.replace(/\s+/g, '-').toLowerCase()}
                        aria-label={`${SEVERITY_LABEL[severity]}, ${category}: ${count} finding${count === 1 ? '' : 's'}`}
                        onClick={() => onSelect(active ? null : { severity, category })}
                        style={cellStyle(severity, count)}
                        className={cn(
                          'h-9 w-full px-2 text-center text-ink',
                          count === 0 ? 'cursor-default text-muted' : 'cursor-pointer hover:ring-1 hover:ring-accent',
                          active ? 'ring-2 ring-accent' : '',
                        )}
                      >
                        {count}
                      </button>
                    </td>
                  )
                })}
                <td className="tnum border border-line bg-raised/50 px-2 py-1.5 text-center text-ink">
                  {matrixRowTotal(matrix, severity)}
                </td>
              </tr>
            ))}
          </tbody>
          <tfoot>
            <tr>
              <th scope="row" className="border border-line bg-raised/50 px-2 py-1.5 text-left text-muted">
                Total
              </th>
              {THREAT_CATEGORIES.map((category) => (
                <td key={category} className="tnum border border-line bg-raised/50 px-2 py-1.5 text-center text-ink">
                  {matrixColumnTotal(matrix, category)}
                </td>
              ))}
              <td className="tnum border border-line bg-raised/50 px-2 py-1.5 text-center font-semibold text-ink">
                {total}
              </td>
            </tr>
          </tfoot>
        </table>
      </div>
    </Card>
  )
}
