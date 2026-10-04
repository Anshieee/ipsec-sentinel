import { useEffect, useMemo, useRef, useState } from 'react'
import { Check, Copy, KeyRound, ShieldCheck } from 'lucide-react'
import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { Button } from '@/components/ui/Button'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { cn } from '@/components/ui/cn'
import { useSentinel } from '@/store/useSentinel'
import { severityRank } from '@/lib/severity'
import type { MatrixSelection } from './ThreatMatrixCard'
import type { Finding } from '@/types/analysis'

export interface FindingsListProps {
  findings: Finding[]
  selection: MatrixSelection | null
}

function sortFindings(list: Finding[]): Finding[] {
  return [...list].sort((a, b) => {
    const rank = severityRank(a.severity) - severityRank(b.severity)
    if (rank !== 0) return rank
    return a.ruleId.localeCompare(b.ruleId)
  })
}

/** Findings and recommendations engine (spec 10.1 D.2). */
export function FindingsList({ findings, selection }: FindingsListProps) {
  const searchQuery = useSentinel((s) => s.searchQuery)
  const highlightId = useSentinel((s) => s.highlightId)
  const [copiedId, setCopiedId] = useState<string | null>(null)
  const containerRef = useRef<HTMLDivElement | null>(null)

  const filtered = useMemo(() => {
    const needle = searchQuery.trim().toLowerCase()
    return sortFindings(
      findings.filter((finding) => {
        if (selection && (finding.severity !== selection.severity || finding.category !== selection.category)) {
          return false
        }
        if (!needle) return true
        return `${finding.title} ${finding.evidence} ${finding.recommendation} ${finding.ruleId}`
          .toLowerCase()
          .includes(needle)
      }),
    )
  }, [findings, searchQuery, selection])

  useEffect(() => {
    if (!highlightId) return
    const rows = Array.from(containerRef.current?.querySelectorAll<HTMLElement>('[data-row-id]') ?? [])
    const target = rows.find((row) => row.dataset.rowId === highlightId)
    target?.scrollIntoView({ block: 'center' })
  }, [highlightId])

  const copyRecommendation = async (finding: Finding): Promise<void> => {
    try {
      await navigator.clipboard.writeText(finding.recommendation)
      setCopiedId(finding.id)
      window.setTimeout(() => setCopiedId(null), 1500)
    } catch {
      useSentinel.getState().notify({ severity: 'warn', message: 'Clipboard unavailable in this browser.' })
    }
  }

  if (findings.length === 0) {
    return (
      <Card data-testid="findings-list">
        <CardHeader title="Findings & recommendations" />
        <p className="flex items-center gap-2 text-[13px] text-green">
          <ShieldCheck size={16} aria-hidden="true" />
          No findings. This configuration meets the baseline policy.
        </p>
      </Card>
    )
  }

  return (
    <Card data-testid="findings-list">
      <CardHeader
        title="Findings & recommendations"
        description={
          selection
            ? `Filtered to ${selection.severity} · ${selection.category}`
            : `${filtered.length} of ${findings.length} findings shown`
        }
      />
      <div ref={containerRef} className="space-y-3">
        {filtered.length === 0 ? (
          <p className="text-[13px] text-text-secondary">No findings match the current filter.</p>
        ) : (
          filtered.map((finding) => {
            const highlighted = highlightId === finding.id
            return (
              <article
                key={finding.id}
                data-row-id={finding.id}
                className={cn(
                  'rounded-card border p-3',
                  highlighted ? 'border-blue ring-2 ring-blue' : 'border-border',
                )}
              >
                <div className="flex flex-wrap items-center gap-2">
                  <SeverityBadge severity={finding.severity} />
                  <h3 className="text-[13px] font-semibold text-text-primary">{finding.title}</h3>
                  <Badge>{finding.category}</Badge>
                  <Badge tone="cyan">{finding.stride}</Badge>
                  <span className="ml-auto font-mono text-[11px] text-text-secondary">{finding.ruleId}</span>
                </div>

                <p className="mt-2 rounded-control bg-bg-card/60 p-2 font-mono text-[11px] leading-4 text-text-secondary">
                  {finding.evidence}
                </p>

                <p className="mt-2 text-[11px] text-text-secondary">Reference: {finding.reference}</p>

                <div className="mt-2 rounded-control border border-border bg-bg-card/40 p-2">
                  <p className="flex items-center gap-1.5 text-[11px] font-semibold uppercase tracking-wide text-text-secondary">
                    <KeyRound size={12} aria-hidden="true" />
                    Recommendation
                  </p>
                  <div className="mt-1 flex items-start justify-between gap-2">
                    <p className="text-[13px] leading-5 text-text-primary">{finding.recommendation}</p>
                    <Button
                      variant="ghost"
                      size="sm"
                      onClick={() => void copyRecommendation(finding)}
                      aria-label={`Copy recommendation for ${finding.ruleId}`}
                    >
                      {copiedId === finding.id ? <Check size={12} aria-hidden="true" /> : <Copy size={12} aria-hidden="true" />}
                      {copiedId === finding.id ? 'Copied' : 'Copy'}
                    </Button>
                  </div>
                </div>
              </article>
            )
          })
        )}
      </div>
    </Card>
  )
}
