import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import { SeverityBadge } from '@/components/ui/SeverityBadge'
import { cn } from '@/components/ui/cn'
import { fmtInt } from '@/lib/format'
import { STRIDE_TAGS } from '@/lib/threat'
import type { StrideTag } from '@/lib/threat'
import type { Finding } from '@/types/analysis'

export interface StrideBreakdownProps {
  findings: Finding[]
}

/** STRIDE breakdown: six items with counts and the findings mapped (spec 10.4 item 6). */
export function StrideBreakdown({ findings }: StrideBreakdownProps) {
  const byTag = new Map<StrideTag, Finding[]>()
  for (const tag of STRIDE_TAGS) byTag.set(tag, [])
  for (const finding of findings) byTag.get(finding.stride)?.push(finding)

  return (
    <Card data-testid="stride-breakdown">
      <CardHeader title="STRIDE breakdown" description="Six categories, count and mapped findings" />
      <ul className="grid grid-cols-1 gap-3 sm:grid-cols-2 xl:grid-cols-3">
        {STRIDE_TAGS.map((tag) => {
          const mapped = byTag.get(tag) ?? []
          return (
            <li
              key={tag}
              data-testid={`stride-item-${tag}`.replace(/\s+/g, '-').toLowerCase()}
              className={cn(
                'rounded-card border p-3',
                mapped.length > 0 ? 'border-line bg-raised/50' : 'border-line/60 bg-transparent',
              )}
            >
              <div className="flex items-center justify-between gap-2">
                <span className="text-[13px] font-semibold text-ink">{tag}</span>
                <Badge tone={mapped.length > 0 ? 'warn' : 'safe'}>
                  {fmtInt(mapped.length)} finding{mapped.length === 1 ? '' : 's'}
                </Badge>
              </div>
              {mapped.length === 0 ? (
                <p className="mt-2 text-[12px] text-safe">No findings mapped to this category.</p>
              ) : (
                <ul className="mt-2 space-y-1.5">
                  {mapped.map((finding) => (
                    <li key={finding.id} className="flex items-center gap-2">
                      <SeverityBadge severity={finding.severity} />
                      <span className="font-mono text-[11px] text-muted">{finding.ruleId}</span>
                      <span className="truncate text-[12px] text-ink" title={finding.title}>
                        {finding.title}
                      </span>
                    </li>
                  ))}
                </ul>
              )}
            </li>
          )
        })}
      </ul>
    </Card>
  )
}
