import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import type { AnalysisResult, BackendControl, ThreatCategory } from '@/types/analysis'
import { THREAT_CATEGORIES } from '@/lib/threat'

const CONTROL_CATEGORY: Record<string, ThreatCategory> = {
  'child-cipher': 'Weak Cipher',
  'dh-strength': 'Key Exchange',
  integrity: 'Weak Cipher',
  pfs: 'PFS',
  lifetime: 'Lifetime',
  replay: 'Replay',
  'ike-version': 'Protocol',
  'ike-cipher': 'Weak Cipher',
  'ike-integrity': 'Weak Cipher',
  'mode-exposure': 'Metadata',
}

type CategoryState = 'safe' | 'at-risk' | 'not-evaluated'

/** Per-category state from backend controls: never plots unknown as safe. */
export function categoryStates(controls: BackendControl[]): { category: ThreatCategory; state: CategoryState; note: string }[] {
  return THREAT_CATEGORIES.map((category) => {
    const mine = controls.filter((c) => CONTROL_CATEGORY[c.id] === category && c.status !== 'NOT_APPLICABLE')
    if (mine.length === 0 || mine.every((c) => c.status === 'UNKNOWN')) {
      return { category, state: 'not-evaluated' as CategoryState, note: 'not evaluated' }
    }
    if (mine.some((c) => c.status === 'FAIL' || c.status === 'LIKELY')) {
      const n = mine.filter((c) => c.status === 'FAIL' || c.status === 'LIKELY').length
      return { category, state: 'at-risk' as CategoryState, note: `${n} control${n === 1 ? '' : 's'} failed` }
    }
    return { category, state: 'safe' as CategoryState, note: 'all evaluated controls pass' }
  })
}

/** Category safety as a bar list (backend results): unevaluated
 * categories are labeled, never plotted as safe. */
export function CategoryBars({ analysis }: { analysis: AnalysisResult }) {
  const states = categoryStates(analysis.controls ?? [])
  return (
    <Card data-testid="category-bars">
      <CardHeader title="Category safety" description="Per-category control results; unevaluated is not safe" />
      <ul className="space-y-2">
        {states.map(({ category, state, note }) => (
          <li key={category} className="flex items-center gap-3">
            <span className="w-28 shrink-0 text-[12px] text-muted">{category}</span>
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-raised" aria-hidden="true">
              <span
                className={`block h-full rounded-full ${state === 'safe' ? 'bg-safe' : state === 'at-risk' ? 'bg-danger' : ''}`}
                style={{ width: state === 'not-evaluated' ? '0%' : '100%' }}
              />
            </span>
            <Badge tone={state === 'safe' ? 'safe' : state === 'at-risk' ? 'danger' : 'neutral'}>
              {state === 'safe' ? 'Safe' : state === 'at-risk' ? 'At risk' : 'Not evaluated'}
            </Badge>
            <span className="sr-only">{note}</span>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[11px] text-muted">
        {states
          .filter((s) => s.state === 'not-evaluated')
          .map((s) => s.category)
          .join(', ') || 'Every category evaluated.'}{' '}
        {states.some((s) => s.state === 'not-evaluated') ? ' — not evaluated (unknown controls are listed under Compliance).' : ''}
      </p>
    </Card>
  )
}
