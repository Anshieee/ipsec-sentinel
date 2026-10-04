import { Card, CardHeader } from '@/components/ui/Card'
import { Badge } from '@/components/ui/Badge'
import type { AnalysisResult, ThreatCategory } from '@/types/analysis'
import { THREAT_CATEGORIES } from '@/lib/threat'
import { findingTaxonomy } from '@/api/backend'

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

type CategoryState = 'safe' | 'pass-inferred' | 'at-risk' | 'likely-at-risk' | 'not-evaluated'

const STATE_LABEL: Record<CategoryState, string> = {
  safe: 'Safe',
  'pass-inferred': 'Pass (inferred)',
  'at-risk': 'At risk',
  'likely-at-risk': 'Likely at risk',
  'not-evaluated': 'Not evaluated',
}

/** Per-category state, findings first: any CONFIRMED finding in the
 * category wins over control results; the finding's own category is
 * used, never the control id. A PASS resting on INFERRED evidence reads
 * "Pass (inferred)", never "Safe". */
export function categoryStates(analysis: AnalysisResult): { category: ThreatCategory; state: CategoryState; note: string }[] {
  const controls = analysis.controls ?? []
  const byFinding = new Map<ThreatCategory, 'CONFIRMED' | 'LIKELY'>()
  for (const f of analysis.findings) {
    const { category } = findingTaxonomy(f.ruleId)
    const verdict = f.verdict ?? 'CONFIRMED'
    const prev = byFinding.get(category)
    if (verdict === 'CONFIRMED' || prev === undefined) byFinding.set(category, verdict)
  }
  return THREAT_CATEGORIES.map((category) => {
    const verdict = byFinding.get(category)
    if (verdict === 'CONFIRMED') return { category, state: 'at-risk' as CategoryState, note: 'confirmed finding' }
    if (verdict === 'LIKELY') return { category, state: 'likely-at-risk' as CategoryState, note: 'likely finding (inferred evidence)' }
    const mine = controls.filter((c) => CONTROL_CATEGORY[c.id] === category && c.status !== 'NOT_APPLICABLE')
    if (mine.length === 0 || mine.every((c) => c.status === 'UNKNOWN')) {
      return { category, state: 'not-evaluated' as CategoryState, note: 'not evaluated' }
    }
    if (mine.some((c) => c.status === 'FAIL' || c.status === 'LIKELY')) {
      return { category, state: 'at-risk' as CategoryState, note: 'control failed without a finding' }
    }
    const pass = mine.filter((c) => c.status === 'PASS')
    if (pass.length > 0 && pass.every((c) => c.source === 'inferred')) {
      return { category, state: 'pass-inferred' as CategoryState, note: 'passes rest on inferred evidence' }
    }
    if (pass.length === mine.length) return { category, state: 'safe' as CategoryState, note: 'all evaluated controls pass' }
    return { category, state: 'not-evaluated' as CategoryState, note: 'not evaluated' }
  })
}

function slug(category: string): string {
  return category.toLowerCase().replace(/[^a-z0-9]+/g, '-')
}

/** Category safety as a bar list (backend results): unevaluated
 * categories are labeled, never plotted as safe. */
export function CategoryBars({ analysis }: { analysis: AnalysisResult }) {
  const states = categoryStates(analysis)
  return (
    <Card data-testid="category-bars">
      <CardHeader title="Category safety" description="Findings first, then evaluated controls" />
      <ul className="space-y-2">
        {states.map(({ category, state, note }) => (
          <li key={category} data-testid={`category-row-${slug(category)}`} className="flex items-center gap-3">
            <span className="w-28 shrink-0 text-[12px] text-text-secondary">{category}</span>
            <span className="h-2 flex-1 overflow-hidden rounded-full bg-bg-card" aria-hidden="true">
              <span
                className={`block h-full rounded-full ${state === 'safe' ? 'bg-green' : state === 'pass-inferred' ? 'bg-green/60' : state === 'at-risk' ? 'bg-red' : state === 'likely-at-risk' ? 'bg-amber' : ''}`}
                style={{ width: state === 'not-evaluated' ? '0%' : '100%' }}
              />
            </span>
            <Badge tone={state === 'safe' || state === 'pass-inferred' ? 'safe' : state === 'not-evaluated' ? 'neutral' : 'danger'}>
              {STATE_LABEL[state]}
            </Badge>
            <span className="sr-only">{note}</span>
          </li>
        ))}
      </ul>
      <p className="mt-2 text-[11px] text-text-secondary">
        {states
          .filter((s) => s.state === 'not-evaluated')
          .map((s) => s.category)
          .join(', ') || 'Every category evaluated.'}{' '}
        {states.some((s) => s.state === 'not-evaluated') ? ' — not evaluated (unknown controls are listed under Compliance).' : ''}
      </p>
    </Card>
  )
}
