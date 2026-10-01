import { render, screen, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { AuditSummary } from '@/components/audit/AuditSummary'
import { FindingsTable, findingsToCsv, sortFindings } from '@/components/audit/FindingsTable'
import { RemediationPlan, orderRemediation } from '@/components/audit/RemediationPlan'
import { AuditPage } from '@/pages/AuditPage'
import { useSentinel, deriveValues } from '@/store/useSentinel'
import { getFixture } from '@/api/fixtures'
import { computeRiskScore } from '@/lib/risk'

function loadFixture(id: 'A' | 'B' | 'C'): ReturnType<typeof getFixture> {
  const analysis = getFixture(id)
  useSentinel.getState().setAnalysis(analysis)
  return analysis
}

const renderPage = (): void => {
  render(
    <MemoryRouter>
      <AuditPage />
    </MemoryRouter>,
  )
}

/**
 * Derived values straight from the store: `useDerived` is a React hook, and
 * these assertions run in plain test bodies, so the pure `deriveValues` behind
 * it is what a non-rendering test should call.
 */
function getDerived(): ReturnType<typeof deriveValues> {
  const state = useSentinel.getState()
  return deriveValues(state.current, state.settings.minRuleConfidence, state.settings.uncertainThreshold)
}

beforeEach(() => {
  useSentinel.getState().clear()
  useSentinel.getState().setSearchQuery('')
  useSentinel.setState({ notifications: [], highlightId: undefined })
})

describe('Audit — header summary', () => {
  it('shows the score derivation sentence and severity counts', () => {
    loadFixture('B')
    render(
      <MemoryRouter>
        <AuditSummary />
      </MemoryRouter>,
    )
    expect(screen.getByTestId('score-derivation')).toHaveTextContent(
      'Score derivation: 25 x critical + 12 x high + 5 x medium + 2 x low, capped at 100',
    )
    const gauge = screen.getByTestId('risk-gauge')
    expect(gauge).toHaveAttribute('aria-valuenow', '78')
  })
})

describe('Audit — remediation projected score', () => {
  it('projects the score over unticked findings and updates as items are ticked', async () => {
    const user = userEvent.setup()
    loadFixture('B')
    const derived = getDerived()
    expect(derived.findings.length).toBeGreaterThan(0)
    expect(computeRiskScore(derived.findings)).toBe(78)

    render(<RemediationPlan findings={derived.findings} currentScore={derived.riskScore} />)

    expect(screen.getByTestId('remediation-progress')).toHaveTextContent(
      `0 of ${derived.findings.length} completed`,
    )
    expect(screen.getByTestId('projected-score')).toHaveTextContent('Projected risk score: 78')

    const first = derived.findings[0]
    await user.click(screen.getByTestId(`remediation-check-${first.ruleId}`))

    const remaining = derived.findings.filter((finding) => finding.id !== first.id)
    const expected = computeRiskScore(remaining)
    expect(screen.getByTestId('projected-score')).toHaveTextContent(`Projected risk score: ${expected}`)
    expect(expected).toBeLessThan(78)
    expect(screen.getByTestId('remediation-progress')).toHaveTextContent(
      `1 of ${derived.findings.length} completed`,
    )

    // Ticking everything leaves an empty unticked set: score 0.
    for (const finding of remaining) {
      await user.click(screen.getByTestId(`remediation-check-${finding.ruleId}`))
    }
    expect(screen.getByTestId('projected-score')).toHaveTextContent('Projected risk score: 0')
    expect(screen.getByTestId('remediation-progress')).toHaveTextContent(
      `${derived.findings.length} of ${derived.findings.length} completed`,
    )
  })

  it('orders items immediate, short term, planned', () => {
    loadFixture('C')
    const derived = getDerived()
    const ordered = orderRemediation(derived.findings)
    const groups = ordered.map((finding) =>
      finding.severity === 'critical'
        ? 0
        : finding.severity === 'high'
          ? 1
          : 2,
    )
    expect(groups).toEqual([...groups].sort((a, b) => a - b))
  })
})

describe('Audit — findings table', () => {
  it('filters with severity chips and exports the filtered list as CSV', async () => {
    const user = userEvent.setup()
    loadFixture('B')
    const derived = getDerived()
    render(<FindingsTable findings={derived.findings} />)

    expect(screen.getByTestId('findings-table')).toHaveTextContent(
      `${derived.findings.length} of ${derived.findings.length} findings shown`,
    )

    const criticals = derived.findings.filter((finding) => finding.severity === 'critical')
    expect(criticals.length).toBeGreaterThan(0)
    await user.click(screen.getByTestId('severity-chip-critical'))
    expect(screen.getByTestId('findings-table')).toHaveTextContent(
      `${criticals.length} of ${derived.findings.length} findings shown`,
    )

    const exportButton = screen.getByTestId('export-findings-csv')
    expect(exportButton).toBeEnabled()
    const rows = within(screen.getByTestId('findings-table')).getAllByRole('row')
    // header + filtered rows
    expect(rows.length).toBe(criticals.length + 1)
  })

  it('expands a row to reveal evidence, reference and recommendation', async () => {
    const user = userEvent.setup()
    loadFixture('B')
    const derived = getDerived()
    render(<FindingsTable findings={derived.findings} />)

    const first = derived.findings[0]
    const toggle = screen.getByTestId(`finding-toggle-${first.ruleId}`)
    expect(toggle).toHaveAttribute('aria-expanded', 'false')
    await user.click(toggle)
    expect(toggle).toHaveAttribute('aria-expanded', 'true')
    const panel = screen.getByTestId(`finding-panel-${first.ruleId}`)
    expect(panel).toHaveTextContent('Evidence')
    expect(panel).toHaveTextContent(first.evidence)
    expect(panel).toHaveTextContent(first.reference)
    expect(panel).toHaveTextContent(first.recommendation)
  })

  it('sorts by rule id and produces RFC 4180 CSV', () => {
    loadFixture('B')
    const derived = getDerived()
    const sorted = sortFindings(derived.findings, 'ruleId', 'asc')
    const ids = sorted.map((finding) => finding.ruleId)
    expect(ids).toEqual([...ids].sort())

    const csv = findingsToCsv(sorted)
    const lines = csv.split('\n')
    expect(lines[0]).toBe(
      'Rule ID,Severity,Category,STRIDE,Title,Evidence,Reference,Recommendation',
    )
    expect(lines.length).toBe(sorted.length + 1)
    expect(lines[1]).toContain(sorted[0].ruleId)
    // quoting: a field containing a comma must be wrapped in quotes
    const quoted = findingsToCsv([{ ...sorted[0], title: 'with, comma' }])
    expect(quoted).toContain('"with, comma"')
  })
})

describe('Audit — page composition', () => {
  it('renders every spec 10.4 section', () => {
    loadFixture('B')
    renderPage()
    expect(screen.getByTestId('page-audit')).toBeInTheDocument()
    expect(screen.getByTestId('audit-summary')).toBeInTheDocument()
    expect(screen.getByTestId('threat-matrix')).toBeInTheDocument()
    expect(screen.getByTestId('score-waterfall')).toBeInTheDocument()
    expect(screen.getByTestId('category-radar')).toBeInTheDocument()
    expect(screen.getByTestId('findings-table')).toBeInTheDocument()
    expect(screen.getByTestId('stride-breakdown')).toBeInTheDocument()
    expect(screen.getByTestId('remediation-plan')).toBeInTheDocument()
  })
})
