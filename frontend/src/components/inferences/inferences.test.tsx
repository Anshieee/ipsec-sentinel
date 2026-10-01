import { fireEvent, render, screen } from '@testing-library/react'
import { MemoryRouter } from 'react-router-dom'
import { describe, expect, it, beforeEach } from 'vitest'
import { InferencesPage } from '@/pages/InferencesPage'
import { useSentinel } from '@/store/useSentinel'
import { getFixture } from '@/api/fixtures'
import { fmtPct } from '@/lib/format'

function topProbability(id: 'A' | 'B' | 'C'): number {
  const analysis = getFixture(id)
  const top = [...analysis.trafficClasses].sort((a, b) => b.probability - a.probability)[0]
  return top?.probability ?? 0
}

function renderPage(): ReturnType<typeof render> {
  return render(
    <MemoryRouter>
      <InferencesPage />
    </MemoryRouter>,
  )
}

describe('Inferences — uncertainty threshold slider', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
    useSentinel.getState().setSetting('uncertainThreshold', 0.6)
    useSentinel.setState({ notifications: [], highlightId: undefined })
  })

  it('toggles the Uncertain state when the threshold crosses the top-1 probability', () => {
    const analysis = getFixture('B')
    useSentinel.getState().setAnalysis(analysis)
    const top = topProbability('B')
    expect(top).toBeGreaterThan(0.6)

    renderPage()

    const slider = screen.getByTestId('threshold-slider')
    expect(slider).toHaveValue('0.6')
    expect(screen.getByTestId('threshold-state')).toHaveTextContent('Classification is confident')

    // 0.9 is above the top-1 probability: the classification becomes uncertain.
    fireEvent.change(slider, { target: { value: '0.9' } })
    expect(useSentinel.getState().settings.uncertainThreshold).toBe(0.9)
    expect(screen.getByTestId('threshold-state')).toHaveTextContent('Uncertain classification')

    // Dropping back below the top-1 probability clears the uncertain state.
    fireEvent.change(slider, { target: { value: '0.3' } })
    expect(screen.getByTestId('threshold-state')).toHaveTextContent('Classification is confident')
  })

  it('renders the parameter table with all sixteen parameters and confidence bars', () => {
    useSentinel.getState().setAnalysis(getFixture('A'))
    renderPage()

    const table = screen.getByTestId('inference-table')
    expect(table).toBeInTheDocument()
    const expanders = table.querySelectorAll('button[aria-expanded]')
    expect(expanders).toHaveLength(16)
    expect(table).toHaveTextContent('Direct parse')
    expect(table).toHaveTextContent('GBM classifier')
  })

  it('exposes the slider bounds and step from the spec', () => {
    useSentinel.getState().setAnalysis(getFixture('A'))
    renderPage()
    const slider = screen.getByTestId('threshold-slider')
    expect(slider).toHaveAttribute('min', '0.3')
    expect(slider).toHaveAttribute('max', '0.9')
    expect(slider).toHaveAttribute('step', '0.05')
    expect(slider).toHaveAccessibleName(/uncertainty threshold/i)
    expect(fmtPct(0.6, 0)).toBe('60%')
  })
})
