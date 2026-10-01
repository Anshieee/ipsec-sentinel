import { fireEvent, render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, beforeEach } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { KpiBar } from '@/components/overview/KpiBar'
import { UploadZone } from '@/components/overview/UploadZone'
import { ClassChart } from '@/components/overview/ClassChart'
import { OverviewBottom } from '@/components/overview/OverviewBottom'
import { useSentinel } from '@/store/useSentinel'
import { getFixture } from '@/api/fixtures'
import { PARSE_ERROR } from '@/api/mock'

function loadFixture(id: 'A' | 'B' | 'C'): ReturnType<typeof getFixture> {
  const analysis = getFixture(id)
  useSentinel.getState().setAnalysis(analysis)
  return analysis
}

describe('Overview — risk gauge', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
    useSentinel.getState().setSearchQuery('')
    useSentinel.setState({ notifications: [], highlightId: undefined })
  })

  it('exposes aria-valuenow matching the rule engine score', () => {
    const analysis = loadFixture('B')
    render(
      <MemoryRouter>
        <KpiBar analysis={analysis} />
      </MemoryRouter>,
    )
    const gauge = screen.getByTestId('risk-gauge')
    expect(gauge).toHaveAttribute('role', 'meter')
    expect(gauge).toHaveAttribute('aria-valuenow', String(analysis.riskScore))
    expect(gauge).toHaveAttribute('aria-valuemin', '0')
    expect(gauge).toHaveAttribute('aria-valuemax', '100')
    expect(gauge).toHaveAttribute('aria-valuetext', `${analysis.riskScore} out of 100, high risk`)
  })
})

describe('Overview — threat matrix filter toggle', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
    useSentinel.getState().setSearchQuery('')
    useSentinel.setState({ notifications: [], highlightId: undefined })
  })

  it('toggles a cell filter on and off and clears it', async () => {
    const user = userEvent.setup()
    loadFixture('B')
    render(
      <MemoryRouter>
        <OverviewBottom />
      </MemoryRouter>,
    )

    const matrix = screen.getByTestId('threat-matrix')
    const cells = within(matrix)
      .getAllByRole('button')
      .filter((button) => !button.hasAttribute('disabled'))
    expect(cells.length).toBeGreaterThan(0)
    const cell = cells[0]

    expect(cell).toHaveAttribute('aria-pressed', 'false')
    await user.click(cell)
    expect(cell).toHaveAttribute('aria-pressed', 'true')
    expect(screen.getByTestId('findings-list')).toHaveTextContent('Filtered to')

    await user.click(screen.getByTestId('clear-matrix-filter'))
    expect(cell).toHaveAttribute('aria-pressed', 'false')
    expect(screen.getByTestId('findings-list')).not.toHaveTextContent('Filtered to')
  })
})

describe('Overview — upload validation error', () => {
  beforeEach(() => {
    useSentinel.getState().resetUpload()
    useSentinel.setState({ notifications: [] })
  })

  it('shows the inline role="alert" message for an unsupported extension', async () => {
    render(<UploadZone />)
    const input = screen.getByTestId('upload-zone-input')
    const file = new File(['notes'], 'notes.txt', { type: 'text/plain' })

    fireEvent.change(input, { target: { files: [file] } })

    await waitFor(() => expect(screen.getByTestId('upload-error')).toBeInTheDocument())
    const alert = screen.getByRole('alert')
    expect(alert).toHaveTextContent('Unsupported file type. Upload a .pcap or .pcapng trace.')
    expect(screen.queryByRole('progressbar')).toBeNull()
  })

  it('surfaces the parse failure message from the simulated pipeline', async () => {
    useSentinel.setState({ upload: { status: 'error', progress: 0, error: PARSE_ERROR } })
    render(<UploadZone />)
    expect(screen.getByRole('alert')).toHaveTextContent(PARSE_ERROR)
  })
})

describe('Overview — uncertain classification banner', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
    useSentinel.setState({ notifications: [], highlightId: undefined })
  })

  it('shows the banner for fixture C below the 0.6 threshold', () => {
    const analysis = loadFixture('C')
    const top = [...analysis.trafficClasses].sort((a, b) => b.probability - a.probability)[0]
    expect(top?.probability).toBeLessThan(0.6)

    render(<ClassChart classes={analysis.trafficClasses} />)
    const banner = screen.getByTestId('uncertain-banner')
    expect(banner).toHaveTextContent('Uncertain classification')
    expect(banner).toHaveTextContent(
      'The top prediction is below the confidence threshold; treat the traffic type as unknown.',
    )
    const items = within(banner).getAllByRole('listitem')
    expect(items.length).toBe(3)
  })

  it('hides the banner for fixture B above the threshold', () => {
    const analysis = loadFixture('B')
    render(<ClassChart classes={analysis.trafficClasses} />)
    expect(screen.queryByTestId('uncertain-banner')).toBeNull()
  })
})
