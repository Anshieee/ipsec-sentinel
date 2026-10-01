import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, beforeEach } from 'vitest'
import { InspectorPage } from '@/pages/InspectorPage'
import { useSentinel } from '@/store/useSentinel'
import { getFixture } from '@/api/fixtures'

function loadFixture(id: 'A' | 'B' | 'C'): ReturnType<typeof getFixture> {
  const analysis = getFixture(id)
  useSentinel.getState().setAnalysis(analysis)
  return analysis
}

describe('Inspector — pagination', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
    useSentinel.setState({ notifications: [], highlightId: undefined })
  })

  it('shows the first 100 rows and reports the correct range', () => {
    const analysis = loadFixture('B')
    render(<InspectorPage />)

    const status = screen.getByTestId('pagination-status')
    expect(status).toHaveTextContent('Showing 1 to 100 of 2,000 sampled packets')
    expect(status).toHaveTextContent(`of ${analysis.summary.packets.toLocaleString('en-US')} total`)

    const table = screen.getByTestId('packet-table')
    const bodyRows = within(table).getAllByRole('row').slice(1) // exclude header
    expect(bodyRows).toHaveLength(100)
  })

  it('advances to the next page and updates the range', async () => {
    const user = userEvent.setup()
    loadFixture('B')
    render(<InspectorPage />)

    await user.click(screen.getByTestId('next-page'))
    expect(screen.getByTestId('pagination-status')).toHaveTextContent('Showing 101 to 200 of 2,000 sampled packets')
  })

  it('respects the page-size selector', async () => {
    const user = userEvent.setup()
    loadFixture('B')
    render(<InspectorPage />)

    await user.selectOptions(screen.getByTestId('page-size'), '50')
    expect(screen.getByTestId('pagination-status')).toHaveTextContent('Showing 1 to 50 of 2,000 sampled packets')

    const table = screen.getByTestId('packet-table')
    const bodyRows = within(table).getAllByRole('row').slice(1)
    expect(bodyRows).toHaveLength(50)
  })
})

describe('Inspector — protocol filtering', () => {
  beforeEach(() => {
    useSentinel.getState().clear()
    useSentinel.setState({ notifications: [], highlightId: undefined })
  })

  it('filters to ESP only and reports the filtered count', async () => {
    const user = userEvent.setup()
    const analysis = loadFixture('B')
    const espCount = analysis.packets.filter((packet) => packet.proto === 'ESP').length
    expect(espCount).toBeGreaterThan(0)

    render(<InspectorPage />)
    const chip = screen.getByTestId('protocol-chip-ESP')
    expect(chip).toHaveAttribute('aria-pressed', 'false')
    await user.click(chip)
    expect(chip).toHaveAttribute('aria-pressed', 'true')

    const shown = Math.min(espCount, 100)
    expect(screen.getByTestId('pagination-status')).toHaveTextContent(
      `Showing 1 to ${shown} of ${espCount.toLocaleString('en-US')} sampled packets`,
    )
  })

  it('combines protocol chips and resets back to the full sample', async () => {
    const user = userEvent.setup()
    const analysis = loadFixture('B')
    const ikeCount = analysis.packets.filter((packet) => packet.proto === 'IKE').length

    render(<InspectorPage />)
    await user.click(screen.getByTestId('protocol-chip-IKE'))
    expect(screen.getByTestId('pagination-status')).toHaveTextContent(
      `Showing 1 to ${Math.min(ikeCount, 100)} of ${ikeCount.toLocaleString('en-US')} sampled packets`,
    )

    await user.click(screen.getByRole('button', { name: /reset filters/i }))
    expect(screen.getByTestId('pagination-status')).toHaveTextContent('Showing 1 to 100 of 2,000 sampled packets')
  })

  it('filters by free text across src, dst, SPI and info', async () => {
    const user = userEvent.setup()
    const analysis = loadFixture('B')
    const spi = analysis.packets.find((packet) => packet.spi)?.spi
    expect(spi).toBeTruthy()

    render(<InspectorPage />)
    const query = screen.getByTestId('packet-query')
    await user.type(query, String(spi))

    const expected = analysis.packets.filter((packet) =>
      `${packet.src} ${packet.dst} ${packet.spi ?? ''} ${packet.info}`.toLowerCase().includes(String(spi).toLowerCase()),
    ).length

    await waitFor(() =>
      expect(screen.getByTestId('pagination-status')).toHaveTextContent(
        `Showing 1 to ${Math.min(expected, 100)} of ${expected.toLocaleString('en-US')} sampled packets`,
      ),
    )
  })
})
