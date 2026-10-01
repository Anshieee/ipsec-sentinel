import { render, screen, waitFor, within } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it, beforeEach, vi } from 'vitest'
import { MemoryRouter } from 'react-router-dom'
import { Header } from '@/components/layout/Header'
import { useSentinel } from '@/store/useSentinel'
import { getFixture } from '@/api/fixtures'
import { resetFilePicker } from '@/lib/filePicker'

function renderHeader(route = '/'): ReturnType<typeof render> {
  return render(
    <MemoryRouter initialEntries={[route]}>
      <Header />
    </MemoryRouter>,
  )
}

function resetStore(): void {
  const state = useSentinel.getState()
  state.clear()
  state.setSearchQuery('')
  state.setHighlightId(undefined)
  state.setReportOpen(false)
  resetFilePicker()
  useSentinel.setState({ notifications: [] })
}

describe('Header — global search results', () => {
  beforeEach(resetStore)

  it('shows "No analysis loaded" when there is no analysis', async () => {
    const user = userEvent.setup()
    renderHeader()
    await user.click(screen.getByTestId('global-search-input'))
    expect(screen.getByTestId('search-results')).toHaveTextContent('No analysis loaded')
  })

  it('returns grouped results capped at 3 per group and 9 overall', async () => {
    const user = userEvent.setup()
    useSentinel.getState().setAnalysis(getFixture('B'))
    renderHeader()

    const input = screen.getByTestId('global-search-input')
    await user.click(input)
    await user.type(input, 'esp')

    const results = screen.getByTestId('search-results')
    await waitFor(() => expect(within(results).getAllByRole('option').length).toBeGreaterThan(0))

    const options = within(results).getAllByRole('option')
    expect(options.length).toBeLessThanOrEqual(9)

    const counts = new Map<string, number>()
    for (const option of options) {
      const group = option.parentElement
      const label = group?.querySelector('p')?.textContent ?? 'unknown'
      counts.set(label, (counts.get(label) ?? 0) + 1)
    }
    for (const [, count] of counts) {
      expect(count).toBeLessThanOrEqual(3)
    }
    expect(counts.size).toBeGreaterThan(1)
  })

  it('navigates on Enter and sets highlightId', async () => {
    const user = userEvent.setup()
    useSentinel.getState().setAnalysis(getFixture('A'))
    renderHeader('/')

    const input = screen.getByTestId('global-search-input')
    await user.click(input)
    await user.type(input, 'rekey')

    const results = screen.getByTestId('search-results')
    await waitFor(() => expect(within(results).getAllByRole('option').length).toBeGreaterThan(0))

    await user.keyboard('{ArrowDown}')
    await user.keyboard('{Enter}')

    await waitFor(() => expect(useSentinel.getState().highlightId).toBeTruthy())
    expect(useSentinel.getState().searchQuery).toBe('')
  })

  it('closes the dropdown with Escape', async () => {
    const user = userEvent.setup()
    useSentinel.getState().setAnalysis(getFixture('A'))
    renderHeader()

    const input = screen.getByTestId('global-search-input')
    await user.click(input)
    await user.type(input, 'aes')
    await waitFor(() => expect(screen.getByTestId('search-results')).toBeTruthy())

    await user.keyboard('{Escape}')
    await waitFor(() => expect(screen.queryByTestId('search-results')).toBeNull())
  })
})

describe('Header — export enablement', () => {
  beforeEach(resetStore)

  it('disables export actions until an analysis exists', () => {
    renderHeader()
    const group = screen.getByTestId('export-group')
    expect(within(group).getByTestId('export-pdf')).toBeDisabled()
    expect(within(group).getByTestId('export-json')).toBeDisabled()
  })

  it('enables export actions once an analysis is loaded', () => {
    useSentinel.getState().setAnalysis(getFixture('A'))
    renderHeader()
    const group = screen.getByTestId('export-group')
    expect(within(group).getByTestId('export-pdf')).toBeEnabled()
    expect(within(group).getByTestId('export-json')).toBeEnabled()
  })

  it('exports the analysis as a Blob-backed JSON download', async () => {
    const user = userEvent.setup()
    useSentinel.getState().setAnalysis(getFixture('A'))
    renderHeader()

    const createObjectURL = vi.fn(() => 'blob:mock')
    const revokeObjectURL = vi.fn()
    Object.defineProperty(URL, 'createObjectURL', { value: createObjectURL, configurable: true })
    Object.defineProperty(URL, 'revokeObjectURL', { value: revokeObjectURL, configurable: true })

    await user.click(screen.getByTestId('export-json'))
    await waitFor(() => expect(createObjectURL).toHaveBeenCalledTimes(1))
    expect(useSentinel.getState().notifications[0]?.message).toBe('Exported analysis JSON.')
  })
})
