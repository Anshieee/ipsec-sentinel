import { describe, expect, it, vi } from 'vitest'
import { render, screen } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { Button } from './Button'
import { Badge } from './Badge'
import { Tabs } from './Tabs'

describe('UI primitives smoke', () => {
  it('renders a Button with its label and handles clicks', async () => {
    const onClick = vi.fn()
    render(<Button onClick={onClick}>Upload trace</Button>)
    const button = screen.getByRole('button', { name: 'Upload trace' })
    expect(button).toBeInTheDocument()
    await userEvent.click(button)
    expect(onClick).toHaveBeenCalledTimes(1)
  })

  it('renders a Badge with the given tone classes', () => {
    render(
      <Badge tone="danger" data-testid="badge">
        Critical
      </Badge>,
    )
    const badge = screen.getByTestId('badge')
    expect(badge).toHaveTextContent('Critical')
    expect(badge.className).toContain('border-danger/40')
  })

  it('renders a Tabs tablist and supports arrow-key navigation', async () => {
    const onChange = vi.fn()
    render(
      <Tabs
        ariaLabel="Report sections"
        idPrefix="report"
        value="executive"
        onChange={onChange}
        items={[
          { id: 'executive', label: 'Executive' },
          { id: 'technical', label: 'Technical' },
        ]}
      />,
    )
    const tablist = screen.getByRole('tablist', { name: 'Report sections' })
    expect(tablist).toBeInTheDocument()
    const executive = screen.getByRole('tab', { name: 'Executive' })
    expect(executive).toHaveAttribute('aria-selected', 'true')
    expect(executive).toHaveAttribute('tabindex', '0')
    executive.focus()
    await userEvent.keyboard('{ArrowRight}')
    expect(onChange).toHaveBeenCalledWith('technical')
  })
})
