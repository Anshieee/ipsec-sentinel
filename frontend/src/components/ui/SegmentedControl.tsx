import { useRef } from 'react'
import type { KeyboardEvent, ReactNode } from 'react'
import { cn } from './cn'

export interface SegmentedOption<T extends string> {
  value: T
  label: ReactNode
  icon?: ReactNode
  title?: string
}

export interface SegmentedControlProps<T extends string> {
  options: SegmentedOption<T>[]
  value: T
  onChange: (value: T) => void
  ariaLabel: string
  className?: string
  compact?: boolean
  'data-testid'?: string
}

/** Radiogroup-style segmented control with roving tabindex and arrow keys. */
export function SegmentedControl<T extends string>({
  options,
  value,
  onChange,
  ariaLabel,
  className,
  compact,
  'data-testid': testId,
}: SegmentedControlProps<T>) {
  const refs = useRef<Record<string, HTMLButtonElement | null>>({})

  const move = (index: number) => {
    const bounded = (index + options.length) % options.length
    const option = options[bounded]
    if (!option) return
    onChange(option.value)
    refs.current[option.value]?.focus()
  }

  const onKeyDown = (e: KeyboardEvent<HTMLDivElement>) => {
    const current = options.findIndex((o) => o.value === value)
    if (e.key === 'ArrowRight' || e.key === 'ArrowDown') {
      e.preventDefault()
      move(current + 1)
    } else if (e.key === 'ArrowLeft' || e.key === 'ArrowUp') {
      e.preventDefault()
      move(current - 1)
    } else if (e.key === 'Home') {
      e.preventDefault()
      move(0)
    } else if (e.key === 'End') {
      e.preventDefault()
      move(options.length - 1)
    }
  }

  return (
    <div
      role="radiogroup"
      aria-label={ariaLabel}
      onKeyDown={onKeyDown}
      data-testid={testId}
      className={cn(
        'inline-flex items-center gap-0.5 rounded-control border border-line-strong bg-base/50 p-0.5',
        className,
      )}
    >
      {options.map((option) => {
        const selected = option.value === value
        return (
          <button
            key={option.value}
            type="button"
            role="radio"
            aria-checked={selected}
            tabIndex={selected ? 0 : -1}
            title={option.title}
            ref={(el) => {
              refs.current[option.value] = el
            }}
            onClick={() => onChange(option.value)}
            className={cn(
              'inline-flex items-center gap-1.5 rounded-[5px] font-medium transition-colors',
              compact ? 'h-6 px-2 text-2xs' : 'h-7 px-2.5 text-xs',
              selected
                ? 'bg-raised text-ink shadow-card'
                : 'text-muted hover:bg-raised/60 hover:text-ink active:bg-line/40',
            )}
          >
            {option.icon}
            {option.label}
          </button>
        )
      })}
    </div>
  )
}
