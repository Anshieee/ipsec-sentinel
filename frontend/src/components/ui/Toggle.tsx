import { cn } from './cn'

export interface ToggleProps {
  checked: boolean
  onChange: (checked: boolean) => void
  label: string
  /** Renders the label next to the switch. */
  showLabel?: boolean
  description?: string
  disabled?: boolean
  className?: string
  'data-testid'?: string
}

/** `role="switch"` toggle with a visible label. */
export function Toggle({
  checked,
  onChange,
  label,
  showLabel = true,
  description,
  disabled,
  className,
  'data-testid': testId,
}: ToggleProps) {
  return (
    <div className={cn('flex items-start justify-between gap-3', className)}>
      {showLabel ? (
        <div className="min-w-0">
          <span className="text-sm font-medium text-text-primary">{label}</span>
          {description ? <p className="mt-0.5 text-xs leading-4 text-text-secondary">{description}</p> : null}
        </div>
      ) : null}
      <button
        type="button"
        role="switch"
        aria-checked={checked}
        aria-label={label}
        disabled={disabled}
        data-testid={testId}
        onClick={() => onChange(!checked)}
        className={cn(
          'relative inline-flex h-6 w-9 shrink-0 items-center rounded-full border transition-colors',
          'disabled:cursor-not-allowed disabled:opacity-50',
          checked ? 'border-blue bg-blue' : 'border-track bg-bg-card',
        )}
      >
        <span
          className={cn(
            'inline-block h-4 w-4 rounded-full bg-white transition-transform',
            checked ? 'translate-x-[17px]' : 'translate-x-[3px]',
          )}
          aria-hidden="true"
        />
      </button>
    </div>
  )
}
