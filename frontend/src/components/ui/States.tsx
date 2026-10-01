import type { LucideIcon } from 'lucide-react'
import { Inbox, RotateCcw } from 'lucide-react'
import type { ReactNode } from 'react'
import { Button } from './Button'
import { cn } from './cn'

export interface EmptyStateProps {
  title: string
  body: string
  icon?: LucideIcon
  actions?: ReactNode
  className?: string
  testId?: string
}

export function EmptyState({ title, body, icon: Icon = Inbox, actions, className, testId }: EmptyStateProps) {
  return (
    <div
      className={cn('flex flex-col items-center justify-center rounded-card bg-surface p-8 text-center shadow-card', className)}
      data-testid={testId}
    >
      <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-raised text-muted">
        <Icon size={20} aria-hidden="true" />
      </span>
      <h2 className="text-sm font-semibold text-ink">{title}</h2>
      <p className="mt-1 max-w-md text-sm leading-5 text-muted">{body}</p>
      {actions ? <div className="mt-4 flex flex-wrap items-center justify-center gap-2">{actions}</div> : null}
    </div>
  )
}

export interface ErrorStateProps {
  message: string
  onRetry?: () => void
  retryLabel?: string
  className?: string
  testId?: string
}

export function ErrorState({ message, onRetry, retryLabel = 'Retry', className, testId }: ErrorStateProps) {
  return (
    <div
      role="alert"
      className={cn('flex flex-col items-center justify-center rounded-card bg-surface p-8 text-center shadow-card', className)}
      data-testid={testId}
    >
      <span className="mb-3 flex h-11 w-11 items-center justify-center rounded-full bg-danger/15 text-danger">
        <RotateCcw size={20} aria-hidden="true" />
      </span>
      <h2 className="text-sm font-semibold text-ink">Something went wrong</h2>
      <p className="mt-1 max-w-md font-mono text-xs leading-5 text-muted">{message}</p>
      {onRetry ? (
        <div className="mt-4">
          <Button variant="secondary" onClick={onRetry}>
            {retryLabel}
          </Button>
        </div>
      ) : null}
    </div>
  )
}
