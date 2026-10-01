import type { HTMLAttributes, ReactNode } from 'react'
import { cn } from './cn'

export interface CardProps extends HTMLAttributes<HTMLDivElement> {
  /** Removes the default padding for cards that manage their own layout. */
  flush?: boolean
}

export function Card({ className, flush, children, ...rest }: CardProps) {
  return (
    <section
      className={cn(
        'rounded-card bg-surface shadow-card',
        flush ? '' : 'p-[var(--card-pad)]',
        className,
      )}
      {...rest}
    >
      {children}
    </section>
  )
}

export interface CardHeaderProps {
  title: ReactNode
  description?: ReactNode
  actions?: ReactNode
  className?: string
  /** Heading level for the title. */
  as?: 'h2' | 'h3'
}

export function CardHeader({ title, description, actions, className, as = 'h2' }: CardHeaderProps) {
  const Heading = as
  return (
    <header className={cn('mb-3 flex items-start justify-between gap-3', className)}>
      <div className="min-w-0">
        <Heading className="truncate text-sm font-semibold leading-5 text-ink">{title}</Heading>
        {description ? <p className="mt-0.5 text-xs leading-4 text-muted">{description}</p> : null}
      </div>
      {actions ? <div className="flex shrink-0 items-center gap-2">{actions}</div> : null}
    </header>
  )
}
