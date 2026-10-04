import { cn } from './cn'

export interface SkeletonProps {
  className?: string
  /** Number of stacked lines. */
  lines?: number
  /** Circular variant for avatars. */
  circle?: boolean
}

/** Loading placeholder. Layout-matching skeletons, never a lone spinner. */
export function Skeleton({ className, lines = 1, circle }: SkeletonProps) {
  if (circle) {
    return <span className={cn('block animate-shimmer rounded-full bg-bg-card', className)} aria-hidden="true" />
  }
  if (lines > 1) {
    return (
      <span className="flex flex-col gap-2" aria-hidden="true">
        {Array.from({ length: lines }, (_, i) => (
          <span
            key={i}
            className={cn('block h-3 animate-shimmer rounded bg-bg-card', className)}
            style={{ width: i === lines - 1 ? '60%' : '100%' }}
          />
        ))}
      </span>
    )
  }
  return <span className={cn('block h-3 animate-shimmer rounded bg-bg-card', className)} aria-hidden="true" />
}

/** Card-shaped skeleton used while a panel loads. */
export function SkeletonCard({ rows = 4, className }: { rows?: number; className?: string }) {
  return (
    <div className={cn('rounded-card border border-border bg-bg-elevated p-4', className)} aria-hidden="true">
      <Skeleton className="mb-4 h-4 w-1/3" />
      <div className="flex flex-col gap-3">
        {Array.from({ length: rows }, (_, i) => (
          <Skeleton key={i} className="h-3 w-full" />
        ))}
      </div>
    </div>
  )
}
