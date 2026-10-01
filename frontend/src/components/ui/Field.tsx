import { cn } from './cn'

export type FieldSize = 'sm' | 'md'

/**
 * The one surface for text inputs and selects (DESIGN.md > Inputs, selects,
 * sliders, segmented controls, tabs): `base` inset fill, 1 px `line-strong`
 * border, 6 px radius, 36 px (`md`) or 28 px (`sm`) height. Focus colour is the
 * accent border; the shared focus ring comes from the global `:focus-visible`.
 */
export const fieldClasses = (size: FieldSize = 'md', className?: string): string =>
  cn(
    'rounded-control border border-line-strong bg-base/50 text-xs text-ink placeholder:text-muted',
    'focus:border-accent disabled:cursor-not-allowed disabled:opacity-60',
    size === 'sm' ? 'h-7 px-2' : 'h-9 px-3',
    className,
  )
