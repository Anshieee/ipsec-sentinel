import { cn } from './cn'

/** Keyboard key hint. */
export function Kbd({ children, className }: { children: string; className?: string }) {
  return (
    <kbd
      className={cn(
        'inline-flex h-5 min-w-[20px] items-center justify-center rounded border border-border-strong bg-bg-card px-1.5',
        'font-mono text-2xs leading-none text-text-secondary',
        className,
      )}
    >
      {children}
    </kbd>
  )
}
