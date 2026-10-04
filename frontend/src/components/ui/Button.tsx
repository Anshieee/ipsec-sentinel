import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { cn } from './cn'

export type ButtonVariant = 'primary' | 'secondary' | 'ghost' | 'danger'
export type ButtonSize = 'sm' | 'md'

/**
 * One variant map for both `Button` and `IconButton` (DESIGN.md > Components >
 * Buttons). Interactive borders use `line-strong` so they clear 3:1; hover
 * steps the surface lighter, active steps it darker, disabled is 50 % opacity.
 *
 * The two filled variants lighten past the point where a white label still
 * clears 4.5:1, so their label inverts to `ink-inverse` while hovered and
 * returns to white when the fill steps back down on press. Accessibility in
 * every state outranks the direction of the hover step.
 */
export const BUTTON_VARIANT_CLASS: Record<ButtonVariant, string> = {
  // The single primary action is the light button: #fafafa bg, #080808
  // text (15.6:1), dimmer on hover. Blue is never a filled button.
  primary:
    'bg-white-accent text-bg border border-transparent hover:bg-white-accent/85 active:bg-white-accent/75',
  secondary:
    'bg-bg-card text-text-primary border border-border-strong hover:bg-border/40 active:bg-bg/50',
  ghost:
    'bg-transparent text-text-secondary border border-transparent hover:bg-bg-card hover:text-text-primary active:bg-border/40',
  danger:
    'bg-bg-card text-red border border-strong hover:bg-bg-hover active:bg-bg',
}

const SIZE_CLASS: Record<ButtonSize, string> = {
  sm: 'h-7 px-2 text-xs gap-1.5',
  md: 'h-9 px-3 text-sm gap-2',
}

export const buttonClasses = (variant: ButtonVariant = 'secondary', size: ButtonSize = 'md', className?: string): string =>
  cn(
    'inline-flex items-center justify-center rounded-control font-medium transition-colors',
    'disabled:cursor-not-allowed disabled:opacity-50',
    BUTTON_VARIANT_CLASS[variant],
    SIZE_CLASS[size],
    className,
  )

export interface ButtonProps extends ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant
  size?: ButtonSize
  children?: ReactNode
}

export function Button({ variant = 'secondary', size = 'md', className, type = 'button', ...rest }: ButtonProps) {
  return <button type={type} className={buttonClasses(variant, size, className)} {...rest} />
}
