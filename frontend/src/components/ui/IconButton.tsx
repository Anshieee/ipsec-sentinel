import type { ButtonHTMLAttributes, ReactNode } from 'react'
import { cn } from './cn'
import { BUTTON_VARIANT_CLASS } from './Button'
import type { ButtonSize, ButtonVariant } from './Button'

const SIZE_CLASS: Record<ButtonSize, string> = {
  sm: 'h-7 w-7',
  md: 'h-9 w-9',
}

export interface IconButtonProps extends Omit<ButtonHTMLAttributes<HTMLButtonElement>, 'aria-label'> {
  /** Rendered as the accessible name and as the tooltip. Required. */
  label: string
  variant?: ButtonVariant
  size?: ButtonSize
  children: ReactNode
}

export function IconButton({
  label,
  variant = 'ghost',
  size = 'md',
  className,
  children,
  type = 'button',
  ...rest
}: IconButtonProps) {
  return (
    <button
      type={type}
      aria-label={label}
      title={label}
      className={cn(
        'inline-flex shrink-0 items-center justify-center rounded-control transition-colors',
        'disabled:cursor-not-allowed disabled:opacity-50',
        BUTTON_VARIANT_CLASS[variant],
        SIZE_CLASS[size],
        className,
      )}
      {...rest}
    >
      {children}
    </button>
  )
}
