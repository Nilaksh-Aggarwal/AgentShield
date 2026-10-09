export type ButtonVariant = 'primary' | 'secondary' | 'ghost'
export type ButtonSize = 'sm' | 'md'

export interface ButtonStyleOptions {
  variant?: ButtonVariant
  size?: ButtonSize
  fullWidth?: boolean
}

// `not-disabled:` rather than `enabled:` so the same classes work on links, which have no :enabled state.
const variantClass: Record<ButtonVariant, string> = {
  primary: 'bg-primary text-primary-foreground shadow-sm not-disabled:hover:bg-primary/90',
  secondary: 'border border-border bg-surface text-foreground shadow-xs not-disabled:hover:bg-background',
  ghost: 'text-muted not-disabled:hover:bg-background not-disabled:hover:text-foreground',
}

// `md` meets the 44 × 44 px touch-target size; use `sm` only where pointer precision can be assumed.
const sizeClass: Record<ButtonSize, string> = {
  sm: 'h-8 px-3 text-sm',
  md: 'h-11 px-4 text-sm',
}

/** Classes shared by `Button` and `ButtonLink`, so an action looks the same whether it submits or navigates. */
export function buttonClassName({ variant = 'primary', size = 'md', fullWidth = false }: ButtonStyleOptions = {}): string {
  return [
    'inline-flex cursor-pointer items-center justify-center gap-2 rounded-md font-semibold no-underline transition-colors',
    'disabled:cursor-not-allowed disabled:opacity-50',
    variantClass[variant],
    sizeClass[size],
    fullWidth ? 'w-full' : '',
  ].join(' ')
}
