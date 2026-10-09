import type { ButtonHTMLAttributes } from 'react'
import { Link, type LinkProps } from 'react-router'
import { buttonClassName, type ButtonStyleOptions } from './buttonStyles'

type ButtonProps = ButtonHTMLAttributes<HTMLButtonElement> & ButtonStyleOptions

/** A button. Defaults to `type="button"` so it never submits a form by accident; pass `type="submit"` explicitly. */
export function Button({ variant, size, fullWidth, className = '', type = 'button', ...props }: ButtonProps) {
  return <button type={type} className={`${buttonClassName({ variant, size, fullWidth })} ${className}`} {...props} />
}

type ButtonLinkProps = LinkProps & ButtonStyleOptions

/** In-app navigation that looks like a button (for calls to action). */
export function ButtonLink({ variant, size, fullWidth, className = '', ...props }: ButtonLinkProps) {
  return <Link className={`${buttonClassName({ variant, size, fullWidth })} ${className}`} {...props} />
}
