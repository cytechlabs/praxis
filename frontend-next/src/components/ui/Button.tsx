import React from 'react';

type ButtonVariant = 'primary' | 'secondary' | 'danger' | 'ghost' | 'outline' | 'link';
type ButtonSize = 'sm' | 'md' | 'lg';

interface ButtonProps extends React.ButtonHTMLAttributes<HTMLButtonElement> {
  variant?: ButtonVariant;
  size?: ButtonSize;
  loading?: boolean;
  icon?: React.ReactNode;
  /**
   * Icon-only button: renders a square control. An accessible name is REQUIRED
   * (aria-label or title) - enforced in dev via a console warning.
   */
  iconOnly?: boolean;
}

// PRA-268/PRA-269 tokens: neutral primary/secondary (never red/blue); Signal Red
// only on `danger`. `link` is neutral underlined text with a Signal-Red hover.
// Focus is a neutral ring.
const variantStyles: Record<ButtonVariant, string> = {
  primary: 'bg-action hover:bg-action-hover text-action-fg border-transparent',
  // `secondary` and `outline` are the same neutral bordered control (secondary is
  // the preferred name; outline kept for back-compat).
  secondary: 'bg-action-secondary hover:bg-surface-overlay text-content border-border hover:border-border-strong',
  outline: 'bg-action-secondary hover:bg-surface-overlay text-content border-border hover:border-border-strong',
  danger: 'bg-danger hover:bg-brand-hover text-danger-fg border-transparent',
  ghost: 'bg-transparent hover:bg-surface-overlay text-content-muted hover:text-content border-transparent',
  link: 'bg-transparent border-transparent text-link hover:text-link-hover underline underline-offset-2',
};

const sizeStyles: Record<ButtonSize, string> = {
  sm: 'px-2.5 py-1 text-xs gap-1.5',
  md: 'px-3.5 py-2 text-sm gap-2',
  lg: 'px-5 py-2.5 text-sm gap-2',
};

// Square padding for icon-only buttons so dimensions stay stable across variants.
const iconOnlySizeStyles: Record<ButtonSize, string> = {
  sm: 'p-1.5',
  md: 'p-2',
  lg: 'p-2.5',
};

const Spinner = () => (
  <svg className="animate-spin h-4 w-4" viewBox="0 0 24 24" aria-hidden="true">
    <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4" fill="none" />
    <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4z" />
  </svg>
);

const Button = React.forwardRef<HTMLButtonElement, ButtonProps>(
  (
    { variant = 'outline', size = 'md', loading, icon, iconOnly, children, disabled, className = '', ...props },
    ref,
  ) => {
    if (
      process.env.NODE_ENV !== 'production' &&
      iconOnly &&
      !props['aria-label'] &&
      !props['aria-labelledby'] &&
      !props.title
    ) {
      console.warn('Button: icon-only buttons need an aria-label or title for accessibility.');
    }

    // `link` ignores the padded size scale; icon-only uses square padding.
    const sizing = variant === 'link' ? '' : iconOnly ? iconOnlySizeStyles[size] : sizeStyles[size];

    return (
      <button
        ref={ref}
        disabled={disabled || loading}
        className={`
          inline-flex items-center justify-center font-medium rounded-md border
          transition-all duration-150 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring
          disabled:opacity-50 disabled:cursor-not-allowed
          active:scale-[0.97]
          ${variantStyles[variant]}
          ${sizing}
          ${className}
        `}
        {...props}
      >
        {loading ? <Spinner /> : icon ? <span className="flex-shrink-0">{icon}</span> : null}
        {children}
      </button>
    );
  },
);

Button.displayName = 'Button';

export default Button;
