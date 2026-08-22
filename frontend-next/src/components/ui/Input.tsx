import React, { useId } from 'react';
import { Search } from 'lucide-react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

/*
 * Theme-critical styling every native `<select>` must carry.
 *
 * A native option list is painted by the browser, not by the page. The browser
 * derives it from the control's used background and text colors, so a control
 * whose background is translucent leaves the list composited against the
 * browser's own default surface instead of the app surface. That default is
 * decided by the platform and the browser theme, so light option text can land
 * on a light list and become unreadable. Options also default to a transparent
 * background of their own, which leaves the same decision to the browser even
 * when the closed control looks correct.
 *
 * This contract pins both halves: an opaque semantic surface on the control and
 * explicit colors on the option and optgroup children, so the closed control and
 * the expanded list always resolve to the same theme-aware pair.
 *
 * It deliberately carries no geometry. Width, padding, radius and font size stay
 * at the call site so adopting it never changes a form's layout.
 */
export const nativeSelectClass =
  'bg-surface-sunken text-content ' +
  'focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong ' +
  'disabled:cursor-not-allowed disabled:opacity-60 ' +
  '[&_option]:bg-surface-sunken [&_option]:text-content ' +
  '[&_optgroup]:bg-surface-sunken [&_optgroup]:text-content-muted';

const Input = React.forwardRef<HTMLInputElement, InputProps>(
  ({ label, error, icon, className = '', id, ...props }, ref) => {
    const generatedId = useId();
    const inputId = id || generatedId;
    const errorId = error ? `${inputId}-error` : undefined;
    return (
      <div className="space-y-1">
        {label && (
          <label
            htmlFor={inputId}
            className="block text-xs font-medium text-content-muted uppercase tracking-wider"
          >
            {label}
          </label>
        )}
        <div className="relative">
          {icon && (
            <span className="absolute left-3 top-1/2 -translate-y-1/2 text-content-subtle">
              {icon}
            </span>
          )}
          <input
            ref={ref}
            id={inputId}
            aria-invalid={error ? true : undefined}
            aria-describedby={errorId}
            className={`
              w-full bg-surface-sunken border rounded-md text-sm text-content
              placeholder:text-content-subtle transition-colors duration-150
              focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong
              ${error ? 'border-danger' : 'border-border'}
              ${icon ? 'pl-9' : 'pl-3'} pr-3 py-2
              ${className}
            `}
            {...props}
          />
        </div>
        {error && (
          <p id={errorId} className="text-xs text-danger">
            {error}
          </p>
        )}
      </div>
    );
  }
);

Input.displayName = 'Input';

export const SearchInput: React.FC<React.InputHTMLAttributes<HTMLInputElement>> = (props) => {
  return <Input icon={<Search size={15} />} aria-label={props['aria-label'] || 'Search'} {...props} />;
};

export const Select: React.FC<
  React.SelectHTMLAttributes<HTMLSelectElement> & { label?: string }
> = ({ label, className = '', children, id, ...props }) => {
  const generatedId = useId();
  const selectId = id || generatedId;
  return (
    <div className="space-y-1">
      {label && (
        <label
          htmlFor={selectId}
          className="block text-xs font-medium text-content-muted uppercase tracking-wider"
        >
          {label}
        </label>
      )}
      <select
        id={selectId}
        className={`
          w-full border border-border rounded-md text-sm
          transition-colors duration-150 px-3 py-2
          ${nativeSelectClass}
          ${className}
        `}
        {...props}
      >
        {children}
      </select>
    </div>
  );
};

export default Input;
