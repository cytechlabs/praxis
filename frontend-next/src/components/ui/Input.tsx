import React, { useId } from 'react';
import { Search } from 'lucide-react';

interface InputProps extends React.InputHTMLAttributes<HTMLInputElement> {
  label?: string;
  error?: string;
  icon?: React.ReactNode;
}

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
          w-full bg-surface-sunken border border-border rounded-md text-sm text-content
          transition-colors duration-150 px-3 py-2
          focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong
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
