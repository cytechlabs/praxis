import React from 'react';

/**
 * PRA-269: shared form field wrapper - consistent label / required marker /
 * helper / error for any control (checkbox, radio, custom inputs). The `Input`
 * primitive already renders its own label+error; use `FormField` to give the
 * same treatment to controls that don't.
 */
export const FormField: React.FC<{
  label?: string;
  htmlFor?: string;
  required?: boolean;
  helper?: string;
  error?: string;
  children: React.ReactNode;
  className?: string;
}> = ({ label, htmlFor, required, helper, error, children, className = '' }) => (
  <div className={`space-y-1 ${className}`}>
    {label && (
      <label
        htmlFor={htmlFor}
        className="block text-xs font-medium text-content-muted uppercase tracking-wider"
      >
        {label}
        {required && (
          <span className="text-danger ml-0.5" aria-hidden="true">
            *
          </span>
        )}
      </label>
    )}
    {children}
    {helper && !error && <p className="text-xs text-content-subtle">{helper}</p>}
    {error && <p className="text-xs text-danger">{error}</p>}
  </div>
);

/**
 * A right-aligned (by default) row of form buttons with consistent spacing -
 * pass a submit Button (with `loading` for submitting feedback) + a cancel.
 */
export const FormActions: React.FC<{
  children: React.ReactNode;
  align?: 'left' | 'right';
  className?: string;
}> = ({ children, align = 'right', className = '' }) => (
  <div
    className={`flex items-center gap-2 pt-2 ${align === 'right' ? 'justify-end' : ''} ${className}`}
  >
    {children}
  </div>
);

export default FormField;
