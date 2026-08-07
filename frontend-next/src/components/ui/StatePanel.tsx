import React from 'react';
import Button from './Button';
import EmptyState from './EmptyState';

/**
 * PRA-269 / PRA-274: shared loading / error / not-found panels so every page
 * renders the same states instead of ad-hoc spinners and one-off "failed to
 * load" markup. Loading uses the Praxis block-cursor terminal motif (PRA-268,
 * `.praxis-cursor` in globals.css) - no spinner/orb/illustration.
 */
export const LoadingState: React.FC<{ label?: string; className?: string }> = ({
  label = 'Loading',
  className = '',
}) => (
  <div
    className={`flex items-center justify-center gap-1 py-12 text-content-muted text-sm ${className}`}
    role="status"
    aria-live="polite"
    aria-busy="true"
  >
    <span>{label}</span>
    <span className="praxis-cursor" aria-hidden="true" />
  </div>
);

export const ErrorState: React.FC<{
  title?: string;
  description?: string;
  onRetry?: () => void;
  className?: string;
}> = ({ title, description, onRetry, className }) => (
  <EmptyState
    variant="error"
    title={title}
    description={description}
    className={className}
    action={
      onRetry ? (
        <Button variant="secondary" size="sm" onClick={onRetry}>
          Retry
        </Button>
      ) : undefined
    }
  />
);

export const NotFoundState: React.FC<{
  title?: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}> = ({ title = 'Not found', description, action, className }) => (
  <EmptyState
    variant="default"
    title={title}
    description={description}
    action={action}
    className={className}
  />
);
