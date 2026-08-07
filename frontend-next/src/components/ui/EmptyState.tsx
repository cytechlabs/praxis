import React from 'react';
import { Inbox, Search, Activity, AlertTriangle, Lock, ShieldOff, SlidersHorizontal } from 'lucide-react';

/**
 * PRA-269: shared empty/blank-state surface with presets for the states operator
 * pages actually hit. `variant` sets a sensible icon + default copy; `title` /
 * `description` / `action` override per use.
 */
export type EmptyStateVariant =
  | 'default' // nothing here yet
  | 'not-configured' // a feature that needs setup before it does anything
  | 'no-activity' // feature works, no activity yet
  | 'no-results' // a search/filter matched nothing (filtered to zero)
  | 'error' // data unavailable / failed to load
  | 'restricted' // permission restricted
  | 'locked'; // paid/entitlement locked

interface Preset {
  icon: React.ReactNode;
  title: string;
  description?: string;
}

const PRESETS: Record<EmptyStateVariant, Preset> = {
  default: { icon: <Inbox size={24} />, title: 'Nothing here yet' },
  'not-configured': {
    icon: <SlidersHorizontal size={24} />,
    title: 'Not configured yet',
    description: 'This isn’t set up yet. Configure it to start using it.',
  },
  'no-activity': { icon: <Activity size={24} />, title: 'No activity yet' },
  'no-results': {
    icon: <Search size={24} />,
    title: 'No matches',
    description: 'No items match the current filters. Try clearing or adjusting them.',
  },
  error: {
    icon: <AlertTriangle size={24} />,
    title: 'Something went wrong',
    description: 'This data could not be loaded. Retry, or check back shortly.',
  },
  restricted: {
    icon: <ShieldOff size={24} />,
    title: 'Access restricted',
    description: 'You do not have permission to view this. Ask an administrator for access.',
  },
  locked: {
    icon: <Lock size={24} />,
    title: 'Not included in your plan',
    description: 'This feature requires an upgraded Praxis plan.',
  },
};

interface EmptyStateProps {
  variant?: EmptyStateVariant;
  icon?: React.ReactNode;
  title?: string;
  description?: string;
  action?: React.ReactNode;
  className?: string;
}

const EmptyState: React.FC<EmptyStateProps> = ({
  variant = 'default',
  icon,
  title,
  description,
  action,
  className = '',
}) => {
  const preset = PRESETS[variant];
  const resolvedTitle = title ?? preset.title;
  const resolvedDescription = description ?? preset.description;
  const resolvedIcon = icon ?? preset.icon;
  const iconTone = variant === 'error' ? 'text-danger' : 'text-content-subtle';

  return (
    <div className={`flex flex-col items-center justify-center py-12 text-center ${className}`}>
      <div className="p-3 rounded-full bg-surface-overlay mb-4">
        <span className={iconTone}>{resolvedIcon}</span>
      </div>
      <h3 className="text-sm font-medium text-content mb-1">{resolvedTitle}</h3>
      {resolvedDescription && (
        <p className="text-xs text-content-subtle max-w-sm">{resolvedDescription}</p>
      )}
      {action && <div className="mt-4">{action}</div>}
    </div>
  );
};

export default EmptyState;
