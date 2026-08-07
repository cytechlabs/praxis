import React from 'react';
import { humanizeStatus } from '@/utils/humanize';

export type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'orange';

interface BadgeProps {
  children: React.ReactNode;
  variant?: BadgeVariant;
  pulse?: boolean;
  className?: string;
}

// PRA-268: status roles use semantic tokens (theme-aware). `danger` is Signal
// Red; `info`/`neutral` are neutral (never blue). `orange` stays a raw
// non-red/non-blue accent for the few attention states that use it.
const variantStyles: Record<BadgeVariant, string> = {
  success: 'bg-success/15 text-success border-success/30',
  warning: 'bg-warning/15 text-warning border-warning/30',
  danger: 'bg-danger/15 text-danger border-danger/40',
  info: 'bg-info/15 text-info border-info/30',
  neutral: 'bg-content-subtle/15 text-content-muted border-border-strong',
  orange: 'bg-orange-500/15 text-orange-400 border-orange-500/30',
};

// PRA-271: the ONE state -> variant convention. Case-insensitive; matches the
// raw enum values the backend emits (underscored forms included) so the same
// concept renders the same variant everywhere via StatusBadge. Unknown values
// fall through to neutral (never invented color).
export function statusToBadgeVariant(status: string): BadgeVariant {
  const s = status.toLowerCase();
  if (['active', 'completed', 'success', 'succeeded', 'passed', 'pass', 'enabled',
       'healthy', 'connected', 'reachable', 'online', 'up', 'enrolled', 'compliant',
       'ok', 'rollback_completed', 'resolved', 'approved'].includes(s)) return 'success';
  if (['inactive', 'decommissioned', 'cancelled', 'canceled', 'off', 'disabled',
       'unknown', 'not_applicable', 'na', 'n_a', 'not_enrolled', 'disconnected',
       'never_checked', 'not_checked', 'skipped', 'none', 'draft'].includes(s)) return 'neutral';
  if (['maintenance', 'pending', 'pending_enrollment', 'paused', 'warning', 'scheduled',
       'auth_failed', 'degraded', 'partial', 'stale', 'expiring', 'rollback_attempted',
       'needs_attention', 'held'].includes(s)) return 'warning';
  if (['failed', 'error', 'unreachable', 'killed', 'rejected', 'blocked', 'timeout',
       'rollback_attempted_failed', 'rollback_failed', 'critical', 'fail',
       'noncompliant', 'non_compliant', 'expired', 'offline', 'down',
       'dead_letter'].includes(s)) return 'danger';
  if (['running', 'in_progress', 'queued', 'processing', 'reconciling', 'syncing',
       'connecting', 'scanning'].includes(s)) return 'info';
  return 'neutral';
}

const Badge: React.FC<BadgeProps> = ({ children, variant = 'neutral', pulse, className = '' }) => {
  return (
    <span
      className={`
        inline-flex items-center gap-1.5 px-2 py-0.5 rounded-full text-xs font-medium border
        ${variantStyles[variant]}
        ${className}
      `}
    >
      {pulse && (
        <span className="relative flex h-1.5 w-1.5">
          <span className={`animate-ping absolute inline-flex h-full w-full rounded-full opacity-75 ${
            variant === 'danger' ? 'bg-danger' : variant === 'warning' ? 'bg-warning' : 'bg-content-muted'
          }`} />
          <span className={`relative inline-flex rounded-full h-1.5 w-1.5 ${
            variant === 'danger' ? 'bg-danger' : variant === 'warning' ? 'bg-warning' : 'bg-content-muted'
          }`} />
        </span>
      )}
      {children}
    </span>
  );
};

/**
 * PRA-269: a status string in one step - shared variant mapping + humanized
 * (sentence-case) label - so the same enum reads identically everywhere. Pass a
 * raw status (e.g. `in_progress`) and get `<Badge variant="info">In progress`.
 */
export const StatusBadge: React.FC<{
  status: string;
  pulse?: boolean;
  className?: string;
}> = ({ status, pulse, className }) => (
  <Badge variant={statusToBadgeVariant(status)} pulse={pulse} className={className}>
    {humanizeStatus(status)}
  </Badge>
);

export default Badge;
