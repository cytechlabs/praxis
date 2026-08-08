/**
 * PRA-153 #4: TransportBadge.
 *
 * Renders the per-host transport state derived by the backend's
 * _compute_badge helper. Compact form is for the systems list /
 * grid (just the colored pill); full form is for the host detail
 * page (pill + secondary "preference" context line).
 *
 * Badge vocabulary (matches backend):
 *   agent_connected    pref=auto, tunnel healthy
 *   agent_forced       pref=agent, tunnel healthy
 *   agent_unavailable  pref=agent, tunnel down/stale/unregistered
 *   ssh_forced         pref=ssh
 *   ssh_fallback       pref=auto, tunnel down/stale/unregistered
 *   unknown            broker health call itself failed - must NOT
 *                      silently imply agent is usable
 */

import React from 'react';
import Badge from '../ui/Badge';
import { BadgeState, TransportPreference } from '../../services/systemService';

type Variant = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'orange';

interface BadgeMeta {
  variant: Variant;
  label: string;
  pulse?: boolean;
}

const META: Record<BadgeState, BadgeMeta> = {
  agent_connected: { variant: 'success', label: 'Agent connected' },
  agent_forced: { variant: 'success', label: 'Agent forced' },
  // Forced pref + tunnel down means ops will fail - danger, not warning.
  agent_unavailable: { variant: 'danger', label: 'Agent unavailable', pulse: true },
  ssh_forced: { variant: 'info', label: 'SSH forced' },
  ssh_fallback: { variant: 'info', label: 'SSH fallback' },
  // unknown = couldn't reach the broker. Yellow is the right read:
  // we don't know enough to say "OK" or "broken".
  unknown: { variant: 'warning', label: 'Unknown' },
};

interface Props {
  badgeState: BadgeState | null | undefined;
  /** When true, render only the colored pill (systems list). */
  compact?: boolean;
  /** Operator routing intent. Shown as secondary context in the
   *  full variant ("(pref: agent)") so users see why the badge says
   *  what it does. Optional - falls back to no secondary line. */
  transportPreference?: TransportPreference | null;
  className?: string;
}

const TransportBadge: React.FC<Props> = ({
  badgeState,
  compact = false,
  transportPreference,
  className = '',
}) => {
  // Loading / pre-fetch placeholder - kept neutral so the row
  // doesn't flicker between colors as health calls settle.
  if (!badgeState) {
    return (
      <Badge variant="neutral" className={className}>
        {compact ? '-' : 'Loading…'}
      </Badge>
    );
  }

  const meta = META[badgeState];

  if (compact) {
    return (
      <Badge variant={meta.variant} pulse={meta.pulse} className={className}>
        {meta.label}
      </Badge>
    );
  }

  return (
    <div className={`inline-flex flex-col items-start gap-1 ${className}`}>
      <Badge variant={meta.variant} pulse={meta.pulse}>
        {meta.label}
      </Badge>
      {transportPreference && (
        <span className="text-xs text-content-subtle">
          Preference: <span className="text-content-muted">{transportPreference}</span>
        </span>
      )}
    </div>
  );
};

export default TransportBadge;
