/**
 * PRA-338: pure presentation logic for the thin-agent status card.
 *
 * Kept as a standalone module (no React) so the state->copy mapping is
 * unit-testable with the repo's node-env Vitest setup. The component
 * (ThinAgentStatusCard.tsx) only wires these into badges/layout.
 *
 * Two orthogonal signals, deliberately NOT merged:
 *   - lifecycle (agent_status): does this host have a thin agent, and in
 *     what enrollment state (not_enrolled / active / disabled / revoked).
 *   - liveness (agent_liveness): is the broker tunnel live right now
 *     (online / stale / offline / unknown). `unknown` (broker unreachable)
 *     is kept visibly distinct from `offline` (broker has no tunnel).
 *
 * Copy boundary: nothing here mentions the SSH access broker, CA trust,
 * principals hooks, or sshd - those belong to a separate panel. A test
 * enforces that boundary so the two never bleed together in the UI.
 */

import type { AgentLifecycle, AgentLiveness } from '../../services/systemService';

export type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'orange';

export interface SignalPresentation {
  label: string;
  variant: BadgeVariant;
  description: string;
}

const LIFECYCLE: Record<AgentLifecycle, SignalPresentation> = {
  not_enrolled: {
    label: 'Not enrolled',
    variant: 'neutral',
    description:
      'No Praxis thin agent is enrolled on this host. Non-interactive ops run over SSH.',
  },
  active: {
    label: 'Active',
    variant: 'success',
    description: 'A thin agent is enrolled and its certificate is active.',
  },
  disabled: {
    label: 'Disabled',
    variant: 'warning',
    description:
      'Thin-agent enrollment is paused (reversible). The broker refuses the tunnel until it is re-enabled.',
  },
  revoked: {
    label: 'Revoked',
    variant: 'danger',
    description: 'The thin-agent certificate has been revoked and cannot reconnect.',
  },
};

const LIVENESS: Record<AgentLiveness, SignalPresentation> = {
  online: {
    label: 'Online',
    variant: 'success',
    description: 'The broker holds a live tunnel with a recent heartbeat.',
  },
  stale: {
    label: 'Stale',
    variant: 'warning',
    description:
      'A tunnel is registered but its last heartbeat is past the liveness window.',
  },
  offline: {
    label: 'Offline',
    variant: 'neutral',
    description: 'The broker has no tunnel registered for this host.',
  },
  unknown: {
    label: 'Unknown',
    variant: 'warning',
    description:
      'The broker could not be reached to determine the tunnel state - this is not the same as offline.',
  },
};

/**
 * Presentation for a failed/slow status fetch. Rendered on the card when
 * the request errors so the page never breaks; deliberately an explicit
 * "unavailable", never a confident "offline" or "not enrolled".
 */
export const UNAVAILABLE_PRESENTATION: SignalPresentation = {
  label: 'Status unavailable',
  variant: 'warning',
  description:
    'Could not load thin-agent status. This does not mean the agent is offline - retry to refresh.',
};

export function lifecyclePresentation(
  status: AgentLifecycle,
  reasons?: { statusReason?: string | null; revocationReason?: string | null },
): SignalPresentation {
  const base = LIFECYCLE[status];
  if (status === 'revoked' && reasons?.revocationReason) {
    return { ...base, description: `${base.description} Reason: ${reasons.revocationReason}` };
  }
  if (status === 'disabled' && reasons?.statusReason) {
    return { ...base, description: `${base.description} Reason: ${reasons.statusReason}` };
  }
  return base;
}

export function livenessPresentation(liveness: AgentLiveness): SignalPresentation {
  return LIVENESS[liveness];
}

/** True when the host has a thin agent at all (any state but not_enrolled). */
export function hasThinAgent(status: AgentLifecycle): boolean {
  return status !== 'not_enrolled';
}

/**
 * Liveness is only a meaningful live signal when the agent is active - a
 * not_enrolled host has no tunnel, and disabled/revoked agents are refused
 * at the broker, so surfacing "offline" there would be noise.
 */
export function showsLiveness(status: AgentLifecycle): boolean {
  return status === 'active';
}
