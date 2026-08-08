/**
 * PRA-153 #4: TransportPreferenceToggle.
 *
 * Three-state segmented control (auto / ssh / agent) for the host
 * detail page. Admin-only - the consumer is responsible for gating
 * on isAdmin before rendering. Switching to "agent" prompts a
 * confirmation because force-agent disables SSH fallback for
 * supported ops; switching to ssh or auto skips confirmation.
 *
 * The component is controlled - parent owns the value and decides
 * what to do with onChange (typically PATCH the backend, then
 * refetch agent-health).
 */

import React, { useState } from 'react';
import { TransportPreference } from '../../services/systemService';
import ConfirmModal from '../ui/ConfirmModal';

interface Props {
  value: TransportPreference;
  onChange: (next: TransportPreference) => void | Promise<void>;
  disabled?: boolean;
}

const OPTIONS: { value: TransportPreference; label: string; help: string }[] = [
  { value: 'auto', label: 'Auto', help: 'Agent if connected, SSH otherwise' },
  { value: 'ssh', label: 'SSH', help: 'Always use SSH' },
  { value: 'agent', label: 'Agent', help: 'Force agent transport' },
];

const TransportPreferenceToggle: React.FC<Props> = ({ value, onChange, disabled }) => {
  // Track the option the user is trying to switch INTO so the
  // confirm modal can fire onConfirm without re-deriving it.
  const [pendingAgent, setPendingAgent] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const handleSelect = async (next: TransportPreference) => {
    if (next === value || disabled) return;
    if (next === 'agent') {
      // Confirmation only on force-agent - switching to ssh or auto
      // is reversible and never breaks ops in a way the user can't
      // undo from here.
      setPendingAgent(true);
      return;
    }
    await onChange(next);
  };

  const confirmAgent = async () => {
    setSubmitting(true);
    try {
      await onChange('agent');
      setPendingAgent(false);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <div
        className="inline-flex rounded-md border border-border-strong bg-surface-raised/40 p-0.5"
        role="group"
        aria-label="Transport preference"
      >
        {OPTIONS.map((opt) => {
          const active = opt.value === value;
          return (
            <button
              key={opt.value}
              type="button"
              disabled={disabled || submitting}
              onClick={() => handleSelect(opt.value)}
              title={opt.help}
              className={[
                'px-3 py-1.5 text-sm font-medium rounded transition-colors',
                active
                  ? 'bg-emerald-600 text-white'
                  : 'text-content hover:bg-surface-overlay hover:text-white',
                disabled || submitting ? 'opacity-60 cursor-not-allowed' : 'cursor-pointer',
              ].join(' ')}
              aria-pressed={active}
            >
              {opt.label}
            </button>
          );
        })}
      </div>

      <ConfirmModal
        open={pendingAgent}
        onClose={() => !submitting && setPendingAgent(false)}
        onConfirm={confirmAgent}
        title="Force agent transport?"
        message="SSH fallback will be disabled for supported operations. If the agent tunnel is unhealthy, those operations will fail until the agent reconnects or you switch back to auto/ssh."
        confirmLabel="Force agent"
        cancelLabel="Cancel"
        variant="warning"
        loading={submitting}
      />
    </>
  );
};

export default TransportPreferenceToggle;
