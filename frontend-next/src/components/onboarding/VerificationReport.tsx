import React from 'react';
import { AlertTriangle, Check, MinusCircle, X } from 'lucide-react';

import type { VerificationCheck } from '@/services/onboardingService';

const CHECK_LABELS: Record<string, string> = {
  address: 'Address',
  network: 'Network reachability',
  host_identity: 'Host identity',
  authentication: 'Credential authentication',
  command: 'Command execution',
  sudo: 'Elevation (sudo)',
};

const STATUS_ICON = {
  pass: <Check size={14} className="text-success" aria-hidden="true" />,
  fail: <X size={14} className="text-danger" aria-hidden="true" />,
  skipped: <MinusCircle size={14} className="text-content-subtle" aria-hidden="true" />,
};

const STATUS_WORD = { pass: 'Passed', fail: 'Failed', skipped: 'Not checked' };

/**
 * Per-check verification results.
 *
 * Each check reports on its own line, so "the host answered, the handshake
 * worked, the password was wrong" reads as three facts rather than one flat
 * failure. The text shown is the message the backend derived from its reason
 * code; nothing here interprets or reformats a transport error.
 */
const VerificationReport: React.FC<{
  checks: VerificationCheck[];
  verified: boolean;
}> = ({ checks, verified }) => {
  if (!checks.length) return null;

  return (
    <div className="space-y-2">
      <p
        className={`text-sm font-medium ${verified ? 'text-success' : 'text-content'}`}
        role="status"
      >
        {verified
          ? 'This host is reachable and the credential works.'
          : 'Verification did not complete.'}
      </p>
      <ul className="divide-y divide-border rounded-md border border-border">
        {checks.map((check) => (
          <li key={check.check} className="flex gap-3 p-3">
            <span className="mt-0.5 shrink-0">{STATUS_ICON[check.status]}</span>
            <div className="min-w-0 flex-1">
              <p className="text-sm text-content">
                {CHECK_LABELS[check.check] ?? check.check}
                <span className="sr-only">: {STATUS_WORD[check.status]}</span>
              </p>
              {check.status !== 'pass' && (
                <p className="mt-0.5 text-xs text-content-muted break-words">
                  {check.message}
                </p>
              )}
              <p className="mt-0.5 font-mono text-[11px] text-content-subtle">
                {check.reason_code}
              </p>
            </div>
          </li>
        ))}
      </ul>
    </div>
  );
};

const KeyFact: React.FC<{
  term: string;
  breakAll?: boolean;
  children: React.ReactNode;
}> = ({ term, breakAll = false, children }) => (
  <div>
    <dt className="text-[11px] uppercase tracking-wider text-content-subtle">
      {term}
    </dt>
    <dd className={`font-mono text-xs text-content${breakAll ? ' break-all' : ''}`}>
      {children}
    </dd>
  </div>
);

type HostKeyDecisionState = 'pending' | 'trusted' | 'rejected';

/**
 * What the operator can still do about the offered key.
 *
 * A decision that has been made is reported and closed; only a pending key
 * offers the two choices, and neither is pre-selected.
 */
const HostKeyDecision: React.FC<{
  decision: HostKeyDecisionState;
  busy: boolean;
  onDecide: (accept: boolean) => void;
}> = ({ decision, busy, onDecide }) => {
  if (decision === 'trusted') {
    return <p className="mt-3 text-xs text-success">You approved this key.</p>;
  }
  if (decision === 'rejected') {
    return (
      <p className="mt-3 text-xs text-danger">
        You rejected this key. Nothing was added.
      </p>
    );
  }
  return (
    <div className="mt-3 flex flex-wrap gap-2">
      <button
        type="button"
        disabled={busy}
        onClick={() => onDecide(true)}
        className="rounded-md border border-border bg-action px-3 py-1.5 text-xs text-action-fg hover:bg-action-hover disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
      >
        This fingerprint is correct
      </button>
      <button
        type="button"
        disabled={busy}
        onClick={() => onDecide(false)}
        className="rounded-md border border-border bg-action-secondary px-3 py-1.5 text-xs text-content hover:border-border-strong disabled:opacity-50 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
      >
        It does not match
      </button>
    </div>
  );
};

/**
 * Everything the operator needs in order to judge an offered key: what it
 * claims to be, the fingerprint to compare against, and the decision itself.
 */
const HostKeyDetails: React.FC<{
  fingerprint: string;
  keyType: string | null;
  decision: HostKeyDecisionState;
  busy: boolean;
  onDecide: (accept: boolean) => void;
}> = ({ fingerprint, keyType, decision, busy, onDecide }) => (
  <div className="min-w-0 flex-1">
    <h3 className="text-sm font-medium text-content">
      Confirm this host&apos;s identity
    </h3>
    <p className="mt-1 text-xs text-content-muted">
      Praxis has not seen this host before. Check that the fingerprint below
      matches the host you mean to manage. If it does not, stop: something
      else may be answering at this address.
    </p>
    <dl className="mt-3 space-y-1">
      <KeyFact term="Key type">{keyType ?? 'unknown'}</KeyFact>
      <KeyFact term="SHA-256 fingerprint" breakAll>
        {fingerprint}
      </KeyFact>
    </dl>
    <HostKeyDecision decision={decision} busy={busy} onDecide={onDecide} />
  </div>
);

/**
 * The host key an unknown host offered, shown for an explicit decision.
 *
 * Approval is a deliberate act: the fingerprint is displayed in full and broken
 * for reading, and neither button is pre-selected, because "trust this host" is
 * exactly the decision that should not be made by pressing Next out of habit.
 */
export const HostKeyReview: React.FC<{
  fingerprint: string;
  keyType: string | null;
  decision: HostKeyDecisionState;
  busy: boolean;
  onDecide: (accept: boolean) => void;
}> = ({ fingerprint, keyType, decision, busy, onDecide }) => (
  <div className="rounded-md border border-warning/40 bg-warning/10 p-4">
    <div className="flex gap-3">
      <AlertTriangle size={16} className="mt-0.5 shrink-0 text-warning" aria-hidden="true" />
      <HostKeyDetails
        fingerprint={fingerprint}
        keyType={keyType}
        decision={decision}
        busy={busy}
        onDecide={onDecide}
      />
    </div>
  </div>
);

export default VerificationReport;
