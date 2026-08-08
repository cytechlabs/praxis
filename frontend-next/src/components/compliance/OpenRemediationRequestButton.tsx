/**
 * PRA-177 Slice 2 (+ Slice 2a fix): "Open remediation request" cell for
 * a single compliance evidence row.
 *
 * The cell always renders concrete copy so an auditor scanning the
 * evidence table never sees a silent empty action column:
 *
 *   - `verdict === 'fail'` AND `canWrite`  →  active Remediate CTA
 *     that opens a justification modal, POSTs via
 *     `createRemediationRequest`, then navigates to the request
 *     detail page.
 *   - `verdict !== 'fail'`                 →  short disabled-state
 *     label ("Pass - no action" / "Error - re-evaluate") so the row
 *     explains why remediation does not apply.
 *   - `verdict === 'fail'` AND auditor/no canWrite →  short label
 *     "Admin or maintainer required" so a read-only user understands
 *     why the action is hidden from them.
 *
 * Used by both the per-host evidence page
 * (`/compliance/systems/[id]`) and the policy detail Evidence tab
 * (`/compliance/policies/[id]`) so the operator flow and the
 * disabled-state copy are identical regardless of entry point.
 */
import React, { useState } from 'react';
import { useRouter } from 'next/router';
import { ClipboardCheck } from 'lucide-react';
import { toast } from 'sonner';
import { Button, Modal } from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  ComplianceApiError,
  ComplianceEvidenceRow,
  createRemediationRequest,
} from '@/services/complianceService';

interface OpenRemediationRequestButtonProps {
  row: ComplianceEvidenceRow;
  /** Called after a successful request is opened so the parent can
   *  refresh its evidence list (the row may show a different state). */
  onOpened?: () => void;
  /** Style override: `"row"` renders a tight inline link for table
   *  cells, `"button"` renders the standard Button component. */
  variant?: 'row' | 'button';
}

const OpenRemediationRequestButton: React.FC<OpenRemediationRequestButtonProps> = ({
  row,
  onOpened,
  variant = 'row',
}) => {
  const router = useRouter();
  const { canWrite } = useAuth();
  const [open, setOpen] = useState(false);
  const [justification, setJustification] = useState('');
  const [submitting, setSubmitting] = useState(false);

  // Non-failing rows render an inline explanation so the action
  // column never silently disappears (Slice 2a fix to the P1 finding).
  if (row.verdict !== 'fail') {
    const label =
      row.verdict === 'pass'
        ? 'Pass - no action'
        : 'Error - re-evaluate first';
    return (
      <span
        className="text-[11px] text-content-subtle"
        title="Remediation requests open from failing evidence rows only."
        data-testid="remediation-not-applicable"
      >
        {label}
      </span>
    );
  }

  if (!canWrite) {
    return (
      <span
        className="text-[11px] text-content-subtle"
        title="Opening a remediation request requires the admin or maintainer role."
        data-testid="remediation-rbac-required"
      >
        Admin or maintainer required
      </span>
    );
  }

  const handleSubmit = async () => {
    setSubmitting(true);
    try {
      const created = await createRemediationRequest({
        evidence_id: row.id,
        justification: justification.trim() ? justification.trim() : null,
      });
      toast.success(`Remediation request #${created.id} opened`);
      setOpen(false);
      setJustification('');
      onOpened?.();
      // Use router.push so the spinner ends before navigation; the
      // request detail page reads its own freshly-created row.
      await router.push(`/compliance/remediation/requests/${created.id}`);
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Open remediation request failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      {variant === 'row' ? (
        <button
          onClick={() => setOpen(true)}
          className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300"
          title="Open a remediation request for this failing check"
        >
          <ClipboardCheck size={12} /> Remediate
        </button>
      ) : (
        <Button variant="outline" size="sm" onClick={() => setOpen(true)}>
          <ClipboardCheck size={14} /> Open remediation request
        </Button>
      )}
      <Modal
        open={open}
        onClose={() => {
          if (!submitting) setOpen(false);
        }}
        title="Open remediation request"
      >
        <div className="space-y-4">
          <div className="text-xs text-content-muted space-y-1">
            <div>
              Policy:{' '}
              <span className="font-mono text-content">{row.policy_slug}</span>
            </div>
            <div>
              Check:{' '}
              <span className="font-mono text-content">{row.check_slug}</span>
            </div>
            <div>
              System:{' '}
              <span className="font-mono text-content">#{row.system_id}</span>
            </div>
            <div>
              Evidence row:{' '}
              <span className="font-mono text-content">#{row.id}</span>
            </div>
          </div>
          <p className="text-xs text-content-subtle leading-relaxed">
            Opening a request records intent for an admin to approve. It does
            not run anything on the host. Approve / reject / cancel, plan
            build and acknowledge, and dispatch are all available from the
            request detail page once the request is approved.
          </p>
          <div>
            <label
              htmlFor="remediation-justification"
              className="block text-xs uppercase tracking-wide text-content-subtle mb-1"
            >
              Justification (optional, ≤ 4096 chars)
            </label>
            <textarea
              id="remediation-justification"
              rows={4}
              maxLength={4096}
              className="w-full bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
              value={justification}
              onChange={(e) => setJustification(e.target.value)}
              placeholder="Why does this need remediation?"
            />
          </div>
          <div className="flex justify-end gap-2">
            <Button
              variant="outline"
              onClick={() => setOpen(false)}
              disabled={submitting}
            >
              Cancel
            </Button>
            <Button variant="primary" onClick={handleSubmit} loading={submitting}>
              Open request
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
};

export default OpenRemediationRequestButton;
