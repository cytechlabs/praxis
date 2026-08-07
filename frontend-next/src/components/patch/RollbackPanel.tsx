/**
 * PRA-173 closeout: rollback panel.
 *
 * Operator surface for the entire rollback lifecycle on one
 * execution: evaluate → request approval → vote → start dispatch
 * → dispatch-next → cancel → verify-due. Embedded under the
 * ExecutionPanel on the plan detail page (PRA-164's
 * `/patch-update-plans/[id]`).
 *
 * State machine (driven by the rollback detail + dispatch detail
 * envelopes from `patchRollbackService.getExecutionRollback` and
 * `.getExecutionRollbackDispatch`):
 *
 * 1. No execution yet → panel hidden.
 * 2. Execution exists, no rollback evaluated → "Evaluate" button.
 * 3. Refused (e.g. execution_not_terminal) → display refusal,
 *    re-evaluate button.
 * 4. Evaluated, no approval requested → feasibility summary +
 *    "Request approval" button.
 * 5. Approval pending → status + frozen-plan preview + vote
 *    buttons (admin/maintainer).
 * 6. Approval approved, no dispatch run → "Start dispatch" button.
 * 7. Dispatch running → "Dispatch next batch" + "Cancel" + per-host
 *    progress.
 * 8. Dispatch terminal → "Verify due" button + verification
 *    progress (installed_version_after columns).
 *
 * Frontend never implies rollback is automatic or always
 * available. Unsupported / refused / unavailable cases are always
 * rendered with explicit copy. Frozen plan preview consumes the
 * approval snapshot (`approval.frozen_plan_snapshot`), never the
 * live per-package `command_plan` column.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import Badge from '@/components/ui/Badge';
import { useAuth } from '@/context/AuthContext';
import {
  cancelExecutionRollbackDispatch,
  dispatchNextExecutionRollback,
  evaluateExecutionRollback,
  getExecutionRollback,
  getExecutionRollbackDispatch,
  PatchRollbackApiError,
  requestRollbackApproval,
  startExecutionRollbackDispatch,
  verifyDueExecutionRollback,
  voteRollbackApproval,
  type RollbackDetail,
  type RollbackDispatchDetail,
  type RollbackDispatchHostState,
  type RollbackHostState,
} from '@/services/patchRollbackService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const HOST_STATE_VARIANT: Record<RollbackHostState, string> = {
  feasible: 'success',
  partial_feasible: 'warning',
  infeasible: 'neutral',
};

const DISPATCH_HOST_STATE_VARIANT: Record<RollbackDispatchHostState, string> = {
  pending: 'neutral',
  running: 'warning',
  succeeded: 'success',
  failed: 'danger',
  skipped: 'neutral',
  canceled: 'neutral',
};

export interface RollbackPanelProps {
  executionId: number | null;
  planRefresh: () => Promise<void>;
  reportError: (label: string, e: unknown) => void;
}

export const RollbackPanel: React.FC<RollbackPanelProps> = ({
  executionId,
  planRefresh,
  reportError,
}) => {
  const formatTimestamp = useFormatTimestamp();
  const [rollback, setRollback] = useState<RollbackDetail | null>(null);
  const [dispatch, setDispatch] = useState<RollbackDispatchDetail | null>(null);
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [showFrozenPlan, setShowFrozenPlan] = useState(false);
  // PRA-173 closeout fix: role-gate write controls.
  // ``canWrite`` is admin || maintainer (matches the backend's
  // ``require_role("admin", "maintainer")`` guards on every
  // rollback POST endpoint). Auditor / read-only roles still see
  // the panel + read-only state but never see the action buttons -
  // avoids the "click → 403" UX dead-end.
  const { canWrite } = useAuth();

  const refresh = useCallback(async () => {
    if (executionId == null) {
      setRollback(null);
      setDispatch(null);
      setLoaded(true);
      return;
    }
    try {
      const [rb, disp] = await Promise.all([
        getExecutionRollback(executionId),
        getExecutionRollbackDispatch(executionId),
      ]);
      setRollback(rb);
      setDispatch(disp);
    } catch (e) {
      if (e instanceof PatchRollbackApiError && e.status === 404) {
        setRollback(null);
        setDispatch(null);
      } else {
        reportError('Load rollback state', e);
      }
    } finally {
      setLoaded(true);
    }
  }, [executionId, reportError]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const guarded = async (label: string, op: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await op();
      toast.success(label);
      await Promise.all([refresh(), planRefresh()]);
    } catch (e) {
      reportError(label, e);
    } finally {
      setBusy(false);
    }
  };

  // No execution at all - operator hasn't started anything to roll
  // back yet. Panel stays hidden until the parent surfaces an
  // execution id.
  if (executionId == null) return null;
  if (!loaded) {
    return (
      <section className="rounded-md border border-praxis-border bg-praxis-surface p-4">
        <h2 className="text-sm font-semibold">Rollback</h2>
        <p className="mt-1 text-xs text-praxis-text-muted">Loading…</p>
      </section>
    );
  }

  const summary = rollback?.rollback?.feasibility_summary;
  const refusalReason = rollback?.rollback?.refusal_reason;
  const approval = rollback?.approval;
  const run = dispatch?.run;
  const isEvaluated = rollback?.rollback?.state === 'evaluated';
  const isRefused = rollback?.rollback?.state === 'refused';
  const hasFeasiblePackages =
    summary != null &&
    (summary.package_counts_by_state?.feasible ?? 0) > 0;
  const approvalPending = approval?.status === 'pending';
  const approvalApproved = approval?.status === 'approved';
  const runIsLive =
    run != null &&
    ['pending', 'running', 'paused'].includes(run.state as string);
  const runIsTerminal =
    run != null &&
    ['succeeded', 'failed', 'canceled'].includes(run.state as string);
  const verificationComplete =
    (run?.progress_summary as Record<string, unknown> | undefined)
      ?.verification_complete_emitted === true;

  return (
    <section
      data-testid="rollback-panel"
      className="rounded-md border border-praxis-border bg-praxis-surface p-4 space-y-3"
    >
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-sm font-semibold">Rollback</h2>
          <p className="text-xs text-praxis-text-muted">
            Best-effort, package-manager-dependent. Requires explicit operator
            action at every step.
          </p>
        </div>
        {/* PRA-173 closeout fix: action buttons gated on
            ``canWrite`` (admin || maintainer). The backend's POST
            endpoints all require those roles, so auditors / read-
            only users would only see a 403 after clicking. Hiding
            the buttons keeps the panel useful as a read-only
            surface without inviting the failure. */}
        {canWrite && (
          <div className="flex flex-wrap gap-1.5">
            {(!rollback?.rollback || isRefused) && (
              <button
                type="button"
                data-testid="rollback-evaluate"
                disabled={busy}
              onClick={() =>
                guarded('Rollback evaluated', () =>
                  evaluateExecutionRollback(executionId),
                )
              }
              className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
            >
              {rollback?.rollback ? 'Re-evaluate' : 'Evaluate rollback'}
            </button>
          )}
          {isEvaluated && !approval && hasFeasiblePackages && (
            <button
              type="button"
              data-testid="rollback-request-approval"
              disabled={busy}
              onClick={() =>
                guarded('Approval requested', () =>
                  requestRollbackApproval(executionId, {
                    required_approvals: 1,
                  }),
                )
              }
              className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
            >
              Request approval
            </button>
          )}
          {approvalPending && (
            <>
              <button
                type="button"
                data-testid="rollback-vote-approve"
                disabled={busy}
                onClick={() =>
                  guarded('Vote recorded: approve', () =>
                    voteRollbackApproval(executionId, { decision: 'approve' }),
                  )
                }
                className="inline-flex items-center rounded-md bg-emerald-600 px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              >
                Approve
              </button>
              <button
                type="button"
                data-testid="rollback-vote-reject"
                disabled={busy}
                onClick={() =>
                  guarded('Vote recorded: reject', () =>
                    voteRollbackApproval(executionId, { decision: 'reject' }),
                  )
                }
                className="inline-flex items-center rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              >
                Reject
              </button>
            </>
          )}
          {approvalApproved && !run && (
            <button
              type="button"
              data-testid="rollback-start"
              disabled={busy}
              onClick={() =>
                guarded('Rollback dispatch started', () =>
                  startExecutionRollbackDispatch(executionId, {}),
                )
              }
              className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
            >
              Start rollback dispatch
            </button>
          )}
          {runIsLive && (
            <>
              <button
                type="button"
                data-testid="rollback-dispatch-next"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const result =
                      await dispatchNextExecutionRollback(executionId);
                    if (result.no_pending) {
                      toast.success('No pending hosts left.');
                    } else {
                      toast.success(
                        `Dispatched ${result.dispatched_count} host(s) - ${result.succeeded_count} ok, ${result.failed_count} failed.`,
                      );
                    }
                    await Promise.all([refresh(), planRefresh()]);
                  } catch (e) {
                    reportError('Dispatch next batch', e);
                  } finally {
                    setBusy(false);
                  }
                }}
                className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              >
                Dispatch next batch
              </button>
              <button
                type="button"
                data-testid="rollback-cancel"
                disabled={busy}
                onClick={() =>
                  guarded('Rollback dispatch canceled', () =>
                    cancelExecutionRollbackDispatch(executionId, {
                      cancel_reason: 'operator',
                    }),
                  )
                }
                className="inline-flex items-center rounded-md bg-red-600 px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              >
                Cancel
              </button>
            </>
          )}
          {runIsTerminal && !verificationComplete && (
            <button
              type="button"
              data-testid="rollback-verify-due"
              disabled={busy}
              onClick={async () => {
                setBusy(true);
                try {
                  const result = await verifyDueExecutionRollback(executionId);
                  if (result.no_due) {
                    toast.success('No hosts due for verification.');
                  } else {
                    toast.success(
                      `Verified ${result.reachable_host_count} host(s); ${result.unreachable_host_count} unreachable.`,
                    );
                  }
                  await Promise.all([refresh(), planRefresh()]);
                } catch (e) {
                  reportError('Verify due', e);
                } finally {
                  setBusy(false);
                }
              }}
              className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
            >
              Verify due
            </button>
          )}
          </div>
        )}
      </div>

      {/* Feasibility state */}
      {!rollback?.rollback && (
        <p className="text-xs text-praxis-text-muted">
          Rollback feasibility has not been evaluated for this execution. Click
          <strong> Evaluate rollback</strong> to compute per-host and
          per-package feasibility from the original execution evidence.
        </p>
      )}

      {isRefused && (
        <div className="rounded-md border border-amber-300 bg-amber-50 p-3 text-xs text-amber-900">
          <strong>Rollback not yet evaluable:</strong>{' '}
          <code>{refusalReason}</code>. The execution must be in a terminal
          state (succeeded / failed / canceled) before feasibility can be
          computed.
        </div>
      )}

      {isEvaluated && summary && (
        <div className="space-y-2">
          <div className="flex flex-wrap gap-1.5 text-xs">
            <Badge variant="success">
              {summary.host_counts_by_state.feasible ?? 0} feasible
            </Badge>
            <Badge variant="warning">
              {summary.host_counts_by_state.partial_feasible ?? 0} partial
            </Badge>
            <Badge variant="neutral">
              {summary.host_counts_by_state.infeasible ?? 0} infeasible
            </Badge>
            <span className="text-praxis-text-muted">
              · {summary.package_count} package row(s) ·{' '}
              {summary.package_counts_by_state.feasible ?? 0} dispatch-ready
            </span>
          </div>
          {Object.keys(summary.refusal_counts || {}).length > 0 && (
            <p className="text-xs text-praxis-text-muted">
              Refusals:{' '}
              {Object.entries(summary.refusal_counts)
                .map(([k, v]) => `${k}=${v}`)
                .join(', ')}
            </p>
          )}
        </div>
      )}

      {/* Per-host rollup table */}
      {isEvaluated && rollback?.hosts && rollback.hosts.length > 0 && (
        <div className="overflow-auto rounded-md border border-praxis-border">
          <table className="min-w-full text-xs">
            <thead className="bg-praxis-surface text-praxis-text-muted">
              <tr>
                <th className="px-3 py-2 text-left font-medium">Host</th>
                <th className="px-3 py-2 text-left font-medium">State</th>
                <th className="px-3 py-2 text-left font-medium">Refusal</th>
                <th className="px-3 py-2 text-left font-medium">Packages</th>
              </tr>
            </thead>
            <tbody>
              {rollback.hosts.map((h) => (
                <tr
                  key={h.id}
                  className="border-t border-praxis-border"
                  data-testid={`rollback-host-${h.id}`}
                >
                  <td className="px-3 py-1.5 font-mono">
                    {h.system_hostname_snapshot ?? `system ${h.system_id_snapshot}`}
                  </td>
                  <td className="px-3 py-1.5">
                    <Badge variant={HOST_STATE_VARIANT[h.state] as never}>
                      {humanizeStatus(h.state)}
                    </Badge>
                  </td>
                  <td className="px-3 py-1.5 font-mono text-praxis-text-muted">
                    {h.refusal_reason ?? '-'}
                  </td>
                  <td className="px-3 py-1.5">
                    {(h.package_summary as Record<string, number>)
                      ?.feasible_count ?? 0}{' '}
                    feasible /{' '}
                    {(h.package_summary as Record<string, number>)
                      ?.infeasible_count ?? 0}{' '}
                    infeasible
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Approval status */}
      {approval && (
        <div
          data-testid="rollback-approval-summary"
          className="rounded-md border border-praxis-border p-3 text-xs space-y-1"
        >
          <div className="flex items-center justify-between">
            <strong>Approval status:</strong>{' '}
            <Badge
              variant={
                approval.status === 'approved'
                  ? ('success' as never)
                  : approval.status === 'rejected'
                    ? ('danger' as never)
                    : ('warning' as never)
              }
            >
              {approval.status ?? 'unknown'}
            </Badge>
          </div>
          <p className="text-praxis-text-muted">
            Requested {formatTimestamp(approval.requested_at)} ·{' '}
            {(
              (approval.frozen_plan_snapshot as Record<string, number>)
                ?.feasible_package_count ?? 0
            ).toString()}{' '}
            package(s) in the frozen plan
          </p>
          <button
            type="button"
            data-testid="rollback-toggle-frozen-plan"
            onClick={() => setShowFrozenPlan(!showFrozenPlan)}
            className="text-praxis-primary underline"
          >
            {showFrozenPlan ? 'Hide' : 'Show'} frozen plan preview
          </button>
          {showFrozenPlan && (
            <pre
              data-testid="rollback-frozen-plan-snapshot"
              className="mt-2 max-h-72 overflow-auto rounded-md bg-black p-2 font-mono text-[10px] text-green-300"
            >
              {JSON.stringify(approval.frozen_plan_snapshot, null, 2)}
            </pre>
          )}
        </div>
      )}

      {/* Dispatch progress */}
      {run && (
        <div
          data-testid="rollback-dispatch-summary"
          className="rounded-md border border-praxis-border p-3 text-xs space-y-2"
        >
          <div className="flex flex-wrap items-center gap-2">
            <strong>Dispatch run:</strong>
            <Badge
              variant={
                run.state === 'succeeded'
                  ? ('success' as never)
                  : run.state === 'failed'
                    ? ('danger' as never)
                    : run.state === 'canceled'
                      ? ('neutral' as never)
                      : ('warning' as never)
              }
            >
              {humanizeStatus(run.state)}
            </Badge>
            <span className="text-praxis-text-muted">
              · started {formatTimestamp(run.started_at)}
            </span>
            {run.completed_at && (
              <span className="text-praxis-text-muted">
                · completed {formatTimestamp(run.completed_at)}
              </span>
            )}
          </div>
          {dispatch?.hosts && dispatch.hosts.length > 0 && (
            <div className="overflow-auto rounded-md border border-praxis-border">
              <table className="min-w-full text-xs">
                <thead className="bg-praxis-surface text-praxis-text-muted">
                  <tr>
                    <th className="px-3 py-2 text-left font-medium">Host</th>
                    <th className="px-3 py-2 text-left font-medium">State</th>
                    <th className="px-3 py-2 text-left font-medium">Started</th>
                    <th className="px-3 py-2 text-left font-medium">
                      Completed
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {dispatch.hosts.map((h) => (
                    <tr
                      key={h.id}
                      className="border-t border-praxis-border"
                      data-testid={`rollback-dispatch-host-${h.id}`}
                    >
                      <td className="px-3 py-1.5 font-mono">
                        {h.system_hostname_snapshot ?? `system ${h.system_id_snapshot}`}
                      </td>
                      <td className="px-3 py-1.5">
                        <Badge
                          variant={
                            DISPATCH_HOST_STATE_VARIANT[h.state] as never
                          }
                        >
                          {humanizeStatus(h.state)}
                        </Badge>
                      </td>
                      <td className="px-3 py-1.5 text-praxis-text-muted">
                        {h.started_at ? formatTimestamp(h.started_at) : '-'}
                      </td>
                      <td className="px-3 py-1.5 text-praxis-text-muted">
                        {h.completed_at
                          ? formatTimestamp(h.completed_at)
                          : '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {dispatch?.packages && dispatch.packages.length > 0 && (
            <div className="overflow-auto rounded-md border border-praxis-border">
              <table className="min-w-full text-xs">
                <thead className="bg-praxis-surface text-praxis-text-muted">
                  <tr>
                    <th className="px-3 py-2 text-left font-medium">Package</th>
                    <th className="px-3 py-2 text-left font-medium">Target</th>
                    <th className="px-3 py-2 text-left font-medium">Outcome</th>
                    <th className="px-3 py-2 text-left font-medium">
                      Observed version
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {dispatch.packages.map((p) => (
                    <tr
                      key={p.id}
                      className="border-t border-praxis-border"
                      data-testid={`rollback-dispatch-package-${p.id}`}
                    >
                      <td className="px-3 py-1.5 font-mono">{p.package_name}</td>
                      <td className="px-3 py-1.5 font-mono text-praxis-text-muted">
                        {p.target_rollback_version_snapshot ?? '-'}
                      </td>
                      <td className="px-3 py-1.5">{p.outcome}</td>
                      <td className="px-3 py-1.5 font-mono text-praxis-text-muted">
                        {p.installed_version_after ?? '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
    </section>
  );
};

export default RollbackPanel;
