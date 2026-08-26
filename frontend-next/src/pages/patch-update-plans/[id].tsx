/**
 * PRA-164 #4: patch update plan detail page.
 *
 * Operator surface for one plan: shows plan summary, ring sequence,
 * per-host wave breakdown with selection_summary + preflight_summary
 * + block_reasons, and approval / schedule / supersede / cancel /
 * refresh / export controls. Slice 4 closeout for PRA-164;
 * execution still belongs to PRA-171/172/173.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import {
  ChevronDown,
  ChevronRight,
  Download,
  RefreshCcw,
  Slash,
  Upload,
  XCircle,
} from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import Badge from '@/components/ui/Badge';
import PageHeader from '@/components/ui/PageHeader';
import { Button, ErrorState, LoadingState } from '@/components/ui';
import ExportButton from '@/components/ExportButton';
import { useAuth } from '@/context/AuthContext';
import {
  approvePatchUpdatePlan,
  cancelPatchUpdatePlan,
  getPatchUpdatePlan,
  listHostPreflight,
  listHostSelectedPackages,
  PatchUpdatePlanApiError,
  refreshPatchUpdatePlan,
  rejectPatchUpdatePlan,
  requestPatchUpdatePlanApproval,
  schedulePatchUpdatePlan,
  supersedePatchUpdatePlan,
  triggerExportDownload,
  type PatchUpdatePlanDetail,
  type PatchUpdatePlanHost,
  type PlanState,
  type PreflightSnapshot,
  type SelectedPackage,
} from '@/services/patchUpdatePlanService';
import {
  cancelPatchUpdateExecution,
  dispatchNextPatchUpdateExecution,
  getExecutionRebootQueue,
  getLatestExecutionForPlan,
  listExecutionHostPackages,
  pausePatchUpdateExecution,
  PatchUpdateExecutionApiError,
  resumePatchUpdateExecution,
  startPatchUpdateExecution,
  type ExecutionHostPackage,
  type ExecutionHostState,
  type ExecutionState,
  type PackageOutcome,
  type PatchUpdateExecutionDetail,
  type RebootReconciliation,
} from '@/services/patchExecutionService';
import RebootReconciliationWarning from '@/components/patch/RebootReconciliationWarning';
import RollbackPanel from '@/components/patch/RollbackPanel';
import PlanRollbackSummary from '@/components/patch/PlanRollbackSummary';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const STATE_LABELS: Record<PlanState, string> = {
  draft: 'Draft',
  awaiting_approval: 'Awaiting Approval',
  approved: 'Approved',
  scheduled: 'Scheduled',
  blocked: 'Blocked',
  superseded: 'Superseded',
  canceled: 'Canceled',
};


const PatchUpdatePlanDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { id } = router.query;
  const planId = typeof id === 'string' ? Number(id) : NaN;

  const [plan, setPlan] = useState<PatchUpdatePlanDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [busy, setBusy] = useState(false);
  const [scheduleAt, setScheduleAt] = useState<string>('');

  const refresh = useCallback(async () => {
    if (!Number.isFinite(planId)) return;
    try {
      const data = await getPatchUpdatePlan(planId);
      setPlan(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [planId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const reportError = (label: string, e: unknown) => {
    const msg =
      e instanceof PatchUpdatePlanApiError
        ? `${e.message} (HTTP ${e.status})`
        : e instanceof Error
          ? e.message
          : String(e);
    toast.error(`${label}: ${msg}`);
  };

  const guarded = async (label: string, op: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await op();
      toast.success(label);
      await refresh();
    } catch (e) {
      reportError(label, e);
    } finally {
      setBusy(false);
    }
  };

  if (!Number.isFinite(planId)) {
    return (
      <MainLayout>
        <div className="p-6 text-sm text-red-700">Invalid plan id.</div>
      </MainLayout>
    );
  }

  if (error) {
    return (
      <MainLayout>
        <div className="p-6">
          <ErrorState title="Couldn’t load plan" onRetry={refresh} />
        </div>
      </MainLayout>
    );
  }

  if (plan === null) {
    return (
      <MainLayout>
        <LoadingState label="Loading plan" />
      </MainLayout>
    );
  }

  const policySnapshot = plan.policy_snapshot as Record<string, unknown>;
  const policySlug =
    typeof policySnapshot.slug === 'string' ? policySnapshot.slug : `#${plan.policy_id}`;
  const requiresApproval = Boolean(policySnapshot.requires_approval);

  const isDraft = plan.state === 'draft';
  const isAwaiting = plan.state === 'awaiting_approval';
  const isApproved = plan.state === 'approved';
  const isTerminal = plan.state === 'canceled' || plan.state === 'superseded';

  return (
    <MainLayout>
      <Head>
        <title>{plan.name} · Patch Update Plan · Praxis</title>
      </Head>
      <div className="space-y-4 p-6">
        <PageHeader
          title={`${plan.name} (${STATE_LABELS[plan.state]})`}
          subtitle={plan.description || `Plan for policy ${policySlug}.`}
          actions={
            <div className="flex flex-wrap gap-1.5">
              <button
                type="button"
                disabled={busy || isTerminal}
                onClick={() => guarded('Refresh plan', () => refreshPatchUpdatePlan(plan.id))}
                className="inline-flex items-center gap-1 rounded-md border border-praxis-border bg-praxis-surface px-2 py-1 text-xs disabled:opacity-50"
              >
                <RefreshCcw size={12} />
                Refresh
              </button>
              <button
                type="button"
                disabled={busy}
                onClick={() => triggerExportDownload(plan.id).catch((e) => reportError('Export', e))}
                className="inline-flex items-center gap-1 rounded-md border border-praxis-border bg-praxis-surface px-2 py-1 text-xs disabled:opacity-50"
              >
                <Download size={12} />
                Export JSON
              </button>
              {(isDraft || plan.state === 'blocked') && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => guarded('Cancel plan', () => cancelPatchUpdatePlan(plan.id))}
                  className="inline-flex items-center gap-1 rounded-md border border-praxis-border bg-praxis-surface px-2 py-1 text-xs disabled:opacity-50"
                >
                  <XCircle size={12} />
                  Cancel
                </button>
              )}
              {!isTerminal && (
                <button
                  type="button"
                  disabled={busy}
                  onClick={() => guarded('Supersede plan', () => supersedePatchUpdatePlan(plan.id))}
                  className="inline-flex items-center gap-1 rounded-md border border-praxis-border bg-praxis-surface px-2 py-1 text-xs disabled:opacity-50"
                >
                  <Slash size={12} />
                  Supersede
                </button>
              )}
            </div>
          }
        />

        {/* Approval / Schedule controls */}
        <section className="rounded-md border border-praxis-border bg-praxis-surface p-4 space-y-3">
          <h2 className="text-sm font-semibold">Approval &amp; Schedule</h2>
          {plan.approval ? (
            <div className="text-xs text-praxis-text-muted">
              Approval #{plan.approval.approval_id} status:{' '}
              <strong>{plan.approval.status}</strong>{' '}
              ({plan.approval.required_approvals} approver
              {plan.approval.required_approvals === 1 ? '' : 's'} required)
            </div>
          ) : (
            <div className="text-xs text-praxis-text-muted">
              {requiresApproval
                ? 'No approval requested yet.'
                : 'Policy does not require approval - direct approve is enabled.'}
            </div>
          )}
          <div className="flex flex-wrap gap-1.5">
            {isDraft && requiresApproval && (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  guarded('Approval requested', () =>
                    requestPatchUpdatePlanApproval(plan.id),
                  )
                }
                className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              >
                Request approval
              </button>
            )}
            {(isDraft && !requiresApproval) || isAwaiting ? (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  guarded('Approved', () => approvePatchUpdatePlan(plan.id))
                }
                className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              >
                Approve
              </button>
            ) : null}
            {isAwaiting && (
              <button
                type="button"
                disabled={busy}
                onClick={() =>
                  guarded('Rejected', () => rejectPatchUpdatePlan(plan.id))
                }
                className="inline-flex items-center rounded-md border border-red-300 bg-red-50 px-3 py-1.5 text-xs text-red-800 disabled:opacity-50"
              >
                Reject
              </button>
            )}
            {isApproved && (
              <div className="inline-flex items-center gap-1.5">
                <input
                  type="datetime-local"
                  value={scheduleAt}
                  onChange={(e) => setScheduleAt(e.target.value)}
                  className="rounded border border-praxis-border bg-praxis-bg p-1 text-xs"
                />
                <button
                  type="button"
                  disabled={busy || !scheduleAt}
                  onClick={() =>
                    guarded('Scheduled', () =>
                      schedulePatchUpdatePlan(plan.id, {
                        scheduled_start_at: new Date(scheduleAt).toISOString(),
                      }),
                    )
                  }
                  className="inline-flex items-center gap-1 rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
                >
                  <Upload size={12} />
                  Schedule
                </button>
              </div>
            )}
          </div>
        </section>

        {/* PRA-171: execution-run substrate panel. Slice 1 surfaces the
            "Start execution" / pause / resume / cancel controls plus a
            live-progress rollup. Metadata-only - no package-manager
            dispatch, SSH, agent ops, or package mutation. */}
        <ExecutionPanel plan={plan} planRefresh={refresh} reportError={reportError} />

        {/* PRA-173 closeout: plan-scoped rollback summary. Independent of
            the latest-execution rollback panel - surfaces every execution
            that has been started for this plan and whether its rollback
            feasibility has been evaluated, even if no rollback dispatch is
            currently active. */}
        <PlanRollbackSummary planId={plan.id} reportError={reportError} />

        {/* Plan-level block reasons */}
        {plan.block_reasons.length > 0 && (
          <section className="rounded-md border border-amber-300 bg-amber-50 p-4 space-y-2">
            <h2 className="text-sm font-semibold text-amber-900">
              Plan-level block reasons
            </h2>
            <ul className="space-y-1 text-xs text-amber-900">
              {plan.block_reasons.map((br, idx) => (
                <li key={idx}>
                  <strong>{br.code}</strong> -{' '}
                  <span className="font-mono">{JSON.stringify(br.details)}</span>
                </li>
              ))}
            </ul>
          </section>
        )}

        {/* Ring sequence */}
        {plan.ring_sequence_snapshot.length > 0 && (
          <section className="rounded-md border border-praxis-border bg-praxis-surface p-4 space-y-2">
            <h2 className="text-sm font-semibold">Ring sequence</h2>
            <div className="flex flex-wrap gap-1.5">
              {plan.ring_sequence_snapshot.map((r) => (
                <Badge key={r.ring_id} variant={r.enabled ? 'success' : 'neutral'}>
                  {r.ring_slug} (sort {r.sort_order}
                  {r.enabled ? '' : ', disabled'})
                </Badge>
              ))}
            </div>
          </section>
        )}

        {/* Per-host table */}
        <section className="space-y-2">
          <h2 className="text-sm font-semibold">
            Hosts ({plan.hosts.length})
          </h2>
          <div className="overflow-auto rounded-md border border-praxis-border">
            <table className="min-w-full text-xs">
              <thead className="bg-praxis-surface text-praxis-text-muted">
                <tr>
                  <th className="px-3 py-2 w-6"></th>
                  <th className="px-3 py-2 text-left font-medium">Wave</th>
                  <th className="px-3 py-2 text-left font-medium">Host</th>
                  <th className="px-3 py-2 text-left font-medium">Ring</th>
                  <th className="px-3 py-2 text-left font-medium">State</th>
                  <th className="px-3 py-2 text-left font-medium">Selection</th>
                  <th className="px-3 py-2 text-left font-medium">Preflight</th>
                  <th className="px-3 py-2 text-left font-medium">Block reasons</th>
                </tr>
              </thead>
              <tbody>
                {plan.hosts.map((h) => (
                  <PlanHostRow key={h.id} host={h} planId={plan.id} />
                ))}
              </tbody>
            </table>
          </div>
        </section>

        {/* Snapshot meta */}
        <section className="rounded-md border border-praxis-border bg-praxis-surface p-4 space-y-2 text-xs text-praxis-text-muted">
          <div>
            <strong>Policy:</strong> {policySlug} · created{' '}
            {formatTimestamp(plan.created_at)} · updated{' '}
            {formatTimestamp(plan.updated_at)}
          </div>
          {plan.scheduled_start_at && (
            <div>
              <strong>Scheduled start:</strong>{' '}
              {formatTimestamp(plan.scheduled_start_at)}
            </div>
          )}
        </section>
      </div>
    </MainLayout>
  );
};

const PlanHostRow: React.FC<{ host: PatchUpdatePlanHost; planId: number }> = ({
  host,
  planId,
}) => {
  const sel = host.selection_summary;
  const pre = host.preflight_summary;
  const [expanded, setExpanded] = useState(false);
  const [drillLoaded, setDrillLoaded] = useState(false);
  const [drillError, setDrillError] = useState<string | null>(null);
  const [drillBusy, setDrillBusy] = useState(false);
  const [selectedPackages, setSelectedPackages] = useState<SelectedPackage[]>([]);
  const [preflightRows, setPreflightRows] = useState<PreflightSnapshot[]>([]);

  const runDrill = useCallback(async () => {
    setDrillBusy(true);
    try {
      const [sp, pf] = await Promise.all([
        listHostSelectedPackages(planId, host.id),
        listHostPreflight(planId, host.id),
      ]);
      setSelectedPackages(sp);
      setPreflightRows(pf);
      setDrillLoaded(true);
      setDrillError(null);
    } catch {
      // PRA-274: operator copy, never the raw exception. The "Try again" button
      // below is the retry affordance.
      setDrillError('Couldn’t load host detail. Try again.');
    } finally {
      setDrillBusy(false);
    }
  }, [planId, host.id]);

  const toggleExpanded = useCallback(() => {
    const next = !expanded;
    setExpanded(next);
    if (!next || drillLoaded || drillBusy) return;
    void runDrill();
  }, [expanded, drillLoaded, drillBusy, runDrill]);

  return (
    <>
      <tr className="border-t border-praxis-border align-top">
        <td className="px-3 py-2 align-top">
          <button
            type="button"
            onClick={toggleExpanded}
            aria-expanded={expanded}
            aria-label={expanded ? 'Collapse host detail' : 'Expand host detail'}
            className="text-praxis-text-muted hover:text-praxis-text"
          >
            {expanded ? <ChevronDown size={14} /> : <ChevronRight size={14} />}
          </button>
        </td>
        <td className="px-3 py-2 font-mono">{host.wave_index}</td>
        <td className="px-3 py-2">
          {host.system_hostname_snapshot || `system #${host.system_id}`}
          {host.policy_slug_snapshot && (
            <div className="text-praxis-text-muted">
              via {host.policy_resolution_kind} ({host.policy_slug_snapshot})
            </div>
          )}
        </td>
        <td className="px-3 py-2">
          {host.ring_slug_snapshot || (
            <span className="text-praxis-text-muted">
              {host.ring_resolution_status}
            </span>
          )}
        </td>
        <td className="px-3 py-2">
          <Badge variant={host.state === 'planned' ? 'success' : 'danger'}>
            {humanizeStatus(host.state)}
          </Badge>
        </td>
        <td className="px-3 py-2 text-praxis-text-muted">
          {sel
            ? `sel ${sel.selected} / excl ${sel.excluded} / unres ${sel.unresolvable}${sel.inventory_missing ? ' · no inventory' : ''}`
            : '-'}
        </td>
        <td className="px-3 py-2 text-praxis-text-muted">
          {pre
            ? `avail ${pre.available} / unavail ${pre.unavailable} / pm ${pre.profile_missing} / na ${pre.not_applicable}${pre.installed_drift_count > 0 ? ` · drift ${pre.installed_drift_count}` : ''}`
            : '-'}
        </td>
        <td className="px-3 py-2 text-praxis-text-muted">
          {host.block_reasons.length === 0
            ? '-'
            : host.block_reasons.map((br) => br.code).join(', ')}
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-praxis-border bg-praxis-surface/50">
          <td colSpan={8} className="px-6 py-3">
            {drillBusy && !drillLoaded && <LoadingState label="Loading" />}
            {drillError && (
              <div className="flex items-center justify-between gap-3 rounded border border-danger/40 bg-danger/10 p-2 text-xs text-danger">
                <span>{drillError}</span>
                <Button variant="ghost" size="sm" onClick={() => void runDrill()} disabled={drillBusy}>
                  Try again
                </Button>
              </div>
            )}
            {drillLoaded && (
              <div className="space-y-3">
                <SelectedPackagesPanel rows={selectedPackages} />
                <PreflightRowsPanel rows={preflightRows} />
              </div>
            )}
          </td>
        </tr>
      )}
    </>
  );
};

const SelectedPackagesPanel: React.FC<{ rows: SelectedPackage[] }> = ({ rows }) => (
  <div>
    <h3 className="text-xs font-semibold text-praxis-text-muted uppercase tracking-wide mb-1.5">
      Selected packages ({rows.length})
    </h3>
    {rows.length === 0 ? (
      <div className="text-xs text-praxis-text-muted">
        No selected-package rows for this host.
      </div>
    ) : (
      <div className="overflow-auto rounded border border-praxis-border">
        <table className="min-w-full text-xs">
          <thead className="bg-praxis-surface text-praxis-text-muted">
            <tr>
              <th className="px-2 py-1 text-left font-medium">Package</th>
              <th className="px-2 py-1 text-left font-medium">Installed</th>
              <th className="px-2 py-1 text-left font-medium">Available</th>
              <th className="px-2 py-1 text-left font-medium">Reason</th>
              <th className="px-2 py-1 text-left font-medium">State</th>
              <th className="px-2 py-1 text-left font-medium">Advisory</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-praxis-border">
                <td className="px-2 py-1 font-mono">
                  {r.package_name || '(inventory missing)'}
                </td>
                <td className="px-2 py-1 text-praxis-text-muted">
                  {r.installed_version_snapshot || '-'}
                </td>
                <td className="px-2 py-1 text-praxis-text-muted">
                  {r.available_version_snapshot || '-'}
                </td>
                <td className="px-2 py-1">{r.selection_reason}</td>
                <td className="px-2 py-1">
                  <Badge
                    variant={
                      r.state === 'selected'
                        ? 'success'
                        : r.state === 'excluded'
                          ? 'neutral'
                          : 'warning'
                    }
                  >
                    {humanizeStatus(r.state)}
                  </Badge>
                </td>
                <td className="px-2 py-1 text-praxis-text-muted">
                  {r.advisory_source_kind_snapshot && r.advisory_id_snapshot
                    ? `${r.advisory_source_kind_snapshot} #${r.advisory_id_snapshot}${r.advisory_severity_snapshot ? ` · ${r.advisory_severity_snapshot}` : ''}`
                    : '-'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

const PreflightRowsPanel: React.FC<{ rows: PreflightSnapshot[] }> = ({ rows }) => (
  <div>
    <h3 className="text-xs font-semibold text-praxis-text-muted uppercase tracking-wide mb-1.5">
      Preflight ({rows.length})
    </h3>
    {rows.length === 0 ? (
      <div className="text-xs text-praxis-text-muted">
        No preflight rows for this host.
      </div>
    ) : (
      <div className="overflow-auto rounded border border-praxis-border">
        <table className="min-w-full text-xs">
          <thead className="bg-praxis-surface text-praxis-text-muted">
            <tr>
              <th className="px-2 py-1 text-left font-medium">Package</th>
              <th className="px-2 py-1 text-left font-medium">Installed @ preflight</th>
              <th className="px-2 py-1 text-left font-medium">Family</th>
              <th className="px-2 py-1 text-left font-medium">Availability</th>
              <th className="px-2 py-1 text-left font-medium">Details</th>
            </tr>
          </thead>
          <tbody>
            {rows.map((r) => (
              <tr key={r.id} className="border-t border-praxis-border">
                <td className="px-2 py-1 font-mono">
                  {r.package_name || '(inventory missing)'}
                </td>
                <td className="px-2 py-1 text-praxis-text-muted">
                  {r.installed_version_at_preflight || '-'}
                </td>
                <td className="px-2 py-1 text-praxis-text-muted">
                  {r.package_manager_family_snapshot}
                </td>
                <td className="px-2 py-1">
                  <Badge
                    variant={
                      r.content_availability_state === 'available'
                        ? 'success'
                        : r.content_availability_state === 'unavailable'
                          ? 'danger'
                          : r.content_availability_state === 'profile_missing'
                            ? 'warning'
                            : 'neutral'
                    }
                  >
                    {r.content_availability_state}
                  </Badge>
                </td>
                <td className="px-2 py-1 text-praxis-text-muted font-mono text-[10px]">
                  {Object.keys(r.availability_details).length === 0
                    ? '-'
                    : JSON.stringify(r.availability_details).slice(0, 120)}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    )}
  </div>
);

// ---------------------------------------------------------------------------
// PRA-171 Slice 1 - execution panel
//
// Surfaces the most recent execution for the plan with a live progress
// rollup and the metadata-only Start / Pause / Resume / Cancel
// controls. Slice 1 does NOT dispatch any work; the panel simply
// reflects the substrate's state machine.
// ---------------------------------------------------------------------------

const EXECUTION_STATE_BADGE: Record<
  ExecutionState,
  'success' | 'warning' | 'danger' | 'info' | 'neutral'
> = {
  pending: 'neutral',
  running: 'info',
  paused: 'warning',
  succeeded: 'success',
  failed: 'danger',
  canceled: 'neutral',
};

const EXECUTION_HOST_STATE_BADGE: Record<
  ExecutionHostState,
  'success' | 'warning' | 'danger' | 'info' | 'neutral'
> = {
  pending: 'neutral',
  running: 'info',
  succeeded: 'success',
  failed: 'danger',
  skipped: 'warning',
  paused: 'warning',
  canceled: 'neutral',
};

const ExecutionPanel: React.FC<{
  plan: PatchUpdatePlanDetail;
  planRefresh: () => Promise<void>;
  reportError: (label: string, e: unknown) => void;
}> = ({ plan, planRefresh, reportError }) => {
  const formatTimestamp = useFormatTimestamp();
  const { canWrite } = useAuth();
  const [execution, setExecution] = useState<PatchUpdateExecutionDetail | null>(
    null,
  );
  const [loaded, setLoaded] = useState(false);
  const [busy, setBusy] = useState(false);
  const [rebootReconciliation, setRebootReconciliation] =
    useState<RebootReconciliation | null>(null);

  const refreshExecution = useCallback(async () => {
    try {
      const data = await getLatestExecutionForPlan(plan.id);
      setExecution(data);
      // The reboot queue is read only for its reconciliation health. A
      // queue that could not be built is an operator-actionable state, so
      // it must reach this surface rather than living in the API alone. A
      // failed read is not reported as an error: it must not turn loading
      // an execution into a failure.
      try {
        const queue = await getExecutionRebootQueue(data.id);
        setRebootReconciliation(queue.summary?.reconciliation ?? null);
      } catch {
        setRebootReconciliation(null);
      }
    } catch (e) {
      if (e instanceof PatchUpdateExecutionApiError && e.status === 404) {
        setExecution(null);
        setRebootReconciliation(null);
      } else {
        reportError('Load execution', e);
      }
    } finally {
      setLoaded(true);
    }
  }, [plan.id, reportError]);

  useEffect(() => {
    refreshExecution();
  }, [refreshExecution]);

  const guarded = async (label: string, op: () => Promise<unknown>) => {
    setBusy(true);
    try {
      await op();
      toast.success(label);
      await Promise.all([refreshExecution(), planRefresh()]);
    } catch (e) {
      reportError(label, e);
    } finally {
      setBusy(false);
    }
  };

  const canStart =
    (plan.state === 'approved' || plan.state === 'scheduled') &&
    (execution === null || ['succeeded', 'failed', 'canceled'].includes(execution.state));

  return (
    <section className="rounded-md border border-praxis-border bg-praxis-surface p-4 space-y-3">
      <div className="flex items-start justify-between gap-3">
        <h2 className="text-sm font-semibold">Execution</h2>
        <div className="flex flex-wrap gap-1.5">
          {canStart && (
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                guarded('Execution started', () =>
                  startPatchUpdateExecution({ plan_id: plan.id }),
                )
              }
              className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
            >
              Start execution
            </button>
          )}
          {execution && execution.state === 'running' && (
            <>
              <button
                type="button"
                disabled={busy}
                onClick={async () => {
                  setBusy(true);
                  try {
                    const result = await dispatchNextPatchUpdateExecution(
                      execution.id,
                    );
                    if (result.no_pending) {
                      toast.success('No pending hosts left to dispatch.');
                    } else {
                      toast.success(
                        `Dispatched ${result.dispatched_count} host(s) - ${result.succeeded_count} ok, ${result.failed_count} failed.`,
                      );
                    }
                    await Promise.all([refreshExecution(), planRefresh()]);
                  } catch (e) {
                    reportError('Dispatch next', e);
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
                disabled={busy}
                onClick={() =>
                  guarded('Execution paused', () =>
                    pausePatchUpdateExecution(execution.id),
                  )
                }
                className="inline-flex items-center rounded-md border border-praxis-border bg-praxis-surface px-2 py-1 text-xs disabled:opacity-50"
              >
                Pause
              </button>
            </>
          )}
          {execution && execution.state === 'paused' && (
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                guarded('Execution resumed', () =>
                  resumePatchUpdateExecution(execution.id),
                )
              }
              className="inline-flex items-center rounded-md border border-praxis-border bg-praxis-surface px-2 py-1 text-xs disabled:opacity-50"
            >
              Resume
            </button>
          )}
          {execution && ['pending', 'running', 'paused'].includes(execution.state) && (
            <button
              type="button"
              disabled={busy}
              onClick={() =>
                guarded('Execution canceled', () =>
                  cancelPatchUpdateExecution(execution.id),
                )
              }
              className="inline-flex items-center rounded-md border border-red-300 bg-red-50 px-2 py-1 text-xs text-red-800 disabled:opacity-50"
            >
              Cancel
            </button>
          )}
          <button
            type="button"
            disabled={busy}
            onClick={() => refreshExecution()}
            className="inline-flex items-center gap-1 rounded-md border border-praxis-border bg-praxis-surface px-2 py-1 text-xs disabled:opacity-50"
          >
            <RefreshCcw size={12} />
            Refresh
          </button>
        </div>
      </div>

      {!loaded && (
        <div className="text-xs text-praxis-text-muted">Loading execution…</div>
      )}

      {loaded && execution === null && (
        <div className="text-xs text-praxis-text-muted">
          {plan.state === 'approved' || plan.state === 'scheduled'
            ? 'No execution started yet for this plan.'
            : 'Execution becomes available once the plan is approved or scheduled.'}{' '}
          Execution substrate only - package-manager dispatch is not yet
          available.
        </div>
      )}

      {execution && (
        <RebootReconciliationWarning reconciliation={rebootReconciliation} />
      )}

      {execution && (
        <div className="space-y-2">
          <div className="flex flex-wrap items-center gap-3 text-xs">
            <Badge variant={EXECUTION_STATE_BADGE[execution.state]}>
              {humanizeStatus(execution.state)}
            </Badge>
            <span className="text-praxis-text-muted">
              Started {formatTimestamp(execution.started_at)} · max parallel{' '}
              {execution.max_parallel_per_wave}
              {execution.failure_threshold_percent !== null
                ? ` · failure threshold ${execution.failure_threshold_percent}%`
                : ''}
            </span>
            {/* PRA-178 Slice 4: per-execution exports for the reboot
                queue and rollback dispatch runs. Gated on the same
                canWrite predicate Slice 1a uses so read-only / auditor
                users never see a button that would 403 on click
                (PRA-178 Slice 4a fix to the P1 review finding). */}
            {canWrite ? (
              <>
                <ExportButton
                  endpoint={`/api/backend/patch/update-executions/${execution.id}/reboots/export`}
                  filename={`patch-reboots-execution-${execution.id}`}
                  label="Export reboots"
                />
                <ExportButton
                  endpoint={`/api/backend/patch/update-executions/${execution.id}/rollback/export`}
                  filename={`patch-rollback-execution-${execution.id}`}
                  label="Export rollback"
                />
              </>
            ) : (
              <span
                className="text-[11px] text-praxis-text-muted"
                title="Bulk export requires the admin or maintainer role."
                data-testid="patch-execution-exports-rbac-required"
              >
                Export requires admin or maintainer
              </span>
            )}
            {execution.completed_at && (
              <span className="text-praxis-text-muted">
                Completed {formatTimestamp(execution.completed_at)}
              </span>
            )}
            {execution.pause_reason && (
              <span className="text-amber-700">
                Paused: {execution.pause_reason}
              </span>
            )}
            {execution.cancel_reason && (
              <span className="text-red-700">
                Canceled: {execution.cancel_reason}
              </span>
            )}
          </div>
          {execution.progress.threshold_pause && (
            <div className="rounded-md border border-amber-300 bg-amber-50 p-2 text-xs text-amber-900">
              <strong>Auto-paused: failure threshold exceeded.</strong>{' '}
              {execution.progress.threshold_pause.failed_terminal_hosts} of{' '}
              {execution.progress.threshold_pause.terminal_hosts} terminal hosts
              failed (
              {execution.progress.threshold_pause.failure_percent}% &gt;{' '}
              {execution.progress.threshold_pause.failure_threshold_percent}%
              threshold). Resume to retry the remaining pending hosts, or cancel
              the execution.
            </div>
          )}
          {execution.progress.completed_wave_indexes &&
            execution.progress.completed_wave_indexes.length > 0 && (
              <div className="flex flex-wrap gap-1.5 text-xs">
                <span className="text-praxis-text-muted">Completed waves:</span>
                {execution.progress.completed_wave_indexes.map((w) => (
                  <Badge key={w} variant="success">
                    wave {w}
                  </Badge>
                ))}
              </div>
            )}
          <div className="flex flex-wrap gap-1.5 text-xs">
            <span className="text-praxis-text-muted">Hosts:</span>
            {(Object.keys(execution.progress.host_counts_by_state) as ExecutionHostState[])
              .filter((s) => execution.progress.host_counts_by_state[s] > 0)
              .map((s) => (
                <Badge key={s} variant={EXECUTION_HOST_STATE_BADGE[s]}>
                  {s}: {execution.progress.host_counts_by_state[s]}
                </Badge>
              ))}
            <span className="text-praxis-text-muted">
              · {execution.progress.selected_package_count} selected packages
            </span>
          </div>
          {execution.progress.package_outcome_counts &&
            Object.values(execution.progress.package_outcome_counts).some((n) => n > 0) && (
              <div className="flex flex-wrap gap-1.5 text-xs">
                <span className="text-praxis-text-muted">Package outcomes:</span>
                {(Object.entries(execution.progress.package_outcome_counts) as [
                  PackageOutcome,
                  number,
                ][])
                  .filter(([, n]) => n > 0)
                  .map(([outcome, n]) => (
                    <Badge
                      key={outcome}
                      variant={
                        outcome === 'succeeded'
                          ? 'success'
                          : outcome === 'failed'
                            ? 'danger'
                            : outcome === 'skipped'
                              ? 'warning'
                              : 'neutral'
                      }
                    >
                      {outcome}: {n}
                    </Badge>
                  ))}
              </div>
            )}
          {execution.progress.waves.length > 0 && (
            <div className="overflow-auto rounded-md border border-praxis-border">
              <table className="min-w-full text-xs">
                <thead className="bg-praxis-surface text-praxis-text-muted">
                  <tr>
                    <th className="px-2 py-1 text-left font-medium">Wave</th>
                    <th className="px-2 py-1 text-left font-medium">Hosts</th>
                    <th className="px-2 py-1 text-left font-medium">Selected packages</th>
                    <th className="px-2 py-1 text-left font-medium">By state</th>
                  </tr>
                </thead>
                <tbody>
                  {execution.progress.waves.map((w) => (
                    <tr key={w.wave_index} className="border-t border-praxis-border">
                      <td className="px-2 py-1 font-mono">{w.wave_index}</td>
                      <td className="px-2 py-1">{w.host_count}</td>
                      <td className="px-2 py-1">{w.selected_package_count}</td>
                      <td className="px-2 py-1">
                        <div className="flex flex-wrap gap-1">
                          {(Object.keys(w.host_counts_by_state) as ExecutionHostState[])
                            .filter((s) => w.host_counts_by_state[s] > 0)
                            .map((s) => (
                              <Badge key={s} variant={EXECUTION_HOST_STATE_BADGE[s]}>
                                {s}: {w.host_counts_by_state[s]}
                              </Badge>
                            ))}
                        </div>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
          {execution.hosts.length > 0 && (
            <div className="overflow-auto rounded-md border border-praxis-border">
              <table className="min-w-full text-xs">
                <thead className="bg-praxis-surface text-praxis-text-muted">
                  <tr>
                    <th className="px-2 py-1 w-6"></th>
                    <th className="px-2 py-1 text-left font-medium">Wave</th>
                    <th className="px-2 py-1 text-left font-medium">Host</th>
                    <th className="px-2 py-1 text-left font-medium">State</th>
                    <th className="px-2 py-1 text-left font-medium">Packages</th>
                    <th className="px-2 py-1 text-left font-medium">Notes</th>
                  </tr>
                </thead>
                <tbody>
                  {execution.hosts.map((h) => (
                    <ExecutionHostRow
                      key={h.id}
                      executionId={execution.id}
                      host={h}
                      reportError={reportError}
                    />
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </div>
      )}
      {/* PRA-173 closeout: rollback lifecycle panel. Renders only
          once an execution exists (i.e. there's something to roll
          back). All controls (evaluate / request approval / vote /
          start / dispatch-next / cancel / verify-due) are gated
          by current state inside the panel. */}
      <RollbackPanel
        executionId={execution?.id ?? null}
        planRefresh={async () => {
          await refreshExecution();
          await planRefresh();
        }}
        reportError={reportError}
      />
    </section>
  );
};

const ExecutionHostRow: React.FC<{
  executionId: number;
  host: PatchUpdateExecutionDetail['hosts'][number];
  reportError: (label: string, e: unknown) => void;
}> = ({ executionId, host, reportError }) => {
  const [expanded, setExpanded] = useState(false);
  const [drillLoaded, setDrillLoaded] = useState(false);
  const [drillBusy, setDrillBusy] = useState(false);
  const [packages, setPackages] = useState<ExecutionHostPackage[]>([]);

  const toggleExpanded = useCallback(async () => {
    const next = !expanded;
    setExpanded(next);
    if (!next || drillLoaded || drillBusy) return;
    setDrillBusy(true);
    try {
      const rows = await listExecutionHostPackages(executionId, host.id);
      setPackages(rows);
      setDrillLoaded(true);
    } catch (e) {
      reportError('Load host packages', e);
    } finally {
      setDrillBusy(false);
    }
  }, [expanded, drillLoaded, drillBusy, executionId, host.id, reportError]);

  const errorDetails = host.error_details as Record<string, unknown> | null;
  const stderrSummary =
    typeof errorDetails?.stderr === 'string'
      ? (errorDetails.stderr as string).slice(0, 200)
      : null;

  return (
    <>
      <tr className="border-t border-praxis-border align-top">
        <td className="px-2 py-1">
          <button
            type="button"
            onClick={toggleExpanded}
            aria-expanded={expanded}
            className="text-praxis-text-muted"
          >
            {expanded ? <ChevronDown size={12} /> : <ChevronRight size={12} />}
          </button>
        </td>
        <td className="px-2 py-1 font-mono">{host.wave_index}</td>
        <td className="px-2 py-1">
          {host.system_hostname_snapshot || `system #${host.system_id_snapshot ?? '?'}`}
        </td>
        <td className="px-2 py-1">
          <Badge variant={EXECUTION_HOST_STATE_BADGE[host.state]}>{humanizeStatus(host.state)}</Badge>
        </td>
        <td className="px-2 py-1">{host.selected_package_count}</td>
        <td className="px-2 py-1 text-praxis-text-muted">
          {stderrSummary || (host.skip_reasons.length > 0
            ? host.skip_reasons.map((r) => r.code).join(', ')
            : '-')}
        </td>
      </tr>
      {expanded && (
        <tr className="border-t border-praxis-border bg-praxis-bg/30">
          <td></td>
          <td colSpan={5} className="px-2 py-2 space-y-2">
            {drillBusy && <LoadingState label="Loading" />}
            {drillLoaded && packages.length === 0 && (
              <div className="text-praxis-text-muted">
                No package result rows yet for this host. The dispatcher writes
                them when a batch is processed.
              </div>
            )}
            {drillLoaded && packages.length > 0 && (
              <table className="min-w-full text-xs">
                <thead className="text-praxis-text-muted">
                  <tr>
                    <th className="px-2 py-1 text-left font-medium">Package</th>
                    <th className="px-2 py-1 text-left font-medium">Requested</th>
                    <th className="px-2 py-1 text-left font-medium">Before</th>
                    <th className="px-2 py-1 text-left font-medium">After</th>
                    <th className="px-2 py-1 text-left font-medium">Outcome</th>
                    <th className="px-2 py-1 text-left font-medium">Error</th>
                  </tr>
                </thead>
                <tbody>
                  {packages.map((p) => (
                    <tr key={p.id} className="border-t border-praxis-border">
                      <td className="px-2 py-1 font-mono">{p.package_name}</td>
                      <td className="px-2 py-1">{p.requested_version_snapshot ?? '-'}</td>
                      <td className="px-2 py-1">{p.installed_version_before ?? '-'}</td>
                      <td className="px-2 py-1">{p.installed_version_after ?? '-'}</td>
                      <td className="px-2 py-1">
                        <Badge
                          variant={
                            p.outcome === 'succeeded'
                              ? 'success'
                              : p.outcome === 'failed'
                                ? 'danger'
                                : p.outcome === 'skipped'
                                  ? 'warning'
                                  : 'neutral'
                          }
                        >
                          {p.outcome}
                        </Badge>
                      </td>
                      <td className="px-2 py-1 text-praxis-text-muted">
                        {p.error_code ?? '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            )}
            {errorDetails && (
              <ExecutionHostErrorDetails details={errorDetails} />
            )}
          </td>
        </tr>
      )}
    </>
  );
};

// ---------------------------------------------------------------------------
// PRA-171 Slice 4 - structured failed-host error_details renderer.
// Surfaces the well-known keys the dispatch service writes (transport,
// exit_code, command, stderr, stdout, code, etc.) in a tidy field
// layout. Falls back to a raw JSON <pre> for unexpected payload
// shapes so the operator never loses visibility.
// ---------------------------------------------------------------------------

const KNOWN_ERROR_DETAIL_KEYS = [
  'code',
  'transport',
  'exit_code',
  'duration_ms',
  'command',
  'stderr',
  'stdout',
  'message',
] as const;

const ExecutionHostErrorDetails: React.FC<{
  details: Record<string, unknown>;
}> = ({ details }) => {
  const knownEntries: Array<[string, unknown]> = KNOWN_ERROR_DETAIL_KEYS
    .filter((k) => details[k] !== undefined && details[k] !== null && details[k] !== '')
    .map((k) => [k, details[k]]);
  const otherKeys = Object.keys(details).filter(
    (k) => !KNOWN_ERROR_DETAIL_KEYS.includes(k as (typeof KNOWN_ERROR_DETAIL_KEYS)[number]),
  );
  const hasKnown = knownEntries.length > 0;
  const hasOther = otherKeys.length > 0;
  if (!hasKnown && !hasOther) return null;

  const renderValue = (key: string, value: unknown) => {
    if (key === 'stderr' || key === 'stdout' || key === 'command') {
      const text = typeof value === 'string' ? value : JSON.stringify(value);
      return (
        <pre className="whitespace-pre-wrap break-all text-[10px] bg-praxis-bg/60 p-1.5 rounded max-h-40 overflow-auto">
          {text}
        </pre>
      );
    }
    if (typeof value === 'string' || typeof value === 'number') {
      return <span className="font-mono">{String(value)}</span>;
    }
    return (
      <span className="font-mono text-[10px]">{JSON.stringify(value)}</span>
    );
  };

  return (
    <div className="rounded-md border border-red-200 bg-red-50 p-2 space-y-1.5">
      <div className="text-xs font-semibold text-red-800">
        Failure details
      </div>
      {hasKnown && (
        <dl className="grid grid-cols-[max-content_1fr] gap-x-2 gap-y-0.5 text-xs">
          {knownEntries.map(([k, v]) => (
            <React.Fragment key={k}>
              <dt className="text-praxis-text-muted">{k}</dt>
              <dd>{renderValue(k, v)}</dd>
            </React.Fragment>
          ))}
        </dl>
      )}
      {hasOther && (
        <details className="text-[10px]">
          <summary className="cursor-pointer text-praxis-text-muted">
            Raw details ({otherKeys.length} other field{otherKeys.length === 1 ? '' : 's'})
          </summary>
          <pre className="bg-praxis-bg/60 p-1.5 rounded mt-1 overflow-auto max-h-40">
            {JSON.stringify(
              Object.fromEntries(otherKeys.map((k) => [k, details[k]])),
              null,
              2,
            )}
          </pre>
        </details>
      )}
    </div>
  );
};

export default PatchUpdatePlanDetailPage;
