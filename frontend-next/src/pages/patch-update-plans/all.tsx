/**
 * PRA-164 #4: patch update plans list page.
 *
 * Operator-facing list of every dry-run patch update plan with
 * state + policy filters and a quick-create form. Mirrors the
 * patch-policies list shape - no hero, no decorative sections,
 * dense tabular operator surface.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Archive, Eye, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import Badge from '@/components/ui/Badge';
import PageHeader from '@/components/ui/PageHeader';
import { Button, LoadingState, ConfirmModal, Modal } from '@/components/ui';
import ExportButton from '@/components/ExportButton';
import { useAuth } from '@/context/AuthContext';
import {
  archivePatchUpdatePlan,
  createPatchUpdatePlanDryRun,
  deletePatchUpdatePlan,
  listPatchUpdatePlans,
  PatchUpdatePlanApiError,
  type PatchUpdatePlan,
  type PlanState,
  PLAN_STATE_VALUES,
} from '@/services/patchUpdatePlanService';
import {
  listPatchPolicies,
  type PatchPolicy,
} from '@/services/patchPolicyService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const STATE_LABELS: Record<PlanState, string> = {
  draft: 'Draft',
  awaiting_approval: 'Awaiting Approval',
  approved: 'Approved',
  scheduled: 'Scheduled',
  blocked: 'Blocked',
  superseded: 'Superseded',
  canceled: 'Canceled',
};

type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'orange';

const STATE_VARIANTS: Record<PlanState, BadgeVariant> = {
  draft: 'neutral',
  awaiting_approval: 'warning',
  approved: 'success',
  scheduled: 'info',
  blocked: 'danger',
  superseded: 'neutral',
  canceled: 'neutral',
};

const PatchUpdatePlansListPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const { canWrite, isAdmin } = useAuth();
  const [plans, setPlans] = useState<PatchUpdatePlan[] | null>(null);
  const [policies, setPolicies] = useState<PatchPolicy[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [stateFilter, setStateFilter] = useState<'' | PlanState>('');
  const [policyFilter, setPolicyFilter] = useState<'' | string>('');
  const [showArchived, setShowArchived] = useState(false);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<PatchUpdatePlan | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [confirmArchive, setConfirmArchive] = useState<PatchUpdatePlan | null>(null);
  const [archiveReason, setArchiveReason] = useState('');
  const [archiving, setArchiving] = useState(false);
  const [form, setForm] = useState<{
    policy_id: string;
    name: string;
    description: string;
  }>({ policy_id: '', name: '', description: '' });

  const refresh = useCallback(async () => {
    try {
      const opts: {
        policy_id?: number;
        state?: PlanState;
        include_archived?: boolean;
      } = {};
      if (stateFilter) opts.state = stateFilter as PlanState;
      if (policyFilter) opts.policy_id = Number(policyFilter);
      if (showArchived) opts.include_archived = true;
      const [planRows, policyRows] = await Promise.all([
        listPatchUpdatePlans(opts),
        listPatchPolicies(),
      ]);
      setPlans(planRows);
      setPolicies(policyRows);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [stateFilter, policyFilter, showArchived]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const policyById = useMemo(() => {
    const m = new Map<number, PatchPolicy>();
    for (const p of policies) m.set(p.id, p);
    return m;
  }, [policies]);

  const canSubmit = !!form.policy_id && !!form.name.trim();

  const handleCreate = async () => {
    setCreating(true);
    try {
      const plan = await createPatchUpdatePlanDryRun({
        policy_id: Number(form.policy_id),
        name: form.name.trim(),
        description: form.description.trim() || null,
      });
      toast.success(`Plan ${plan.name} created (state: ${plan.state})`);
      setForm({ policy_id: '', name: '', description: '' });
      setShowCreate(false);
      await refresh();
    } catch (e) {
      const msg =
        e instanceof PatchUpdatePlanApiError
          ? `${e.message} (HTTP ${e.status})`
          : e instanceof Error
            ? e.message
            : String(e);
      toast.error(`Create plan failed: ${msg}`);
    } finally {
      setCreating(false);
    }
  };

  const handleDeletePlan = async (plan: PatchUpdatePlan) => {
    setDeleting(true);
    try {
      await deletePatchUpdatePlan(plan.id);
      toast.success(`Deleted plan "${plan.name}"`);
      setConfirmDelete(null);
      await refresh();
    } catch (e) {
      const msg =
        e instanceof PatchUpdatePlanApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : String(e);
      toast.error(`Delete plan failed: ${msg}`);
    } finally {
      setDeleting(false);
    }
  };

  const handleArchivePlan = async (plan: PatchUpdatePlan) => {
    setArchiving(true);
    try {
      await archivePatchUpdatePlan(plan.id, archiveReason);
      toast.success(`Archived plan "${plan.name}"`);
      setConfirmArchive(null);
      setArchiveReason('');
      await refresh();
    } catch (e) {
      const msg =
        e instanceof PatchUpdatePlanApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : String(e);
      toast.error(`Archive plan failed: ${msg}`);
    } finally {
      setArchiving(false);
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Patch Update Plans · Praxis</title>
      </Head>
      <div className="space-y-4 p-6">
        <PageHeader
          title="Patch Update Plans"
          subtitle="Dry-run plans built from patch policies. Approval, schedule, and audit-export controls live on the plan detail page."
          actions={
            <div className="flex items-center gap-2">
              {/*
                PRA-178 Slice 1: bounded review-period export of patch
                update executions. Defaults to the last 30 days; the
                backend rejects windows > 366 days and filter sets that
                would produce more than 50,000 rows with HTTP 422.
                Admin/maintainer only - gated via the same canWrite
                helper that other write-action affordances use so
                auditor/read-only users never see a button that
                would 403 on click (PRA-178 Slice 1a fix to the P1
                review finding).
              */}
              {canWrite ? (
                <>
                  <ExportButton
                    endpoint="/api/backend/patch/update-executions/export"
                    filename="patch-executions-export"
                  />
                  {/* PRA-178 Slice 4: bounded review-period export of
                      patch update plans (the rows on this page).
                      Same RBAC + canWrite gating as Slice 1. */}
                  <ExportButton
                    endpoint="/api/backend/patch/update-plans/export"
                    filename="patch-update-plans-export"
                  />
                </>
              ) : (
                <span
                  className="text-[11px] text-gray-500"
                  title="Bulk export requires the admin or maintainer role."
                  data-testid="patch-executions-export-rbac-required"
                >
                  Export requires admin or maintainer
                </span>
              )}
              <button
                type="button"
                onClick={() => setShowCreate((v) => !v)}
                className="inline-flex items-center gap-1.5 rounded-md border border-praxis-border bg-praxis-surface px-3 py-1.5 text-xs font-medium text-praxis-text hover:bg-praxis-surface-2"
              >
                <Plus size={13} />
                {showCreate ? 'Hide' : 'New plan'}
              </button>
            </div>
          }
        />

        {showCreate && (
          <div className="rounded-md border border-praxis-border bg-praxis-surface p-4 space-y-3">
            <h2 className="text-sm font-semibold">Create dry-run plan</h2>
            <div className="grid grid-cols-1 sm:grid-cols-3 gap-3">
              <label className="text-xs text-praxis-text-muted">
                Policy
                <select
                  value={form.policy_id}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, policy_id: e.target.value }))
                  }
                  className="mt-1 block w-full rounded border border-praxis-border bg-praxis-bg p-1.5 text-sm"
                >
                  <option value="">Select a policy…</option>
                  {policies.map((p) => (
                    <option key={p.id} value={p.id}>
                      {p.slug}
                    </option>
                  ))}
                </select>
              </label>
              <label className="text-xs text-praxis-text-muted">
                Name
                <input
                  type="text"
                  value={form.name}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, name: e.target.value }))
                  }
                  className="mt-1 block w-full rounded border border-praxis-border bg-praxis-bg p-1.5 text-sm"
                />
              </label>
              <label className="text-xs text-praxis-text-muted">
                Description
                <input
                  type="text"
                  value={form.description}
                  onChange={(e) =>
                    setForm((f) => ({ ...f, description: e.target.value }))
                  }
                  className="mt-1 block w-full rounded border border-praxis-border bg-praxis-bg p-1.5 text-sm"
                />
              </label>
            </div>
            <div className="flex gap-2">
              <button
                type="button"
                disabled={!canSubmit || creating}
                onClick={handleCreate}
                className="inline-flex items-center rounded-md bg-praxis-primary px-3 py-1.5 text-xs font-medium text-white disabled:opacity-50"
              >
                {creating ? 'Creating…' : 'Create dry-run'}
              </button>
              <button
                type="button"
                onClick={() => setShowCreate(false)}
                className="inline-flex items-center rounded-md border border-praxis-border bg-praxis-surface px-3 py-1.5 text-xs"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        <div className="flex flex-wrap gap-3 items-end">
          <label className="text-xs text-praxis-text-muted">
            State
            <select
              value={stateFilter}
              onChange={(e) =>
                setStateFilter(e.target.value as '' | PlanState)
              }
              className="mt-1 block rounded border border-praxis-border bg-praxis-bg p-1.5 text-sm"
            >
              <option value="">All states</option>
              {PLAN_STATE_VALUES.map((s) => (
                <option key={s} value={s}>
                  {STATE_LABELS[s]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-praxis-text-muted">
            Policy
            <select
              value={policyFilter}
              onChange={(e) => setPolicyFilter(e.target.value)}
              className="mt-1 block rounded border border-praxis-border bg-praxis-bg p-1.5 text-sm"
            >
              <option value="">All policies</option>
              {policies.map((p) => (
                <option key={p.id} value={p.id}>
                  {p.slug}
                </option>
              ))}
            </select>
          </label>
          <label className="flex items-center gap-1.5 text-xs text-praxis-text-muted">
            <input
              type="checkbox"
              checked={showArchived}
              onChange={(e) => setShowArchived(e.target.checked)}
              className="rounded border-praxis-border"
            />
            Show archived
          </label>
        </div>

        {error && (
          <div className="rounded-md border border-red-300 bg-red-50 p-3 text-sm text-red-800">
            Something went wrong. Please try again.
          </div>
        )}

        <div className="overflow-auto rounded-md border border-praxis-border">
          <table className="min-w-full text-xs">
            <thead className="bg-praxis-surface text-praxis-text-muted">
              <tr>
                <th className="px-3 py-2 text-left font-medium">ID</th>
                <th className="px-3 py-2 text-left font-medium">Name</th>
                <th className="px-3 py-2 text-left font-medium">Policy</th>
                <th className="px-3 py-2 text-left font-medium">State</th>
                <th className="px-3 py-2 text-left font-medium">Created</th>
                <th className="px-3 py-2"></th>
              </tr>
            </thead>
            <tbody>
              {plans === null ? (
                <tr>
                  <td colSpan={6} className="px-3 py-4 text-center text-praxis-text-muted">
                    <LoadingState label="Loading plans" />
                  </td>
                </tr>
              ) : plans.length === 0 ? (
                <tr>
                  <td colSpan={6} className="px-3 py-4 text-center text-praxis-text-muted">
                    No plans match the current filter.
                  </td>
                </tr>
              ) : (
                plans.map((plan) => {
                  const policy =
                    plan.policy_id != null
                      ? policyById.get(plan.policy_id)
                      : undefined;
                  const archived = plan.archived_at != null;
                  const policyLabel = policy
                    ? policy.slug
                    : plan.policy_id != null
                      ? `#${plan.policy_id}`
                      : (typeof plan.policy_snapshot?.slug === 'string'
                          ? `${plan.policy_snapshot.slug} (deleted)`
                          : '-');
                  return (
                    <tr
                      key={plan.id}
                      className={`border-t border-praxis-border${archived ? ' opacity-60' : ''}`}
                    >
                      <td className="px-3 py-2 font-mono">{plan.id}</td>
                      <td className="px-3 py-2">
                        <Link
                          href={`/patch-update-plans/${plan.id}`}
                          className="text-praxis-link hover:underline"
                        >
                          {plan.name}
                        </Link>
                        {plan.description && (
                          <div className="text-praxis-text-muted">
                            {plan.description}
                          </div>
                        )}
                      </td>
                      <td className="px-3 py-2">{policyLabel}</td>
                      <td className="px-3 py-2">
                        <div className="flex items-center gap-1.5">
                          <Badge variant={STATE_VARIANTS[plan.state]}>
                            {STATE_LABELS[plan.state]}
                          </Badge>
                          {archived && (
                            <Badge variant="neutral">Archived</Badge>
                          )}
                        </div>
                      </td>
                      <td className="px-3 py-2 text-praxis-text-muted">
                        {formatTimestamp(plan.created_at)}
                      </td>
                      <td className="px-3 py-2 text-right">
                        <div className="inline-flex items-center gap-3">
                          <Link
                            href={`/patch-update-plans/${plan.id}`}
                            className="inline-flex items-center gap-1 text-praxis-link hover:underline"
                          >
                            <Eye size={13} />
                            View
                          </Link>
                          {/* Delete vs Archive is decided by the backend
                              (can_hard_delete / can_archive), never inferred
                              from state - a blocked plan with approval history
                              is NOT hard-deletable but IS archivable. */}
                          {canWrite && plan.can_hard_delete && (
                            <button
                              onClick={() => setConfirmDelete(plan)}
                              className="inline-flex items-center gap-1 rounded p-1 text-praxis-text-muted hover:text-danger"
                              title="Delete plan"
                            >
                              <Trash2 size={13} />
                            </button>
                          )}
                          {/* Plans with history: admin archive/retire
                              (audit-preserving), never destructive delete. */}
                          {isAdmin && plan.can_archive && (
                            <button
                              onClick={() => {
                                setArchiveReason('');
                                setConfirmArchive(plan);
                              }}
                              className="inline-flex items-center gap-1 rounded p-1 text-praxis-text-muted hover:text-warning"
                              title="Archive plan (preserves audit history)"
                            >
                              <Archive size={13} />
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>
      </div>
      <ConfirmModal
        open={confirmDelete !== null}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => {
          if (confirmDelete) void handleDeletePlan(confirmDelete);
        }}
        title="Delete patch update plan"
        message={
          confirmDelete
            ? `Delete plan "${confirmDelete.name}"? This removes the draft plan and its unexecuted selections. Plans with approval, schedule, or execution history cannot be deleted - archive those instead to preserve the audit trail.`
            : ''
        }
        confirmLabel="Delete"
        variant="danger"
        loading={deleting}
      />
      <Modal
        open={confirmArchive !== null}
        onClose={() => {
          setConfirmArchive(null);
          setArchiveReason('');
        }}
        title="Archive patch update plan"
        maxWidth="max-w-md"
      >
        <p className="text-sm text-content-muted leading-relaxed">
          {confirmArchive
            ? `Archive plan "${confirmArchive.name}"? It leaves the normal plan list but is NOT deleted - every approval, schedule, execution, reboot, rollback, and selected-package record is retained as an immutable audit tombstone and stays queryable from audit/reporting surfaces.`
            : ''}
        </p>
        <label className="mt-4 block text-xs text-content-muted">
          Reason (optional)
          <textarea
            value={archiveReason}
            onChange={(e) => setArchiveReason(e.target.value)}
            rows={2}
            placeholder="Why is this plan being retired?"
            className="mt-1 block w-full rounded border border-praxis-border bg-praxis-bg p-1.5 text-sm text-praxis-text"
          />
        </label>
        <div className="mt-6 flex justify-end gap-3">
          <Button
            variant="ghost"
            onClick={() => {
              setConfirmArchive(null);
              setArchiveReason('');
            }}
            disabled={archiving}
          >
            Cancel
          </Button>
          <Button
            variant="primary"
            onClick={() => {
              if (confirmArchive) void handleArchivePlan(confirmArchive);
            }}
            loading={archiving}
          >
            Archive
          </Button>
        </div>
      </Modal>
    </MainLayout>
  );
};

export default PatchUpdatePlansListPage;
