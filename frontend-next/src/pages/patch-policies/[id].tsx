/**
 * Patch policy detail page.
 *
 * Edit form + bindings (host / static-group / smart-group) + fleet-default
 * controls. The cycle-guard error from the slice 1e
 * ``bind_smart_group`` path ("smart group X references patch.* and
 * cannot be bound - feedback loop") is surfaced verbatim so operators
 * see the exact reason, not a generic toast.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import Link from 'next/link';
import {
  ArrowLeft,
  Plus,
  Save,
  Star,
  StarOff,
  Trash2,
  X,
} from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Badge, ErrorState, LoadingState, nativeSelectClass, PageHeader } from '@/components/ui';
import {
  bindPatchPolicyGroup,
  bindPatchPolicyHost,
  bindPatchPolicySmartGroup,
  clearFleetDefaultPatchPolicy,
  getPatchPolicy,
  listPatchPolicyBindings,
  PatchPolicyApiError,
  setFleetDefaultPatchPolicy,
  unbindPatchPolicyGroup,
  unbindPatchPolicyHost,
  unbindPatchPolicySmartGroup,
  updatePatchPolicy,
  scopeRequiresPackages,
  REBOOT_POLICY_LABELS,
  REBOOT_POLICY_VALUES,
  ROLLOUT_CADENCE_LABELS,
  ROLLOUT_CADENCE_VALUES,
  SCOPE_KIND_LABELS,
  SCOPE_KIND_VALUES,
  FAILURE_POLICY_LABELS,
  FAILURE_POLICY_VALUES,
  type PatchPolicy,
  type PatchPolicyBindings,
  type PatchPolicyUpdateInput,
  type RebootPolicy,
  type RolloutCadence,
  type ScopeKind,
  type FailurePolicy,
} from '@/services/patchPolicyService';
import { fetchAllSystems, fetchGroups } from '@/services/systemService';
import { apiFetch } from '@/utils/api';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface IdName {
  id: number;
  label: string;
}

const PatchPolicyDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const idParam = router.query.id;
  const policyId =
    typeof idParam === 'string' && idParam !== '' ? Number(idParam) : null;

  const [policy, setPolicy] = useState<PatchPolicy | null>(null);
  const [bindings, setBindings] = useState<PatchPolicyBindings | null>(null);
  const [error, setError] = useState<string | null>(null);

  // Lookup tables for resolving binding rows to friendly labels.
  const [systems, setSystems] = useState<IdName[]>([]);
  const [groups, setGroups] = useState<IdName[]>([]);
  const [smartGroups, setSmartGroups] = useState<IdName[]>([]);

  // Form state for the edit panel - mirrors the policy row but
  // tracks edits separately so cancel restores cleanly.
  const [edit, setEdit] = useState<PatchPolicyUpdateInput>({});
  const [scopePackagesText, setScopePackagesText] = useState('');
  const [saving, setSaving] = useState(false);

  // Add-binding selectors.
  const [addHostId, setAddHostId] = useState<string>('');
  const [addGroupId, setAddGroupId] = useState<string>('');
  const [addSmartGroupId, setAddSmartGroupId] = useState<string>('');

  // -- Fetch helpers --------------------------------------------------------

  const refreshPolicy = useCallback(async () => {
    if (!policyId) return;
    try {
      const data = await getPatchPolicy(policyId);
      setPolicy(data);
      setEdit({});
      setScopePackagesText((data.scope_packages || []).join(', '));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [policyId]);

  const refreshBindings = useCallback(async () => {
    if (!policyId) return;
    try {
      const data = await listPatchPolicyBindings(policyId);
      setBindings(data);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [policyId]);

  useEffect(() => {
    if (!policyId) return;
    refreshPolicy();
    refreshBindings();
    fetchAllSystems()
      .then((rows) =>
        setSystems(rows.map((r) => ({ id: r.id, label: r.hostname }))),
      )
      .catch(() => {
        /* non-fatal - id labels just won't resolve */
      });
    fetchGroups()
      .then((rows) =>
        setGroups(rows.map((r) => ({ id: r.id, label: r.name }))),
      )
      .catch(() => {
        /* non-fatal */
      });
    apiFetch('/api/backend/smart-groups')
      .then(async (res) => {
        if (!res.ok) return;
        const data = await res.json();
        const list = Array.isArray(data) ? data : data.smart_groups || [];
        setSmartGroups(
          list.map((sg: { id: number; name: string }) => ({
            id: sg.id,
            label: sg.name,
          })),
        );
      })
      .catch(() => {
        /* non-fatal */
      });
  }, [policyId, refreshPolicy, refreshBindings]);

  // -- Edit form ------------------------------------------------------------

  const merged: PatchPolicy | null = useMemo(() => {
    if (!policy) return null;
    return { ...policy, ...edit } as PatchPolicy;
  }, [policy, edit]);

  const dirty = useMemo(() => {
    if (!policy) return false;
    if (Object.keys(edit).length > 0) return true;
    const original = (policy.scope_packages || []).join(', ');
    return scopePackagesText.trim() !== original.trim();
  }, [policy, edit, scopePackagesText]);

  const onSave = async () => {
    if (!policy) return;
    setSaving(true);
    try {
      const payload: PatchPolicyUpdateInput = { ...edit };
      // Always ship scope_packages when scope_kind requires them, so the
      // server-side cross-field invariant has a value to evaluate.
      const nextScope = (edit.scope_kind ?? policy.scope_kind) as ScopeKind;
      const cleanPackages = scopePackagesText
        .split(',')
        .map((s) => s.trim())
        .filter((s) => s.length > 0);
      const originalPackages = (policy.scope_packages || []).join(',');
      const packagesChanged =
        cleanPackages.join(',') !== originalPackages.replace(/,\s*/g, ',');
      if (
        scopeRequiresPackages(nextScope) ||
        ('scope_kind' in edit && !scopeRequiresPackages(nextScope)) ||
        packagesChanged
      ) {
        payload.scope_packages = cleanPackages;
      }

      const updated = await updatePatchPolicy(policy.id, payload);
      setPolicy(updated);
      setEdit({});
      setScopePackagesText((updated.scope_packages || []).join(', '));
      toast.success('Saved');
    } catch (e) {
      const msg =
        e instanceof PatchPolicyApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : 'Save failed';
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const onCancel = () => {
    if (!policy) return;
    setEdit({});
    setScopePackagesText((policy.scope_packages || []).join(', '));
  };

  // -- Fleet default --------------------------------------------------------

  const onSetFleetDefault = async () => {
    if (!policy) return;
    if (
      !window.confirm(
        `Mark "${policy.slug}" as the fleet default? Any existing fleet-default policy will be cleared atomically.`,
      )
    ) {
      return;
    }
    try {
      const updated = await setFleetDefaultPatchPolicy(policy.id);
      setPolicy(updated);
      toast.success(`"${updated.slug}" is now the fleet default`);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to set fleet default');
    }
  };

  const onClearFleetDefault = async () => {
    if (!policy) return;
    try {
      const updated = await clearFleetDefaultPatchPolicy(policy.id);
      setPolicy(updated);
      toast.success(`Cleared fleet-default flag on "${updated.slug}"`);
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : 'Failed to clear fleet default',
      );
    }
  };

  // -- Bindings -------------------------------------------------------------

  const labelForId = (
    table: IdName[],
    id: number,
    fallback = 'unknown',
  ): string => {
    const row = table.find((r) => r.id === id);
    return row ? row.label : `${fallback} #${id}`;
  };

  const onAddHost = async () => {
    if (!policy || !addHostId) return;
    try {
      await bindPatchPolicyHost(policy.id, Number(addHostId));
      toast.success('Bound host');
      setAddHostId('');
      refreshBindings();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Bind host failed');
    }
  };

  const onAddGroup = async () => {
    if (!policy || !addGroupId) return;
    try {
      await bindPatchPolicyGroup(policy.id, Number(addGroupId));
      toast.success('Bound group');
      setAddGroupId('');
      refreshBindings();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Bind group failed');
    }
  };

  const onAddSmartGroup = async () => {
    if (!policy || !addSmartGroupId) return;
    try {
      await bindPatchPolicySmartGroup(policy.id, Number(addSmartGroupId));
      toast.success('Bound smart group');
      setAddSmartGroupId('');
      refreshBindings();
    } catch (e) {
      // The slice 1e cycle guard returns 422 with a message naming
      // the feedback-loop reason. Surface it verbatim - operators
      // need to see the exact rule.
      const msg =
        e instanceof PatchPolicyApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : 'Bind smart group failed';
      toast.error(msg);
    }
  };

  const onRemoveHost = async (hostId: number) => {
    if (!policy) return;
    try {
      await unbindPatchPolicyHost(policy.id, hostId);
      refreshBindings();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Unbind host failed');
    }
  };

  const onRemoveGroup = async (groupId: number) => {
    if (!policy) return;
    try {
      await unbindPatchPolicyGroup(policy.id, groupId);
      refreshBindings();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Unbind group failed');
    }
  };

  const onRemoveSmartGroup = async (smartGroupId: number) => {
    if (!policy) return;
    try {
      await unbindPatchPolicySmartGroup(policy.id, smartGroupId);
      refreshBindings();
    } catch (e) {
      toast.error(
        e instanceof Error ? e.message : 'Unbind smart group failed',
      );
    }
  };

  // -- Render ---------------------------------------------------------------

  if (!policyId) {
    return (
      <MainLayout>
        <LoadingState label="Loading policy" />
      </MainLayout>
    );
  }

  if (error && !policy) {
    return (
      <MainLayout>
        <div className="p-6">
          <ErrorState title="Couldn’t load patch policy" onRetry={refreshPolicy} />
        </div>
      </MainLayout>
    );
  }

  if (!policy || !merged) {
    return (
      <MainLayout>
        <LoadingState label="Loading policy" />
      </MainLayout>
    );
  }

  const fieldNeedsPackages = scopeRequiresPackages(merged.scope_kind);

  return (
    <MainLayout>
      <Head>
        <title>{policy.slug} · Patch policy · Praxis</title>
      </Head>
      <div className="p-6">
        <PageHeader
          title={policy.name}
          subtitle={`${policy.slug} · created ${formatTimestamp(policy.created_at)}`}
          actions={
            <Link
              href="/patch-policies/all"
              className="inline-flex items-center gap-1 rounded border border-border-strong px-3 py-1.5 text-sm text-content hover:bg-surface-overlay"
            >
              <ArrowLeft size={14} /> Back
            </Link>
          }
        />

        <div className="mb-3 flex flex-wrap items-center gap-2">
          {policy.enabled ? (
            <Badge variant="success">Enabled</Badge>
          ) : (
            <Badge variant="neutral">Disabled</Badge>
          )}
          {policy.is_fleet_default && (
            <span
              className="inline-flex items-center gap-1 rounded border border-amber-700/40 bg-amber-900/20 px-2 py-0.5 text-xs text-amber-300"
              title="Terminal fallback for the resolver - at most one fleet-default policy can exist."
            >
              <Star size={12} className="fill-amber-300" />
              Fleet default
            </span>
          )}
          <div className="ml-auto">
            {policy.is_fleet_default ? (
              <button
                onClick={onClearFleetDefault}
                className="inline-flex items-center gap-1 rounded border border-border-strong px-3 py-1.5 text-xs text-content hover:bg-surface-overlay"
              >
                <StarOff size={14} /> Clear fleet default
              </button>
            ) : (
              <button
                onClick={onSetFleetDefault}
                className="inline-flex items-center gap-1 rounded border border-amber-700/40 bg-amber-900/10 px-3 py-1.5 text-xs text-amber-300 hover:bg-amber-900/20"
                title="Mark as the fleet default - replaces any existing fleet-default policy atomically."
              >
                <Star size={14} /> Set as fleet default
              </button>
            )}
          </div>
        </div>

        {error && (
          <div className="mb-4 rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-300">
            Something went wrong. Please try again.
          </div>
        )}

        {/* Edit form */}
        <section className="mb-6 rounded border border-border bg-surface-raised p-4">
          <h3 className="mb-3 text-sm font-medium text-content">
            Policy fields
          </h3>
          <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
            <label className="text-xs text-content-muted">
              Slug (immutable)
              <input
                disabled
                className="mt-1 w-full rounded bg-black/20 px-2 py-1 font-mono text-sm text-content-muted"
                value={policy.slug}
              />
            </label>
            <label className="text-xs text-content-muted">
              Name
              <input
                className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-content"
                value={merged.name}
                onChange={(e) => setEdit({ ...edit, name: e.target.value })}
              />
            </label>
            <label className="text-xs text-content-muted md:col-span-2">
              Description
              <textarea
                className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-content"
                rows={2}
                value={merged.description ?? ''}
                onChange={(e) =>
                  setEdit({ ...edit, description: e.target.value || null })
                }
              />
            </label>
            <label className="text-xs text-content-muted">
              Scope
              <select
                className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                value={merged.scope_kind}
                onChange={(e) =>
                  setEdit({ ...edit, scope_kind: e.target.value as ScopeKind })
                }
              >
                {SCOPE_KIND_VALUES.map((v) => (
                  <option key={v} value={v}>
                    {SCOPE_KIND_LABELS[v]}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs text-content-muted">
              Reboot policy
              <select
                className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                value={merged.reboot_policy}
                onChange={(e) =>
                  setEdit({
                    ...edit,
                    reboot_policy: e.target.value as RebootPolicy,
                  })
                }
              >
                {REBOOT_POLICY_VALUES.map((v) => (
                  <option key={v} value={v}>
                    {REBOOT_POLICY_LABELS[v]}
                  </option>
                ))}
              </select>
            </label>
            <label className="text-xs text-content-muted md:col-span-2">
              Packages{' '}
              <span className="text-content-subtle">
                (comma-separated; required for allowlist / denylist; must be
                empty for security-only / full)
              </span>
              <input
                disabled={!fieldNeedsPackages && (merged.scope_packages || []).length === 0 && scopePackagesText.length === 0}
                className="mt-1 w-full rounded bg-black/40 px-2 py-1 font-mono text-sm text-content disabled:opacity-50"
                value={scopePackagesText}
                onChange={(e) => setScopePackagesText(e.target.value)}
                placeholder={
                  fieldNeedsPackages
                    ? 'openssl, nginx'
                    : '(must be empty for this scope)'
                }
              />
            </label>
            <label className="text-xs text-content-muted">
              Maintenance window ID
              <input
                type="number"
                className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-content"
                value={merged.maintenance_window_id ?? ''}
                onChange={(e) =>
                  setEdit({
                    ...edit,
                    maintenance_window_id: e.target.value
                      ? Number(e.target.value)
                      : null,
                  })
                }
                placeholder="(none)"
              />
            </label>
            <label className="text-xs text-content-muted">
              Reboot window ID
              <input
                type="number"
                className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-content"
                value={merged.reboot_window_id ?? ''}
                onChange={(e) =>
                  setEdit({
                    ...edit,
                    reboot_window_id: e.target.value
                      ? Number(e.target.value)
                      : null,
                  })
                }
                placeholder="(none)"
              />
            </label>
            <label className="flex items-center gap-2 text-xs text-content">
              <input
                type="checkbox"
                checked={merged.requires_approval}
                onChange={(e) =>
                  setEdit({ ...edit, requires_approval: e.target.checked })
                }
              />
              Requires approval
            </label>
            <label className="text-xs text-content-muted">
              Required approvals
              <input
                type="number"
                min={1}
                className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-content"
                value={merged.required_approvals}
                onChange={(e) =>
                  setEdit({
                    ...edit,
                    required_approvals: Math.max(
                      1,
                      Number(e.target.value) || 1,
                    ),
                  })
                }
              />
            </label>
            <label className="text-xs text-content-muted">
              Rollout cadence
              <select
                className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                value={merged.rollout_cadence}
                onChange={(e) =>
                  setEdit({
                    ...edit,
                    rollout_cadence: e.target.value as RolloutCadence,
                  })
                }
              >
                {ROLLOUT_CADENCE_VALUES.map((v) => (
                  <option key={v} value={v}>
                    {ROLLOUT_CADENCE_LABELS[v]}
                  </option>
                ))}
              </select>
              {merged.rollout_cadence === 'staged' && (
                <span className="mt-1 block text-[11px] text-amber-400">
                  Staged is policy intent only; ring binding is not yet enforced.
                </span>
              )}
            </label>
            <label className="text-xs text-content-muted">
              Failure policy
              <select
                className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                value={merged.failure_policy}
                onChange={(e) =>
                  setEdit({
                    ...edit,
                    failure_policy: e.target.value as FailurePolicy,
                  })
                }
              >
                {FAILURE_POLICY_VALUES.map((v) => (
                  <option key={v} value={v}>
                    {FAILURE_POLICY_LABELS[v]}
                  </option>
                ))}
              </select>
            </label>
            <label className="flex items-center gap-2 text-xs text-content">
              <input
                type="checkbox"
                checked={merged.enabled}
                onChange={(e) =>
                  setEdit({ ...edit, enabled: e.target.checked })
                }
              />
              Enabled
            </label>
          </div>
          <div className="mt-3 flex gap-2">
            <button
              onClick={onSave}
              disabled={!dirty || saving}
              className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
            >
              <Save size={14} /> {saving ? 'Saving…' : 'Save'}
            </button>
            <button
              onClick={onCancel}
              disabled={!dirty || saving}
              className="inline-flex items-center gap-1 rounded border border-border-strong px-3 py-1.5 text-sm text-content hover:bg-surface-overlay disabled:opacity-40"
            >
              <X size={14} /> Cancel
            </button>
          </div>
        </section>

        {/* Bindings */}
        <section className="mb-6 rounded border border-border bg-surface-raised p-4">
          <h3 className="mb-3 text-sm font-medium text-content">
            Bindings ·{' '}
            <span className="text-content-subtle">
              direct host &gt; static group &gt; smart group &gt; fleet default
            </span>
          </h3>

          {/* Hosts */}
          <div className="mb-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs uppercase tracking-wide text-content-muted">
                Direct host bindings ({bindings?.hosts.length ?? 0})
              </span>
              <div className="flex items-center gap-2">
                <select
                  className={`rounded px-2 py-1 text-xs ${nativeSelectClass}`}
                  value={addHostId}
                  onChange={(e) => setAddHostId(e.target.value)}
                >
                  <option value="">Select host...</option>
                  {systems
                    .filter(
                      (s) =>
                        !(bindings?.hosts ?? []).some((b) => b.system_id === s.id),
                    )
                    .map((s) => (
                      <option key={s.id} value={s.id}>
                        {s.label}
                      </option>
                    ))}
                </select>
                <button
                  onClick={onAddHost}
                  disabled={!addHostId}
                  className="inline-flex items-center gap-1 rounded bg-blue-600 px-2 py-1 text-xs text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <Plus size={12} /> Add
                </button>
              </div>
            </div>
            {bindings && bindings.hosts.length > 0 ? (
              <ul className="divide-y divide-border rounded border border-border">
                {bindings.hosts.map((b) => (
                  <li
                    key={b.id}
                    className="flex items-center justify-between px-3 py-1.5 text-sm"
                  >
                    <span className="text-content">
                      {labelForId(systems, b.system_id, 'host')}
                    </span>
                    <button
                      onClick={() => onRemoveHost(b.system_id)}
                      className="rounded p-1 text-content-muted hover:text-red-400"
                      title="Unbind"
                    >
                      <Trash2 size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-xs text-content-subtle">No direct host bindings.</div>
            )}
          </div>

          {/* Static groups */}
          <div className="mb-4">
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs uppercase tracking-wide text-content-muted">
                Static group bindings ({bindings?.groups.length ?? 0})
              </span>
              <div className="flex items-center gap-2">
                <select
                  className={`rounded px-2 py-1 text-xs ${nativeSelectClass}`}
                  value={addGroupId}
                  onChange={(e) => setAddGroupId(e.target.value)}
                >
                  <option value="">Select group...</option>
                  {groups
                    .filter(
                      (g) =>
                        !(bindings?.groups ?? []).some((b) => b.group_id === g.id),
                    )
                    .map((g) => (
                      <option key={g.id} value={g.id}>
                        {g.label}
                      </option>
                    ))}
                </select>
                <button
                  onClick={onAddGroup}
                  disabled={!addGroupId}
                  className="inline-flex items-center gap-1 rounded bg-blue-600 px-2 py-1 text-xs text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <Plus size={12} /> Add
                </button>
              </div>
            </div>
            {bindings && bindings.groups.length > 0 ? (
              <ul className="divide-y divide-border rounded border border-border">
                {bindings.groups.map((b) => (
                  <li
                    key={b.id}
                    className="flex items-center justify-between px-3 py-1.5 text-sm"
                  >
                    <span className="text-content">
                      {labelForId(groups, b.group_id, 'group')}
                    </span>
                    <button
                      onClick={() => onRemoveGroup(b.group_id)}
                      className="rounded p-1 text-content-muted hover:text-red-400"
                      title="Unbind"
                    >
                      <Trash2 size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-xs text-content-subtle">No static group bindings.</div>
            )}
          </div>

          {/* Smart groups */}
          <div>
            <div className="mb-2 flex items-center justify-between">
              <span className="text-xs uppercase tracking-wide text-content-muted">
                Smart group bindings ({bindings?.smart_groups.length ?? 0})
              </span>
              <div className="flex items-center gap-2">
                <select
                  className={`rounded px-2 py-1 text-xs ${nativeSelectClass}`}
                  value={addSmartGroupId}
                  onChange={(e) => setAddSmartGroupId(e.target.value)}
                >
                  <option value="">Select smart group...</option>
                  {smartGroups
                    .filter(
                      (sg) =>
                        !(bindings?.smart_groups ?? []).some(
                          (b) => b.smart_group_id === sg.id,
                        ),
                    )
                    .map((sg) => (
                      <option key={sg.id} value={sg.id}>
                        {sg.label}
                      </option>
                    ))}
                </select>
                <button
                  onClick={onAddSmartGroup}
                  disabled={!addSmartGroupId}
                  className="inline-flex items-center gap-1 rounded bg-blue-600 px-2 py-1 text-xs text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <Plus size={12} /> Add
                </button>
              </div>
            </div>
            <p className="mb-2 text-[11px] text-content-subtle">
              Smart groups whose rules reference{' '}
              <span className="font-mono">patch.*</span> cannot be bound here -
              the cycle would create a feedback loop where membership depends
              on the policy that membership assigns.
            </p>
            {bindings && bindings.smart_groups.length > 0 ? (
              <ul className="divide-y divide-border rounded border border-border">
                {bindings.smart_groups.map((b) => (
                  <li
                    key={b.id}
                    className="flex items-center justify-between px-3 py-1.5 text-sm"
                  >
                    <span className="text-content">
                      {labelForId(smartGroups, b.smart_group_id, 'smart group')}
                    </span>
                    <button
                      onClick={() => onRemoveSmartGroup(b.smart_group_id)}
                      className="rounded p-1 text-content-muted hover:text-red-400"
                      title="Unbind"
                    >
                      <Trash2 size={14} />
                    </button>
                  </li>
                ))}
              </ul>
            ) : (
              <div className="text-xs text-content-subtle">
                No smart group bindings.
              </div>
            )}
          </div>
        </section>
      </div>
    </MainLayout>
  );
};

export default PatchPolicyDetailPage;
