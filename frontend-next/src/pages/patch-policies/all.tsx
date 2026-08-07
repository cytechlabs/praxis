/**
 * PRA-161 #1f: patch policies list page.
 *
 * Operator-facing list of every patch policy. Mirrors the
 * content-profiles list shape (table + create form + detail link)
 * because the dense-tabular operational pattern is the locked
 * convention in this app - no hero, no decorative sections.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Eye, Plus, Star, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Badge, ConfirmModal, ErrorState, LoadingState, PageHeader } from '@/components/ui';
import {
  createPatchPolicy,
  deletePatchPolicy,
  listPatchPolicies,
  scopeRequiresPackages,
  type PatchPolicy,
  type ScopeKind,
  SCOPE_KIND_LABELS,
  REBOOT_POLICY_LABELS,
  ROLLOUT_CADENCE_LABELS,
  FAILURE_POLICY_LABELS,
  PatchPolicyApiError,
} from '@/services/patchPolicyService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const PatchPoliciesListPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [policies, setPolicies] = useState<PatchPolicy[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [confirmDelete, setConfirmDelete] = useState<PatchPolicy | null>(null);
  const [deleting, setDeleting] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState<{
    slug: string;
    name: string;
    description: string;
    scope_kind: ScopeKind;
    scope_packages_text: string;
  }>({
    slug: '',
    name: '',
    description: '',
    scope_kind: 'security_only',
    scope_packages_text: '',
  });

  const refresh = useCallback(async () => {
    try {
      const data = await listPatchPolicies();
      setPolicies(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const requiresPackages = scopeRequiresPackages(form.scope_kind);
  const parsedPackages = form.scope_packages_text
    .split(',')
    .map((s) => s.trim())
    .filter((s) => s.length > 0);
  const canSubmit =
    !!form.slug &&
    !!form.name &&
    (!requiresPackages || parsedPackages.length > 0);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await createPatchPolicy({
        slug: form.slug,
        name: form.name,
        description: form.description || null,
        scope_kind: form.scope_kind,
        // Only ship scope_packages when the scope kind expects them.
        // For security_only / full the backend invariant is "must be
        // empty" - sending [] is fine but redundant; sending a populated
        // list would be a guaranteed 422.
        scope_packages: requiresPackages ? parsedPackages : undefined,
      });
      toast.success(`Created patch policy "${form.slug}"`);
      setShowCreate(false);
      setForm({
        slug: '',
        name: '',
        description: '',
        scope_kind: 'security_only',
        scope_packages_text: '',
      });
      refresh();
    } catch (e) {
      const msg =
        e instanceof PatchPolicyApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : 'Failed to create patch policy';
      toast.error(msg);
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (policy: PatchPolicy) => {
    setDeleting(true);
    try {
      await deletePatchPolicy(policy.id);
      toast.success(`Deleted policy "${policy.slug}"`);
      setConfirmDelete(null);
      refresh();
    } catch (e) {
      const msg =
        e instanceof PatchPolicyApiError
          ? e.message
          : e instanceof Error
            ? e.message
            : 'Failed to delete patch policy';
      toast.error(msg);
    } finally {
      setDeleting(false);
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Patch policies · Praxis</title>
      </Head>
      <div className="p-6">
        <PageHeader
          title="Patch policies"
          subtitle="Patch policies define what may be planned and applied to a host: package scope, reboot rules and windows, rollout cadence, failure behavior, and approval governance. Bindings choose the effective policy through host, static-group, smart-group, or fleet-default scope."
          actions={
            <button
              onClick={() => setShowCreate(true)}
              className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500"
            >
              <Plus size={16} /> New policy
            </button>
          }
        />

        {error && (
          <ErrorState title="Couldn’t load patch policies" onRetry={refresh} />
        )}

        {showCreate && (
          <div className="mb-4 rounded border border-zinc-800 bg-[#111115] p-4">
            <h3 className="mb-3 text-sm font-medium text-gray-200">New patch policy</h3>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <label className="text-xs text-gray-400">
                Slug
                <input
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 font-mono text-sm text-gray-100"
                  value={form.slug}
                  onChange={(e) => setForm({ ...form, slug: e.target.value })}
                  placeholder="weekly-security"
                />
              </label>
              <label className="text-xs text-gray-400">
                Name
                <input
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-gray-100"
                  value={form.name}
                  onChange={(e) => setForm({ ...form, name: e.target.value })}
                  placeholder="Weekly security"
                />
              </label>
              <label className="text-xs text-gray-400">
                Scope
                <select
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-gray-100"
                  value={form.scope_kind}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      scope_kind: e.target.value as ScopeKind,
                      // Clear the package list when the operator
                      // switches back to a scope that requires it
                      // empty, so the submit body matches the
                      // server-side invariant.
                      scope_packages_text: scopeRequiresPackages(
                        e.target.value as ScopeKind,
                      )
                        ? form.scope_packages_text
                        : '',
                    })
                  }
                >
                  <option value="security_only">Security only</option>
                  <option value="full">Full</option>
                  <option value="package_allowlist">Allowlist</option>
                  <option value="package_denylist">Denylist</option>
                </select>
              </label>
              {requiresPackages && (
                <label className="text-xs text-gray-400 md:col-span-2">
                  Packages{' '}
                  <span className="text-gray-500">
                    (comma-separated; required for{' '}
                    {SCOPE_KIND_LABELS[form.scope_kind].toLowerCase()})
                  </span>
                  <input
                    className="mt-1 w-full rounded bg-black/40 px-2 py-1 font-mono text-sm text-gray-100"
                    value={form.scope_packages_text}
                    onChange={(e) =>
                      setForm({ ...form, scope_packages_text: e.target.value })
                    }
                    placeholder="openssl, nginx"
                  />
                </label>
              )}
              <label className="text-xs text-gray-400 md:col-span-2">
                Description (optional)
                <textarea
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-gray-100"
                  rows={2}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </label>
            </div>
            <p className="mt-3 text-xs text-gray-500">
              {requiresPackages
                ? 'Allowlist / denylist scopes need at least one package now; you can add more on the detail page.'
                : 'Reboot policy, windows, approval, cadence, and bindings can be set on the policy detail page after creation.'}
            </p>
            <div className="mt-3 flex gap-2">
              <button
                onClick={handleCreate}
                disabled={creating || !canSubmit}
                className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
              >
                {creating ? 'Creating…' : 'Create'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-zinc-800"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {policies === null && !error && <LoadingState label="Loading policies" />}

        {policies !== null && policies.length === 0 && (
          <div className="rounded border border-zinc-800 bg-[#111115] p-6 text-sm text-gray-400">
            No patch policies yet. Click{' '}
            <span className="text-gray-200">New policy</span> to create one.
          </div>
        )}

        {policies && policies.length > 0 && (
          <div className="overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
            <table className="w-full text-sm">
              <thead className="border-b border-zinc-800 text-left text-gray-400">
                <tr>
                  <th className="px-4 py-2">Slug / name</th>
                  <th className="px-4 py-2">Scope</th>
                  <th className="px-4 py-2">Reboot</th>
                  <th className="px-4 py-2">Approval</th>
                  <th className="px-4 py-2">Cadence</th>
                  <th className="px-4 py-2">Failure</th>
                  <th className="px-4 py-2">State</th>
                  <th className="px-4 py-2">Created</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {policies.map((p) => (
                  <tr key={p.id} className="hover:bg-zinc-900/40">
                    <td className="px-4 py-2">
                      <Link
                        href={`/patch-policies/${p.id}`}
                        className="font-mono text-blue-400 hover:text-blue-300"
                      >
                        {p.slug}
                      </Link>
                      <div className="text-xs text-gray-500">{p.name}</div>
                    </td>
                    <td className="px-4 py-2 text-gray-300">
                      <Badge variant="neutral">
                        {SCOPE_KIND_LABELS[p.scope_kind]}
                      </Badge>
                    </td>
                    <td className="px-4 py-2 text-gray-300">
                      {REBOOT_POLICY_LABELS[p.reboot_policy]}
                    </td>
                    <td className="px-4 py-2 text-gray-300">
                      {p.requires_approval ? `Required (${p.required_approvals})` : '-'}
                    </td>
                    <td className="px-4 py-2 text-gray-300">
                      {ROLLOUT_CADENCE_LABELS[p.rollout_cadence]}
                    </td>
                    <td className="px-4 py-2 text-gray-300">
                      {FAILURE_POLICY_LABELS[p.failure_policy]}
                    </td>
                    <td className="px-4 py-2">
                      <div className="flex items-center gap-2">
                        {p.enabled ? (
                          <Badge variant="success">Enabled</Badge>
                        ) : (
                          <Badge variant="neutral">Disabled</Badge>
                        )}
                        {p.is_fleet_default && (
                          <span
                            className="inline-flex items-center gap-1 rounded border border-amber-700/40 bg-amber-900/20 px-1.5 py-0.5 text-xs text-amber-300"
                            title="Fleet default - terminal fallback for the resolver"
                          >
                            <Star size={11} className="fill-amber-300" />
                            Fleet default
                          </span>
                        )}
                      </div>
                    </td>
                    <td className="px-4 py-2 text-gray-400">
                      {formatTimestamp(p.created_at)}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <Link
                        href={`/patch-policies/${p.id}`}
                        className="inline-flex items-center gap-1 rounded p-1 text-gray-400 hover:text-blue-400"
                        title="View detail"
                      >
                        <Eye size={16} />
                      </Link>
                      <button
                        onClick={() => setConfirmDelete(p)}
                        className="ml-1 inline-flex items-center gap-1 rounded p-1 text-gray-400 hover:text-red-400"
                        title="Delete"
                      >
                        <Trash2 size={16} />
                      </button>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
      <ConfirmModal
        open={confirmDelete !== null}
        onClose={() => setConfirmDelete(null)}
        onConfirm={() => {
          if (confirmDelete) void handleDelete(confirmDelete);
        }}
        title="Delete patch policy"
        message={
          confirmDelete
            ? `Delete patch policy "${confirmDelete.slug}"? This drops every host / group / smart-group binding that references it. The fleet-default policy, or a policy still linked to active update plans, cannot be deleted - archive or delete linked update plans first.`
            : ''
        }
        confirmLabel="Delete"
        variant="danger"
        loading={deleting}
      />
    </MainLayout>
  );
};

export default PatchPoliciesListPage;
