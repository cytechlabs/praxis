/**
 * PRA-165 Slice 4: compliance policies list.
 *
 * Mirrors the patch-policies list shape: dense tabular view with a
 * collapsible "create policy" form above. Built-in starter pack
 * policies are flagged so operators don't try to delete them
 * (backend refuses anyway, but the UI hides the delete CTA).
 *
 * Auditors see the table but never the create form or delete CTA -
 * the canWrite gate from AuthContext drives the visibility. The
 * backend enforces the same RBAC; client-side hiding is for UX, not
 * security.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Plus, ShieldCheck, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import {
  Badge,
  Button,
  Card,
  CardBody,
  ConfirmModal,
  EmptyState,
  PageHeader,
  SkeletonTable,
} from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  COMPLIANCE_SEVERITIES,
  ComplianceApiError,
  CompliancePolicy,
  createCompliancePolicy,
  deleteCompliancePolicy,
  listCompliancePolicies,
  SEVERITY_LABELS,
  severityBadgeVariant,
  type ComplianceSeverity,
} from '@/services/complianceService';

type BuiltInFilter = 'all' | 'built_in' | 'custom';

const CompliancePoliciesPage: React.FC = () => {
  const [policies, setPolicies] = useState<CompliancePolicy[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<CompliancePolicy | null>(
    null,
  );
  const [builtInFilter, setBuiltInFilter] = useState<BuiltInFilter>('all');
  const [enabledOnly, setEnabledOnly] = useState(false);
  const [form, setForm] = useState<{
    slug: string;
    name: string;
    description: string;
    severity: ComplianceSeverity;
    category: string;
  }>({
    slug: '',
    name: '',
    description: '',
    severity: 'medium',
    category: 'custom',
  });
  const { canWrite, isAdmin } = useAuth();

  const refresh = useCallback(async () => {
    try {
      // Backend supports ``built_in_only`` directly. For the "custom
      // only" filter the API has no negative flag, so we fetch all and
      // post-filter client-side. The page caps result count at 500
      // (backend max), so this stays bounded.
      const data = await listCompliancePolicies({
        built_in_only: builtInFilter === 'built_in' ? true : undefined,
        enabled_only: enabledOnly || undefined,
      });
      setPolicies(
        builtInFilter === 'custom' ? data.filter((p) => !p.built_in) : data,
      );
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [builtInFilter, enabledOnly]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const canSubmit = form.slug.trim().length > 0 && form.name.trim().length > 0;

  const handleCreate = async () => {
    setCreating(true);
    try {
      await createCompliancePolicy({
        slug: form.slug.trim(),
        name: form.name.trim(),
        description: form.description.trim() || null,
        severity: form.severity,
        category: form.category.trim() || 'custom',
      });
      toast.success('Policy created');
      setShowCreate(false);
      setForm({
        slug: '',
        name: '',
        description: '',
        severity: 'medium',
        category: 'custom',
      });
      await refresh();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Create failed: ${msg}`);
    } finally {
      setCreating(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deleteCompliancePolicy(pendingDelete.id);
      toast.success('Policy deleted');
      setPendingDelete(null);
      await refresh();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Delete failed: ${msg}`);
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Compliance Policies · Praxis</title>
      </Head>

      <div className="p-6 space-y-6">
        <PageHeader
          title="Compliance Policies"
          subtitle="Praxis-shaped compliance: named policies with typed check definitions. Not OpenSCAP."
          actions={
            canWrite ? (
              <Button variant="primary" onClick={() => setShowCreate((v) => !v)}>
                <Plus size={14} /> {showCreate ? 'Cancel' : 'New policy'}
              </Button>
            ) : undefined
          }
        />

        {showCreate && canWrite && (
          <Card>
            <CardBody>
              <h2 className="text-lg font-semibold text-content mb-4">
                New compliance policy
              </h2>
              <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
                <Field label="Slug">
                  <input
                    className="w-full bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
                    value={form.slug}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, slug: e.target.value }))
                    }
                    placeholder="ssh-baseline"
                  />
                </Field>
                <Field label="Name">
                  <input
                    className="w-full bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
                    value={form.name}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, name: e.target.value }))
                    }
                    placeholder="SSH Baseline"
                  />
                </Field>
                <Field label="Severity">
                  <select
                    className="w-full bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
                    value={form.severity}
                    onChange={(e) =>
                      setForm((f) => ({
                        ...f,
                        severity: e.target.value as ComplianceSeverity,
                      }))
                    }
                  >
                    {COMPLIANCE_SEVERITIES.map((s) => (
                      <option key={s} value={s}>
                        {SEVERITY_LABELS[s]}
                      </option>
                    ))}
                  </select>
                </Field>
                <Field label="Category">
                  <input
                    className="w-full bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
                    value={form.category}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, category: e.target.value }))
                    }
                    placeholder="access-control"
                  />
                </Field>
                <Field label="Description" wide>
                  <textarea
                    className="w-full bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
                    rows={3}
                    value={form.description}
                    onChange={(e) =>
                      setForm((f) => ({ ...f, description: e.target.value }))
                    }
                  />
                </Field>
              </div>
              <div className="mt-4 flex justify-end gap-2">
                <Button
                  variant="outline"
                  onClick={() => setShowCreate(false)}
                  disabled={creating}
                >
                  Cancel
                </Button>
                <Button
                  variant="primary"
                  onClick={handleCreate}
                  disabled={!canSubmit || creating}
                  loading={creating}
                >
                  Create policy
                </Button>
              </div>
            </CardBody>
          </Card>
        )}

        {error && (
          <Card>
            <CardBody>
              <p className="text-red-400 text-sm">
                Something went wrong. Please try again.
              </p>
            </CardBody>
          </Card>
        )}

        <Card>
          <CardBody>
            <div className="flex items-center gap-4 mb-4 flex-wrap">
              <div className="flex items-center gap-2">
                <label className="text-xs text-content-muted uppercase tracking-wide">
                  Origin
                </label>
                <select
                  className="bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
                  value={builtInFilter}
                  onChange={(e) =>
                    setBuiltInFilter(e.target.value as BuiltInFilter)
                  }
                >
                  <option value="all">All</option>
                  <option value="built_in">Built-in only</option>
                  <option value="custom">Custom only</option>
                </select>
              </div>
              <label className="flex items-center gap-2 text-sm text-content">
                <input
                  type="checkbox"
                  checked={enabledOnly}
                  onChange={(e) => setEnabledOnly(e.target.checked)}
                />
                Enabled only
              </label>
            </div>
            {policies === null ? (
              <SkeletonTable rows={5} cols={5} />
            ) : policies.length === 0 ? (
              <EmptyState
                icon={<ShieldCheck size={32} />}
                title="No compliance policies yet"
                description="Seed the CIS-aligned starter pack or create one above."
                action={
                  <Link
                    href="/compliance/starter-pack"
                    className="text-blue-400 hover:underline text-sm"
                  >
                    Browse starter pack →
                  </Link>
                }
              />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-left text-content-muted border-b border-border">
                    <tr>
                      <th className="py-2 pr-3">Slug</th>
                      <th className="py-2 pr-3">Name</th>
                      <th className="py-2 pr-3">Severity</th>
                      <th className="py-2 pr-3">Category</th>
                      <th className="py-2 pr-3">Enabled</th>
                      <th className="py-2 pr-3">Built-in</th>
                      <th className="py-2 pr-3"></th>
                    </tr>
                  </thead>
                  <tbody>
                    {policies.map((p) => (
                      <tr
                        key={p.id}
                        className="border-b border-border/50 hover:bg-surface-overlay/30"
                      >
                        <td className="py-2 pr-3">
                          <Link
                            href={`/compliance/policies/${p.id}`}
                            className="text-blue-400 hover:underline font-mono"
                          >
                            {p.slug}
                          </Link>
                        </td>
                        <td className="py-2 pr-3 text-content">{p.name}</td>
                        <td className="py-2 pr-3">
                          <Badge variant={severityBadgeVariant(p.severity)}>
                            {SEVERITY_LABELS[p.severity]}
                          </Badge>
                        </td>
                        <td className="py-2 pr-3 text-content">{p.category}</td>
                        <td className="py-2 pr-3">
                          {p.enabled ? (
                            <Badge variant="success">Enabled</Badge>
                          ) : (
                            <Badge variant="neutral">Disabled</Badge>
                          )}
                        </td>
                        <td className="py-2 pr-3">
                          {p.built_in ? (
                            <Badge variant="info">Built-in</Badge>
                          ) : (
                            <span className="text-xs text-content-subtle">-</span>
                          )}
                        </td>
                        <td className="py-2 pr-3 text-right">
                          {/* Delete is admin-only and refused for built-in
                              starter rows; hide the icon entirely for
                              auditors and built-in policies. */}
                          {isAdmin && !p.built_in && (
                            <button
                              onClick={() => setPendingDelete(p)}
                              className="text-red-400 hover:text-red-300"
                              title="Delete policy"
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      <ConfirmModal
        open={pendingDelete !== null}
        title="Delete compliance policy?"
        message={
          pendingDelete
            ? `This will delete policy "${pendingDelete.slug}" and all of its evidence rows. This cannot be undone.`
            : ''
        }
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleConfirmDelete}
        onClose={() => setPendingDelete(null)}
      />
    </MainLayout>
  );
};

const Field: React.FC<{
  label: string;
  children: React.ReactNode;
  wide?: boolean;
}> = ({ label, children, wide }) => (
  <div className={wide ? 'md:col-span-2' : ''}>
    <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">
      {label}
    </label>
    {children}
  </div>
);

export default CompliancePoliciesPage;
