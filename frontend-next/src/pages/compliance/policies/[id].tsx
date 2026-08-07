/**
 * PRA-165 Slice 4: compliance policy detail page.
 *
 * Four tabs:
 *
 *   - Overview: slug/severity/category/schedule/retention/guidance.
 *   - Checks: typed-kind aware list with create form (admin/maint).
 *   - Evidence: paginated table with verdict + offset paging. Shows
 *     ``runner_status`` and ``runner_owner`` per row so deferred
 *     kinds aren't presented as evaluated verdicts.
 *   - Summary: latest-run rollup per check + per host, exported in
 *     a stable shape the auditor can screenshot.
 *
 * Export buttons (JSONL/CSV) hang off the Evidence tab - direct
 * browser GET, filters carried through in the href.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import ExportEvidenceMenu from '@/components/compliance/ExportEvidenceMenu';
import OpenRemediationRequestButton from '@/components/compliance/OpenRemediationRequestButton';
import {
  Badge,
  Button,
  Card,
  CardBody,
  ConfirmModal,
  EmptyState,
  ErrorState,
  PageHeader,
  SkeletonTable,
  Tabs,
} from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  addPolicyCheck,
  CHECK_KIND_LABELS,
  COMPLIANCE_CHECK_KINDS,
  COMPLIANCE_SEVERITIES,
  ComplianceApiError,
  ComplianceCheck,
  ComplianceCheckKind,
  CompliancePolicyDetail,
  CompliancePolicySummary,
  ComplianceEvidencePage,
  ComplianceSeverity,
  Verdict,
  VERDICTS,
  deletePolicyCheck,
  getCompliancePolicy,
  getPolicySummary,
  isDeferredRunner,
  statusBadgeVariant,
  listPolicyEvidence,
  runCompliancePolicy,
  setCompliancePolicyEnabled,
  SEVERITY_LABELS,
  severityBadgeVariant,
  updateCompliancePolicy,
} from '@/services/complianceService';
import { fetchAllSystems } from '@/services/systemService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

type TabId = 'overview' | 'checks' | 'evidence' | 'summary';

const CompliancePolicyDetailPage: React.FC = () => {
  const router = useRouter();
  const policyId = Number(router.query.id);
  const { canWrite, isAdmin } = useAuth();

  const [policy, setPolicy] = useState<CompliancePolicyDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [activeTab, setActiveTab] = useState<TabId>('overview');
  const [running, setRunning] = useState(false);

  const refresh = useCallback(async () => {
    if (!Number.isFinite(policyId)) return;
    try {
      const data = await getCompliancePolicy(policyId);
      setPolicy(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [policyId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleToggleEnabled = async () => {
    if (!policy) return;
    try {
      await setCompliancePolicyEnabled(policy.id, !policy.enabled);
      toast.success(policy.enabled ? 'Policy disabled' : 'Policy enabled');
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  const handleRunNow = async () => {
    if (!policy) return;
    setRunning(true);
    try {
      const res = await runCompliancePolicy(policy.id);
      toast.success(`Evaluated: ${res.evidence_count} result(s) recorded`);
      await refresh();
      setActiveTab('summary');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setRunning(false);
    }
  };

  if (!Number.isFinite(policyId)) {
    return (
      <MainLayout>
        <div className="p-6 text-gray-400">Invalid policy id.</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>{policy ? `${policy.slug} · Compliance` : 'Compliance Policy'}</title>
      </Head>

      <div className="p-6 space-y-6">
        <PageHeader
          title={policy ? policy.name : 'Compliance Policy'}
          subtitle={
            policy
              ? `${policy.slug} · v${policy.version}${policy.built_in ? ' · built-in' : ''}`
              : undefined
          }
          actions={
            <div className="flex items-center gap-2">
              <Link
                href="/compliance/policies"
                className="inline-flex items-center gap-1.5 text-sm text-gray-300 hover:text-gray-100"
              >
                <ArrowLeft size={14} /> All policies
              </Link>
              {policy && canWrite && policy.enabled && (
                <Button
                  variant="primary"
                  onClick={handleRunNow}
                  disabled={running}
                  title="Evaluate this policy across the fleet now"
                >
                  {running ? 'Running…' : 'Run now'}
                </Button>
              )}
              {policy && canWrite && (
                <Button variant="outline" onClick={handleToggleEnabled}>
                  {policy.enabled ? 'Disable' : 'Enable'}
                </Button>
              )}
            </div>
          }
        />

        {error && (
          <Card>
            <CardBody>
              <p className="text-red-400 text-sm">
                Something went wrong. Please try again.
              </p>
            </CardBody>
          </Card>
        )}

        {!policy ? (
          <Card>
            <CardBody>
              <SkeletonTable rows={6} cols={2} />
            </CardBody>
          </Card>
        ) : (
          <>
            <div>
              <Tabs
                tabs={[
                  { id: 'overview', label: 'Overview' },
                  { id: 'checks', label: `Checks (${policy.checks.length})` },
                  { id: 'evidence', label: 'Evidence' },
                  { id: 'summary', label: 'Summary' },
                ]}
                active={activeTab}
                onChange={(id) => setActiveTab(id as TabId)}
              />
            </div>

            {activeTab === 'overview' && (
              <OverviewTab policy={policy} canWrite={canWrite} onSaved={refresh} />
            )}
            {activeTab === 'checks' && (
              <ChecksTab policy={policy} canWrite={canWrite} isAdmin={isAdmin} onChanged={refresh} />
            )}
            {activeTab === 'evidence' && <EvidenceTab policy={policy} canWrite={canWrite} />}
            {activeTab === 'summary' && <SummaryTab policyId={policy.id} />}
          </>
        )}
      </div>
    </MainLayout>
  );
};

// ---------------------------------------------------------------------------
// Overview tab
// ---------------------------------------------------------------------------

const OverviewTab: React.FC<{
  policy: CompliancePolicyDetail;
  canWrite: boolean;
  onSaved: () => Promise<void>;
}> = ({ policy, canWrite, onSaved }) => {
  const formatTimestamp = useFormatTimestamp();
  const [editing, setEditing] = useState(false);
  const [saving, setSaving] = useState(false);
  const [form, setForm] = useState({
    name: policy.name,
    description: policy.description ?? '',
    severity: policy.severity,
    category: policy.category,
    schedule_interval_hours: policy.schedule_interval_hours,
    evidence_retention_days: policy.evidence_retention_days,
    remediation_guidance: policy.remediation_guidance ?? '',
  });

  const handleSave = async () => {
    setSaving(true);
    try {
      await updateCompliancePolicy(policy.id, {
        name: form.name,
        description: form.description || null,
        severity: form.severity,
        category: form.category,
        schedule_interval_hours: Number(form.schedule_interval_hours),
        evidence_retention_days: Number(form.evidence_retention_days),
        remediation_guidance: form.remediation_guidance || null,
      });
      toast.success('Policy saved');
      setEditing(false);
      await onSaved();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setSaving(false);
    }
  };

  if (!editing) {
    return (
      <Card>
        <CardBody>
          <div className="grid grid-cols-1 md:grid-cols-2 gap-x-6 gap-y-4">
            <Row label="Slug" value={<span className="font-mono">{policy.slug}</span>} />
            <Row
              label="Severity"
              value={
                <Badge variant={severityBadgeVariant(policy.severity)}>
                  {SEVERITY_LABELS[policy.severity]}
                </Badge>
              }
            />
            <Row label="Category" value={policy.category} />
            <Row label="Enabled" value={policy.enabled ? 'Yes' : 'No'} />
            <Row
              label="Schedule interval"
              value={`${policy.schedule_interval_hours} hours`}
            />
            <Row
              label="Evidence retention"
              value={`${policy.evidence_retention_days} days`}
            />
            <Row
              label="Last run"
              value={
                policy.never_run ? (
                  <span className="text-yellow-400">Never run</span>
                ) : (
                  <span>
                    {formatTimestamp(policy.last_run_at as string)}
                    {policy.last_run_status === 'error' && (
                      <span className="ml-2 text-red-400">(error)</span>
                    )}
                    {policy.last_run_status === 'success' && (
                      <span className="ml-2 text-emerald-400">(success)</span>
                    )}
                  </span>
                )
              }
            />
            <Row
              label="Next run"
              value={
                policy.next_run_at
                  ? formatTimestamp(policy.next_run_at)
                  : policy.enabled
                    ? 'Due now'
                    : '-'
              }
            />
            <Row label="Built-in" value={policy.built_in ? 'Yes' : 'No'} />
            <Row label="Version" value={String(policy.version)} />
            <Row label="Created" value={formatTimestamp(policy.created_at)} />
            <Row label="Updated" value={formatTimestamp(policy.updated_at)} />
            {policy.description && (
              <Row label="Description" wide value={policy.description} />
            )}
            {policy.remediation_guidance && (
              <Row
                label="Remediation guidance"
                wide
                value={
                  <pre className="whitespace-pre-wrap text-sm text-gray-300">
                    {policy.remediation_guidance}
                  </pre>
                }
              />
            )}
          </div>
          {canWrite && (
            <div className="mt-6 flex justify-end">
              <Button variant="outline" onClick={() => setEditing(true)}>
                Edit
              </Button>
            </div>
          )}
        </CardBody>
      </Card>
    );
  }

  return (
    <Card>
      <CardBody>
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          <Field label="Name">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={form.name}
              onChange={(e) => setForm((f) => ({ ...f, name: e.target.value }))}
            />
          </Field>
          <Field label="Severity">
            <select
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={form.severity}
              onChange={(e) =>
                setForm((f) => ({ ...f, severity: e.target.value as ComplianceSeverity }))
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
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={form.category}
              onChange={(e) => setForm((f) => ({ ...f, category: e.target.value }))}
            />
          </Field>
          <Field label="Schedule interval (hours)">
            <input
              type="number"
              min={1}
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={form.schedule_interval_hours}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  schedule_interval_hours: Number(e.target.value),
                }))
              }
            />
          </Field>
          <Field label="Evidence retention (days)">
            <input
              type="number"
              min={1}
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={form.evidence_retention_days}
              onChange={(e) =>
                setForm((f) => ({
                  ...f,
                  evidence_retention_days: Number(e.target.value),
                }))
              }
            />
          </Field>
          <Field label="Description" wide>
            <textarea
              rows={3}
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={form.description}
              onChange={(e) =>
                setForm((f) => ({ ...f, description: e.target.value }))
              }
            />
          </Field>
          <Field label="Remediation guidance" wide>
            <textarea
              rows={4}
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={form.remediation_guidance}
              onChange={(e) =>
                setForm((f) => ({ ...f, remediation_guidance: e.target.value }))
              }
            />
          </Field>
        </div>
        <div className="mt-4 flex justify-end gap-2">
          <Button variant="outline" onClick={() => setEditing(false)} disabled={saving}>
            Cancel
          </Button>
          <Button variant="primary" onClick={handleSave} loading={saving}>
            Save
          </Button>
        </div>
      </CardBody>
    </Card>
  );
};

// ---------------------------------------------------------------------------
// Checks tab
// ---------------------------------------------------------------------------

interface CheckDefinitionDraft {
  kind: ComplianceCheckKind;
  package: string;
  min_version: string;
  fact_key: string;
  expected: string;
  path: string;
  sha256: string;
  command: string;
  expected_substring: string;
  expected_exit_code: string;
}

function blankDefinitionDraft(): CheckDefinitionDraft {
  return {
    kind: 'package_installed',
    package: '',
    min_version: '',
    fact_key: '',
    expected: '',
    path: '',
    sha256: '',
    command: '',
    expected_substring: '',
    expected_exit_code: '0',
  };
}

function buildDefinition(draft: CheckDefinitionDraft): Record<string, unknown> {
  switch (draft.kind) {
    case 'package_installed':
    case 'package_absent':
      return { package: draft.package };
    case 'package_version_min':
      return { package: draft.package, min_version: draft.min_version };
    case 'fact_equals':
      return { fact_key: draft.fact_key, expected: draft.expected };
    case 'fact_present':
    case 'fact_absent':
      return { fact_key: draft.fact_key };
    case 'file_exists':
      return { path: draft.path };
    case 'file_sha256':
      return { path: draft.path, sha256: draft.sha256 };
    case 'command_stdout_contains':
      return {
        command: draft.command,
        expected_substring: draft.expected_substring,
      };
    case 'command_exit_code':
      return {
        command: draft.command,
        expected_exit_code: Number(draft.expected_exit_code),
      };
  }
}

const ChecksTab: React.FC<{
  policy: CompliancePolicyDetail;
  canWrite: boolean;
  isAdmin: boolean;
  onChanged: () => Promise<void>;
}> = ({ policy, canWrite, onChanged }) => {
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [pendingDelete, setPendingDelete] = useState<ComplianceCheck | null>(
    null,
  );
  const [draft, setDraft] = useState({
    slug: '',
    title: '',
    def: blankDefinitionDraft(),
  });

  const handleCreate = async () => {
    setCreating(true);
    try {
      await addPolicyCheck(policy.id, {
        slug: draft.slug.trim(),
        title: draft.title.trim(),
        kind: draft.def.kind,
        definition: buildDefinition(draft.def),
      });
      toast.success('Check added');
      setShowCreate(false);
      setDraft({ slug: '', title: '', def: blankDefinitionDraft() });
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Add check failed: ${msg}`);
    } finally {
      setCreating(false);
    }
  };

  const handleConfirmDelete = async () => {
    if (!pendingDelete) return;
    try {
      await deletePolicyCheck(pendingDelete.id);
      toast.success('Check deleted');
      setPendingDelete(null);
      await onChanged();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    }
  };

  return (
    <>
      <Card>
        <CardBody>
          <div className="flex justify-between items-center mb-3">
            <h2 className="text-lg font-semibold text-gray-200">Checks</h2>
            {canWrite && (
              <Button
                variant="primary"
                onClick={() => setShowCreate((v) => !v)}
              >
                <Plus size={14} /> {showCreate ? 'Cancel' : 'New check'}
              </Button>
            )}
          </div>

          {showCreate && canWrite && (
            <CheckForm
              slug={draft.slug}
              title={draft.title}
              def={draft.def}
              onChange={(next) => setDraft(next)}
              onSubmit={handleCreate}
              onCancel={() => setShowCreate(false)}
              submitting={creating}
            />
          )}

          {policy.checks.length === 0 ? (
            <EmptyState
              title="No checks yet"
              description="Add a typed check to evaluate this policy against fleet evidence."
            />
          ) : (
            <table className="w-full text-sm mt-3">
              <thead className="text-left text-gray-400 border-b border-gray-800">
                <tr>
                  <th className="py-2 pr-3">Slug</th>
                  <th className="py-2 pr-3">Title</th>
                  <th className="py-2 pr-3">Kind</th>
                  <th className="py-2 pr-3">Runner</th>
                  <th className="py-2 pr-3">Enabled</th>
                  <th className="py-2 pr-3">Severity</th>
                  <th className="py-2 pr-3"></th>
                </tr>
              </thead>
              <tbody>
                {policy.checks.map((c) => (
                  <tr key={c.id} className="border-b border-gray-900/50">
                    <td className="py-2 pr-3 font-mono">{c.slug}</td>
                    <td className="py-2 pr-3 text-gray-200">{c.title}</td>
                    <td className="py-2 pr-3">
                      <span className="text-xs text-gray-300">
                        {CHECK_KIND_LABELS[c.kind]}
                      </span>
                    </td>
                    <td className="py-2 pr-3">
                      {isDeferredRunner(c.runner_owner) ? (
                        <Badge variant="warning">Requires file probe evidence</Badge>
                      ) : (
                        <Badge variant="info">Supported</Badge>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      {c.enabled ? (
                        <Badge variant="success">Yes</Badge>
                      ) : (
                        <Badge variant="neutral">No</Badge>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      {c.severity_override ? (
                        <Badge
                          variant={severityBadgeVariant(c.severity_override)}
                        >
                          {SEVERITY_LABELS[c.severity_override]}
                        </Badge>
                      ) : (
                        <span className="text-xs text-gray-500">inherits</span>
                      )}
                    </td>
                    <td className="py-2 pr-3 text-right">
                      {canWrite && (
                        <button
                          onClick={() => setPendingDelete(c)}
                          className="text-red-400 hover:text-red-300"
                          title="Delete check"
                        >
                          <Trash2 size={14} />
                        </button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          )}
        </CardBody>
      </Card>

      <ConfirmModal
        open={pendingDelete !== null}
        title="Delete check?"
        message={
          pendingDelete
            ? `Delete check "${pendingDelete.slug}"? Existing evidence rows survive (their check_id becomes null) so audit history is preserved.`
            : ''
        }
        confirmLabel="Delete"
        variant="danger"
        onConfirm={handleConfirmDelete}
        onClose={() => setPendingDelete(null)}
      />
    </>
  );
};

const CheckForm: React.FC<{
  slug: string;
  title: string;
  def: CheckDefinitionDraft;
  onChange: (next: { slug: string; title: string; def: CheckDefinitionDraft }) => void;
  onSubmit: () => void;
  onCancel: () => void;
  submitting: boolean;
}> = ({ slug, title, def, onChange, onSubmit, onCancel, submitting }) => {
  const setDef = (patch: Partial<CheckDefinitionDraft>) =>
    onChange({ slug, title, def: { ...def, ...patch } });

  return (
    <div className="border border-gray-800 rounded p-4 bg-gray-900/40 mb-4">
      <div className="grid grid-cols-1 md:grid-cols-3 gap-4">
        <Field label="Slug">
          <input
            className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
            value={slug}
            onChange={(e) => onChange({ slug: e.target.value, title, def })}
          />
        </Field>
        <Field label="Title">
          <input
            className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
            value={title}
            onChange={(e) => onChange({ slug, title: e.target.value, def })}
          />
        </Field>
        <Field label="Kind">
          <select
            aria-label="Kind"
            className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
            value={def.kind}
            onChange={(e) => setDef({ kind: e.target.value as ComplianceCheckKind })}
          >
            {COMPLIANCE_CHECK_KINDS.map((k) => (
              <option key={k} value={k}>
                {CHECK_KIND_LABELS[k]}
              </option>
            ))}
          </select>
        </Field>

        {(def.kind === 'package_installed' ||
          def.kind === 'package_absent' ||
          def.kind === 'package_version_min') && (
          <Field label="Package">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={def.package}
              onChange={(e) => setDef({ package: e.target.value })}
              placeholder="openssh-server"
            />
          </Field>
        )}
        {def.kind === 'package_version_min' && (
          <Field label="Min version">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={def.min_version}
              onChange={(e) => setDef({ min_version: e.target.value })}
              placeholder="3.0.0"
            />
          </Field>
        )}
        {(def.kind === 'fact_equals' ||
          def.kind === 'fact_present' ||
          def.kind === 'fact_absent') && (
          <Field label="Fact key">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={def.fact_key}
              onChange={(e) => setDef({ fact_key: e.target.value })}
              placeholder="host.kernel_version"
            />
          </Field>
        )}
        {def.kind === 'fact_equals' && (
          <Field label="Expected">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={def.expected}
              onChange={(e) => setDef({ expected: e.target.value })}
            />
          </Field>
        )}
        {(def.kind === 'file_exists' || def.kind === 'file_sha256') && (
          <Field label="Path">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={def.path}
              onChange={(e) => setDef({ path: e.target.value })}
              placeholder="/etc/sudoers"
            />
          </Field>
        )}
        {def.kind === 'file_sha256' && (
          <Field label="SHA-256">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm font-mono text-gray-100"
              value={def.sha256}
              onChange={(e) => setDef({ sha256: e.target.value })}
            />
          </Field>
        )}
        {(def.kind === 'command_stdout_contains' ||
          def.kind === 'command_exit_code') && (
          <Field label="Command" wide>
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm font-mono text-gray-100"
              value={def.command}
              onChange={(e) => setDef({ command: e.target.value })}
            />
          </Field>
        )}
        {def.kind === 'command_stdout_contains' && (
          <Field label="Expected substring">
            <input
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={def.expected_substring}
              onChange={(e) => setDef({ expected_substring: e.target.value })}
            />
          </Field>
        )}
        {def.kind === 'command_exit_code' && (
          <Field label="Expected exit code">
            <input
              type="number"
              min={0}
              max={255}
              className="w-full bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
              value={def.expected_exit_code}
              onChange={(e) => setDef({ expected_exit_code: e.target.value })}
            />
          </Field>
        )}

        {(def.kind === 'file_exists' ||
          def.kind === 'file_sha256' ||
          def.kind === 'command_stdout_contains' ||
          def.kind === 'command_exit_code') && (
          <div className="md:col-span-3 text-xs text-yellow-400">
            ⚠ File and command checks require probe evidence. Evidence rows
            will record <code className="font-mono">runner_deferred</code> until
            that evidence is available.
          </div>
        )}
      </div>

      <div className="mt-4 flex justify-end gap-2">
        <Button variant="outline" onClick={onCancel} disabled={submitting}>
          Cancel
        </Button>
        <Button
          variant="primary"
          onClick={onSubmit}
          loading={submitting}
          disabled={!slug.trim() || !title.trim()}
        >
          Add check
        </Button>
      </div>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Evidence tab
// ---------------------------------------------------------------------------

const EvidenceTab: React.FC<{
  policy: CompliancePolicyDetail;
  canWrite: boolean;
}> = ({ policy, canWrite }) => {
  const formatTimestamp = useFormatTimestamp();
  const [verdict, setVerdict] = useState<Verdict | ''>('');
  const [systemIdText, setSystemIdText] = useState('');
  const [page, setPage] = useState<ComplianceEvidencePage | null>(null);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  // system_id -> hostname for display. Evidence rows carry only system_id (they feed a
  // pinned export contract), so we resolve hostnames client-side; fall back to the id.
  const [hostNames, setHostNames] = useState<Record<number, string>>({});
  const limit = 50;

  useEffect(() => {
    fetchAllSystems()
      .then((rows) =>
        setHostNames(Object.fromEntries(rows.map((s) => [s.id, s.hostname]))),
      )
      .catch(() => setHostNames({}));
  }, []);

  const systemIdFilter = (() => {
    const trimmed = systemIdText.trim();
    if (!trimmed) return undefined;
    const n = Number(trimmed);
    return Number.isFinite(n) && n > 0 ? n : undefined;
  })();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await listPolicyEvidence(policy.id, {
        verdict: verdict || undefined,
        system_id: systemIdFilter,
        offset,
        limit,
      });
      setPage(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [policy.id, verdict, systemIdFilter, offset]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <Card>
      <CardBody>
        <div className="flex items-center justify-between mb-4 flex-wrap gap-3">
          <div className="flex items-center gap-3 flex-wrap">
            <div className="flex items-center gap-2">
              <label className="text-xs text-gray-400 uppercase tracking-wide">
                Verdict
              </label>
              <select
                aria-label="Verdict"
                className="bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
                value={verdict}
                onChange={(e) => {
                  setVerdict(e.target.value as Verdict | '');
                  setOffset(0);
                }}
              >
                <option value="">All</option>
                {VERDICTS.map((v) => (
                  <option key={v} value={v}>
                    {v}
                  </option>
                ))}
              </select>
            </div>
            <div className="flex items-center gap-2">
              <label className="text-xs text-gray-400 uppercase tracking-wide">
                System ID
              </label>
              <input
                aria-label="System ID"
                type="number"
                min={1}
                placeholder="any"
                className="w-24 bg-gray-900 border border-gray-800 rounded px-3 py-1.5 text-sm text-gray-100"
                value={systemIdText}
                onChange={(e) => {
                  setSystemIdText(e.target.value);
                  setOffset(0);
                }}
              />
            </div>
          </div>
          {canWrite && (
            <div className="flex items-center gap-2">
              <ExportEvidenceMenu
                baseOpts={{
                  policy_id: policy.id,
                  verdict: verdict || undefined,
                  system_id: systemIdFilter,
                }}
              />
            </div>
          )}
        </div>

        {error && (
          <p className="text-red-400 text-sm mb-2">
            Something went wrong. Please try again.
          </p>
        )}

        {loading && !page ? (
          <SkeletonTable rows={6} cols={6} />
        ) : page && page.items.length === 0 ? (
          <EmptyState
            title="No evidence rows match"
            description="Try clearing the verdict filter or wait for the next evaluation sweep."
          />
        ) : page ? (
          <>
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead className="text-left text-gray-400 border-b border-gray-800">
                  <tr>
                    <th className="py-2 pr-3">Evaluated</th>
                    <th className="py-2 pr-3">System</th>
                    <th className="py-2 pr-3">Check</th>
                    <th className="py-2 pr-3">Status</th>
                    <th className="py-2 pr-3">Evaluator</th>
                    <th className="py-2 pr-3">Reason</th>
                    <th className="py-2 pr-3">Observed</th>
                    <th className="py-2 pr-3"></th>
                  </tr>
                </thead>
                <tbody>
                  {page.items.map((r) => (
                    <tr key={r.id} className="border-b border-gray-900/50">
                      <td className="py-2 pr-3 text-xs text-gray-300">
                        {formatTimestamp(r.evaluated_at)}
                      </td>
                      <td className="py-2 pr-3">
                        <Link
                          href={`/compliance/systems/${r.system_id}`}
                          className="text-blue-400 hover:underline"
                        >
                          {hostNames[r.system_id] ?? `#${r.system_id}`}
                        </Link>
                      </td>
                      <td className="py-2 pr-3 font-mono text-xs">
                        {r.check_slug}
                      </td>
                      <td className="py-2 pr-3">
                        <Badge variant={statusBadgeVariant(r.status)}>
                          {r.status_label}
                        </Badge>
                      </td>
                      <td className="py-2 pr-3 text-xs text-gray-300">
                        {r.runner_label}
                      </td>
                      <td className="py-2 pr-3 text-xs text-gray-400">
                        {r.verdict_reason_label ?? '-'}
                      </td>
                      <td className="py-2 pr-3 text-xs text-gray-400 font-mono">
                        {r.observed_value ?? '-'}
                      </td>
                      <td className="py-2 pr-3 text-right">
                        <OpenRemediationRequestButton
                          row={r}
                          onOpened={refresh}
                        />
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
            <div className="mt-3 flex items-center justify-between text-xs text-gray-400">
              <span>
                Showing {page.items.length} of {page.total} (offset {page.offset})
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                >
                  Previous
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() =>
                    page.next_offset !== null && setOffset(page.next_offset)
                  }
                  disabled={page.next_offset === null}
                >
                  Next
                </Button>
              </div>
            </div>
          </>
        ) : null}
      </CardBody>
    </Card>
  );
};

// ---------------------------------------------------------------------------
// Summary tab
// ---------------------------------------------------------------------------

const SummaryTab: React.FC<{ policyId: number }> = ({ policyId }) => {
  const formatTimestamp = useFormatTimestamp();
  const [summary, setSummary] = useState<CompliancePolicySummary | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    (async () => {
      try {
        const data = await getPolicySummary(policyId);
        setSummary(data);
        setError(null);
      } catch (e) {
        setError(e instanceof Error ? e.message : String(e));
      }
    })();
  }, [policyId]);

  if (error) {
    return <ErrorState title="Couldn’t load summary" />;
  }

  if (!summary) {
    return (
      <Card>
        <CardBody>
          <SkeletonTable rows={3} cols={4} />
        </CardBody>
      </Card>
    );
  }

  if (summary.latest_run_at === null) {
    return (
      <Card>
        <CardBody>
          <EmptyState
            title="Not yet evaluated"
            description="The scheduler will pick this policy up at its next due window. You can verify the schedule on the Overview tab."
          />
        </CardBody>
      </Card>
    );
  }

  return (
    <div className="space-y-4">
      <Card>
        <CardBody>
          <div className="flex flex-wrap gap-6">
            <Stat label="Latest run" value={formatTimestamp(summary.latest_run_at)} />
            <Stat
              label="Pass"
              value={<span className="text-emerald-400">{summary.pass_count}</span>}
            />
            <Stat
              label="Fail"
              value={<span className="text-red-400">{summary.fail_count}</span>}
            />
            <Stat
              label="Error"
              value={<span className="text-yellow-400">{summary.error_count}</span>}
            />
            <Stat label="Run ID" value={
              <span className="font-mono text-xs">{summary.latest_run_id}</span>
            } />
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardBody>
          <h2 className="text-lg font-semibold text-gray-200 mb-3">Per check</h2>
          <table className="w-full text-sm">
            <thead className="text-left text-gray-400 border-b border-gray-800">
              <tr>
                <th className="py-2 pr-3">Check</th>
                <th className="py-2 pr-3">Kind</th>
                <th className="py-2 pr-3">Evaluator</th>
                <th className="py-2 pr-3">Pass</th>
                <th className="py-2 pr-3">Fail</th>
                <th className="py-2 pr-3">Error</th>
              </tr>
            </thead>
            <tbody>
              {summary.per_check.map((c) => (
                <tr
                  key={`${c.check_slug}-${c.check_id ?? 'deleted'}`}
                  className="border-b border-gray-900/50"
                >
                  <td className="py-2 pr-3 font-mono text-xs">{c.check_slug}</td>
                  <td className="py-2 pr-3 text-xs text-gray-300">
                    {CHECK_KIND_LABELS[c.check_kind]}
                  </td>
                  <td className="py-2 pr-3 text-xs text-gray-300">
                    {c.runner_label}
                  </td>
                  <td className="py-2 pr-3 font-mono text-emerald-400">
                    {c.pass_count}
                  </td>
                  <td className="py-2 pr-3 font-mono text-red-400">
                    {c.fail_count}
                  </td>
                  <td className="py-2 pr-3 font-mono text-yellow-400">
                    {c.error_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardBody>
      </Card>

      <Card>
        <CardBody>
          <h2 className="text-lg font-semibold text-gray-200 mb-3">Per host</h2>
          <table className="w-full text-sm">
            <thead className="text-left text-gray-400 border-b border-gray-800">
              <tr>
                <th className="py-2 pr-3">System</th>
                <th className="py-2 pr-3">Pass</th>
                <th className="py-2 pr-3">Fail</th>
                <th className="py-2 pr-3">Error</th>
              </tr>
            </thead>
            <tbody>
              {summary.per_host.map((h) => (
                <tr key={h.system_id} className="border-b border-gray-900/50">
                  <td className="py-2 pr-3">
                    <Link
                      href={`/compliance/systems/${h.system_id}`}
                      className="text-blue-400 hover:underline"
                    >
                      {h.hostname ?? `#${h.system_id}`}
                    </Link>
                  </td>
                  <td className="py-2 pr-3 font-mono text-emerald-400">
                    {h.pass_count}
                  </td>
                  <td className="py-2 pr-3 font-mono text-red-400">
                    {h.fail_count}
                  </td>
                  <td className="py-2 pr-3 font-mono text-yellow-400">
                    {h.error_count}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </CardBody>
      </Card>
    </div>
  );
};

// ---------------------------------------------------------------------------
// Tiny shared bits
// ---------------------------------------------------------------------------

const Row: React.FC<{
  label: string;
  value: React.ReactNode;
  wide?: boolean;
}> = ({ label, value, wide }) => (
  <div className={wide ? 'md:col-span-2' : ''}>
    <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
    <div className="text-sm text-gray-200 mt-0.5">{value}</div>
  </div>
);

const Field: React.FC<{
  label: string;
  children: React.ReactNode;
  wide?: boolean;
}> = ({ label, children, wide }) => (
  <div className={wide ? 'md:col-span-2' : ''}>
    <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">
      {label}
    </label>
    {children}
  </div>
);

const Stat: React.FC<{ label: string; value: React.ReactNode }> = ({ label, value }) => (
  <div className="min-w-[8rem]">
    <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
    <p className="text-lg font-semibold text-gray-100 mt-0.5">{value}</p>
  </div>
);

export default CompliancePolicyDetailPage;
