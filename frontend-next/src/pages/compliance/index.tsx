/**
 * PRA-165 Slice 4: compliance fleet dashboard.
 *
 * Top-level compliance landing page. Pulls a single
 * ``GET /compliance/fleet/summary`` and renders three rollups in
 * stacked tables: per-policy (with stale badge), per-severity, and
 * per-host. Export buttons hang off the per-policy table (admin /
 * maintainer only).
 *
 * The page is intentionally dense - no hero, no decorative
 * sections - to match the operator-facing convention used by patch
 * policies and content profiles.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { ClipboardCheck, ExternalLink, Play, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import ExportEvidenceMenu from '@/components/compliance/ExportEvidenceMenu';
import { Badge, Button, Card, CardBody, EmptyState, ErrorState, PageHeader, SkeletonTable } from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  ComplianceApiError,
  ComplianceFleetSummary,
  getFleetSummary,
  runCompliancePolicy,
  SEVERITY_LABELS,
  severityBadgeVariant,
  staleLabel,
} from '@/services/complianceService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const ComplianceDashboardPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [summary, setSummary] = useState<ComplianceFleetSummary | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [runningId, setRunningId] = useState<number | null>(null);
  const { canWrite } = useAuth();

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getFleetSummary();
      setSummary(data);
      setError(null);
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  const handleRunNow = useCallback(
    async (policyId: number, slug: string) => {
      setRunningId(policyId);
      try {
        const res = await runCompliancePolicy(policyId);
        toast.success(`Evaluated ${slug}: ${res.evidence_count} result(s) recorded`);
        await refresh();
      } catch (e) {
        const msg = e instanceof ComplianceApiError ? e.message : String(e);
        toast.error(`Run failed: ${msg}`);
      } finally {
        setRunningId(null);
      }
    },
    [refresh],
  );

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <MainLayout>
      <Head>
        <title>Compliance Dashboard · Praxis</title>
      </Head>

      <div className="p-6 space-y-6">
        <PageHeader
          title="Compliance Dashboard"
          subtitle="Fleet-wide compliance verdicts from the latest evaluation run of each enabled policy."
          actions={
            <div className="flex items-center gap-2">
              <Link
                href="/compliance/remediation"
                className="inline-flex items-center gap-1.5 px-3 py-1.5 rounded-md text-sm text-gray-300 hover:text-gray-100 hover:bg-white/5"
              >
                <ClipboardCheck size={14} /> Remediation
              </Link>
              <Button variant="outline" onClick={refresh}>
                <RefreshCw size={14} /> Refresh
              </Button>
              {canWrite && <ExportEvidenceMenu />}
            </div>
          }
        />

        {error && (
          <ErrorState title="Couldn’t load compliance" onRetry={refresh} />
        )}

        {loading && !summary && (
          <Card>
            <CardBody>
              <SkeletonTable rows={6} cols={5} />
            </CardBody>
          </Card>
        )}

        {summary && (
          <>
            <Card>
              <CardBody>
                <div className="flex flex-wrap gap-6">
                  <Stat label="Policies" value={summary.policy_count} />
                  <Stat label="Enabled" value={summary.enabled_policy_count} />
                  <Stat label="Hosts evaluated" value={summary.host_count} />
                  <Stat
                    label="Pass / Fail / Error"
                    value={
                      <span className="font-mono">
                        <span className="text-emerald-400">{summary.pass_count}</span>
                        <span className="text-gray-500"> / </span>
                        <span className="text-red-400">{summary.fail_count}</span>
                        <span className="text-gray-500"> / </span>
                        <span className="text-yellow-400">{summary.error_count}</span>
                      </span>
                    }
                  />
                  <Stat
                    label="Generated"
                    value={
                      <span className="text-xs text-gray-300">
                        {formatTimestamp(summary.generated_at)}
                      </span>
                    }
                  />
                </div>
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <h2 className="text-lg font-semibold text-gray-200 mb-3">
                  Policies
                </h2>
                {summary.per_policy.length === 0 ? (
                  <EmptyState
                    title="No compliance policies yet"
                    description="Seed the CIS-aligned starter pack or author a custom policy."
                  />
                ) : (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="text-left text-gray-400 border-b border-gray-800">
                        <tr>
                          <th className="py-2 pr-3">Policy</th>
                          <th className="py-2 pr-3">Severity</th>
                          <th className="py-2 pr-3">Status</th>
                          <th className="py-2 pr-3">Last run</th>
                          <th className="py-2 pr-3">Next run</th>
                          <th className="py-2 pr-3">Pass</th>
                          <th className="py-2 pr-3">Fail</th>
                          <th className="py-2 pr-3">Error</th>
                          <th className="py-2 pr-3">Actions</th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.per_policy.map((row) => (
                          <tr
                            key={row.policy_id}
                            className="border-b border-gray-900/50 hover:bg-gray-900/30"
                          >
                            <td className="py-2 pr-3">
                              <Link
                                href={`/compliance/policies/${row.policy_id}`}
                                className="text-blue-400 hover:underline"
                              >
                                {row.policy_slug}
                              </Link>
                              {!row.enabled && (
                                <span className="ml-2 text-xs text-gray-500">(disabled)</span>
                              )}
                            </td>
                            <td className="py-2 pr-3">
                              <Badge variant={severityBadgeVariant(row.severity)}>
                                {SEVERITY_LABELS[row.severity]}
                              </Badge>
                            </td>
                            <td className="py-2 pr-3">
                              {runningId === row.policy_id ? (
                                <Badge variant="info">Running…</Badge>
                              ) : row.never_run ? (
                                <Badge variant="warning">Never run</Badge>
                              ) : row.last_run_status === 'error' ? (
                                <Badge variant="danger">Error</Badge>
                              ) : row.stale ? (
                                <Badge variant="warning">{staleLabel(row)}</Badge>
                              ) : (
                                <Badge variant="success">Up to date</Badge>
                              )}
                            </td>
                            <td className="py-2 pr-3 text-gray-300 text-xs">
                              {row.last_run_at
                                ? formatTimestamp(row.last_run_at)
                                : '-'}
                            </td>
                            <td className="py-2 pr-3 text-gray-400 text-xs">
                              {row.next_run_at
                                ? formatTimestamp(row.next_run_at)
                                : row.enabled
                                  ? 'Due now'
                                  : '-'}
                            </td>
                            <td className="py-2 pr-3 font-mono text-emerald-400">
                              {row.pass_count}
                            </td>
                            <td className="py-2 pr-3 font-mono text-red-400">
                              {row.fail_count}
                            </td>
                            <td className="py-2 pr-3 font-mono text-yellow-400">
                              {row.error_count}
                            </td>
                            <td className="py-2 pr-3">
                              <div className="flex items-center gap-3">
                                {canWrite && row.enabled && (
                                  <button
                                    type="button"
                                    onClick={() =>
                                      handleRunNow(row.policy_id, row.policy_slug)
                                    }
                                    disabled={runningId !== null}
                                    className="inline-flex items-center gap-1 text-xs text-blue-400 hover:text-blue-300 disabled:opacity-50 disabled:cursor-not-allowed"
                                    title="Evaluate this policy now instead of waiting for the next sweep"
                                  >
                                    <Play size={12} />
                                    {runningId === row.policy_id
                                      ? 'Running…'
                                      : 'Run now'}
                                  </button>
                                )}
                                <Link
                                  href={`/compliance/policies/${row.policy_id}`}
                                  className="inline-flex items-center gap-1 text-xs text-gray-300 hover:text-gray-100"
                                >
                                  Open <ExternalLink size={12} />
                                </Link>
                              </div>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                )}
              </CardBody>
            </Card>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardBody>
                  <h2 className="text-lg font-semibold text-gray-200 mb-3">
                    By severity
                  </h2>
                  {summary.per_severity.length === 0 ? (
                    <p className="text-gray-500 text-sm">No evaluations yet.</p>
                  ) : (
                    <table className="w-full text-sm">
                      <thead className="text-left text-gray-400 border-b border-gray-800">
                        <tr>
                          <th className="py-2 pr-3">Severity</th>
                          <th className="py-2 pr-3">Pass</th>
                          <th className="py-2 pr-3">Fail</th>
                          <th className="py-2 pr-3">Error</th>
                        </tr>
                      </thead>
                      <tbody>
                        {summary.per_severity.map((row) => (
                          <tr
                            key={row.severity}
                            className="border-b border-gray-900/50"
                          >
                            <td className="py-2 pr-3">
                              <Badge variant={severityBadgeVariant(row.severity)}>
                                {SEVERITY_LABELS[row.severity]}
                              </Badge>
                            </td>
                            <td className="py-2 pr-3 font-mono text-emerald-400">
                              {row.pass_count}
                            </td>
                            <td className="py-2 pr-3 font-mono text-red-400">
                              {row.fail_count}
                            </td>
                            <td className="py-2 pr-3 font-mono text-yellow-400">
                              {row.error_count}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </CardBody>
              </Card>

              <Card>
                <CardBody>
                  <h2 className="text-lg font-semibold text-gray-200 mb-3">
                    By host
                  </h2>
                  {summary.per_host.length === 0 ? (
                    <p className="text-gray-500 text-sm">
                      No evaluations yet.
                    </p>
                  ) : (
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
                        {summary.per_host.map((row) => (
                          <tr
                            key={row.system_id}
                            className="border-b border-gray-900/50"
                          >
                            <td className="py-2 pr-3">
                              <Link
                                href={`/compliance/systems/${row.system_id}`}
                                className="text-blue-400 hover:underline"
                              >
                                {row.hostname ?? `#${row.system_id}`}
                              </Link>
                            </td>
                            <td className="py-2 pr-3 font-mono text-emerald-400">
                              {row.pass_count}
                            </td>
                            <td className="py-2 pr-3 font-mono text-red-400">
                              {row.fail_count}
                            </td>
                            <td className="py-2 pr-3 font-mono text-yellow-400">
                              {row.error_count}
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  )}
                </CardBody>
              </Card>
            </div>
          </>
        )}
      </div>
    </MainLayout>
  );
};

const Stat: React.FC<{ label: string; value: React.ReactNode }> = ({
  label,
  value,
}) => (
  <div className="min-w-[7rem]">
    <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
    <p className="text-2xl font-semibold text-gray-100 mt-0.5">{value}</p>
  </div>
);

export default ComplianceDashboardPage;
