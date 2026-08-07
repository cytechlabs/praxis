/**
 * PRA-177 Slice 1: read-only fleet remediation dashboard.
 *
 * Backed by ``GET /compliance/remediation/fleet-summary``. Mirrors
 * the PRA-167 / PRA-176 substrate without exposing any mutation
 * controls - request open/approve/reject, plan build/acknowledge,
 * and execution dispatch are intentionally absent in this slice.
 *
 * The page is dense and operator-facing: rollup counts, per-state
 * breakdown for requests and current plans, readiness + staleness
 * breakdowns, and a per-severity tally. Drilldown links land on the
 * request, plan, and per-host inventory readback surfaces.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { ArrowLeft, ExternalLink, RefreshCw, Lock } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import ExportButton from '@/components/ExportButton';
import { useAuth } from '@/context/AuthContext';
import { useEntitlements } from '@/context/EntitlementsContext';
import { ENTITLEMENTS } from '@/services/editionService';
import {
  Badge,
  Button,
  Card,
  CardBody,
  EmptyState,
  ErrorState,
  PageHeader,
  SkeletonTable,
} from '@/components/ui';
import {
  ComplianceApiError,
  RemediationFleetSummary,
  RemediationRequestPage,
  REMEDIATION_REQUEST_STATES,
  getRemediationFleetSummary,
  listRemediationRequests,
  remediationRequestStateBadgeVariant,
  SEVERITY_LABELS,
  severityBadgeVariant,
} from '@/services/complianceService';
import { fetchAllSystems } from '@/services/systemService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const REQUEST_PAGE_SIZE = 25;

const ComplianceRemediationDashboardPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const { canWrite } = useAuth();
  // PRA-132: bulk compliance/remediation exports hit the paid-gated
  // /compliance/exports router. Show a paid lock instead of a control that 402s.
  const { hasEntitlement } = useEntitlements();
  const bulkExportsEntitled = hasEntitlement(ENTITLEMENTS.COMPLIANCE_BULK_EXPORTS);
  const [summary, setSummary] = useState<RemediationFleetSummary | null>(null);
  const [recent, setRecent] = useState<RemediationRequestPage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // system_id -> hostname for display (request rows carry only system_id).
  const [hostNames, setHostNames] = useState<Record<number, string>>({});

  useEffect(() => {
    fetchAllSystems()
      .then((rows) =>
        setHostNames(Object.fromEntries(rows.map((s) => [s.id, s.hostname]))),
      )
      .catch(() => setHostNames({}));
  }, []);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const [s, r] = await Promise.all([
        getRemediationFleetSummary(),
        listRemediationRequests({ limit: REQUEST_PAGE_SIZE }),
      ]);
      setSummary(s);
      setRecent(r);
      setError(null);
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      setError(msg);
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  return (
    <MainLayout>
      <Head>
        <title>Fleet Remediation · Praxis</title>
      </Head>

      <div className="p-6 space-y-6">
        <PageHeader
          title="Fleet Remediation"
          subtitle="Rollup of compliance remediation requests, plan previews, and execution attempts. Open / approve / reject / cancel a request, build and acknowledge plans, and dispatch execution attempts from the request and execution attempt detail pages."
          actions={
            <div className="flex items-center gap-2">
              <Link
                href="/compliance"
                className="inline-flex items-center gap-1.5 text-sm text-gray-300 hover:text-gray-100"
              >
                <ArrowLeft size={14} /> Compliance dashboard
              </Link>
              {/*
                PRA-178 Slice 1: bounded review-period export of
                compliance remediation requests. Defaults to the last
                30 days; the backend rejects windows > 366 days and
                filter sets that would produce more than 50,000 rows
                with HTTP 422. Admin/maintainer only - gated via the
                same canWrite helper that other write-action
                affordances use so auditor/read-only users never see
                a button that would 403 on click (PRA-178 Slice 1a
                fix to the P1 review finding).
              */}
              {!bulkExportsEntitled ? (
                <span
                  className="inline-flex items-center gap-1 text-[11px] text-gray-500"
                  title="Bulk evidence/remediation exports are part of the paid Praxis edition."
                  data-testid="remediation-exports-paid-locked"
                >
                  <Lock size={11} /> Bulk export (Pro)
                </span>
              ) : canWrite ? (
                <>
                  <ExportButton
                    endpoint="/api/backend/compliance/exports/remediation-requests"
                    filename="remediation-requests-export"
                    label="Export requests"
                  />
                  {/* PRA-178 Slice 4: remediation plans + execution
                      attempts exports. Same RBAC + canWrite gating
                      as the Slice 1 remediation-requests export. */}
                  <ExportButton
                    endpoint="/api/backend/compliance/exports/remediation-plans"
                    filename="remediation-plans-export"
                    label="Export plans"
                  />
                  <ExportButton
                    endpoint="/api/backend/compliance/exports/remediation-executions"
                    filename="remediation-executions-export"
                    label="Export executions"
                  />
                </>
              ) : (
                <span
                  className="text-[11px] text-gray-500"
                  title="Bulk export requires the admin or maintainer role."
                  data-testid="remediation-requests-export-rbac-required"
                >
                  Export requires admin or maintainer
                </span>
              )}
              <Button variant="outline" onClick={refresh}>
                <RefreshCw size={14} /> Refresh
              </Button>
            </div>
          }
        />

        <Card>
          <CardBody>
            <p className="text-xs text-gray-400 leading-relaxed">
              This dashboard rolls up compliance remediation requests, plan
              previews, and execution attempts recorded by the API. Open a
              remediation request from a failing evidence row; approve /
              reject / cancel from the request detail page. Plan build, plan
              acknowledge, and dispatch are available from the request and
              execution attempt detail pages. Dispatch is the only control that
              can reach a host, and it stays behind the backend readiness gate.
            </p>
          </CardBody>
        </Card>

        {error && (
          <ErrorState title="Couldn’t load remediation" onRetry={refresh} />
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
                  <Stat label="Requests" value={summary.request_total} />
                  <Stat
                    label="Current plans"
                    value={summary.current_plan_total}
                  />
                  <Stat
                    label="Ready / not ready"
                    value={
                      <span className="font-mono">
                        <span className="text-emerald-400">
                          {summary.current_plan_ready_count}
                        </span>
                        <span className="text-gray-500"> / </span>
                        <span className="text-yellow-400">
                          {summary.current_plan_not_ready_count}
                        </span>
                      </span>
                    }
                  />
                  <Stat
                    label="Acknowledged"
                    value={
                      <span className="font-mono">
                        <span className="text-emerald-400">
                          {summary.current_plan_acknowledged_count}
                        </span>
                        <span className="text-gray-500"> / </span>
                        <span className="text-yellow-400">
                          {summary.current_plan_unacknowledged_count}
                        </span>
                      </span>
                    }
                  />
                  <Stat
                    label="Stale plans"
                    value={
                      <span className="font-mono text-orange-400">
                        {summary.current_plan_stale_count}
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

            <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
              <Card>
                <CardBody>
                  <h2 className="text-lg font-semibold text-gray-200 mb-3">
                    Requests by state
                  </h2>
                  {summary.request_total === 0 ? (
                    <p className="text-gray-500 text-sm">
                      No remediation requests have been opened yet.
                    </p>
                  ) : (
                    <table className="w-full text-sm">
                      <thead className="text-left text-gray-400 border-b border-gray-800">
                        <tr>
                          <th className="py-2 pr-3">State</th>
                          <th className="py-2 pr-3">Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {REMEDIATION_REQUEST_STATES.map((state) => (
                          <tr
                            key={state}
                            className="border-b border-gray-900/50"
                          >
                            <td className="py-2 pr-3">
                              <Badge
                                variant={remediationRequestStateBadgeVariant(state)}
                              >
                                {state}
                              </Badge>
                            </td>
                            <td className="py-2 pr-3 font-mono text-gray-200">
                              {summary.request_counts_by_state[state] ?? 0}
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
                    Current plans by state
                  </h2>
                  {summary.current_plan_total === 0 ? (
                    <p className="text-gray-500 text-sm">
                      No remediation plan previews have been built yet.
                    </p>
                  ) : (
                    <table className="w-full text-sm">
                      <thead className="text-left text-gray-400 border-b border-gray-800">
                        <tr>
                          <th className="py-2 pr-3">State</th>
                          <th className="py-2 pr-3">Count</th>
                        </tr>
                      </thead>
                      <tbody>
                        {Object.entries(summary.current_plan_counts_by_state).map(
                          ([state, count]) => (
                            <tr
                              key={state}
                              className="border-b border-gray-900/50"
                            >
                              <td className="py-2 pr-3">
                                <Badge
                                  variant={
                                    state === 'planned'
                                      ? 'success'
                                      : state === 'unsupported'
                                        ? 'warning'
                                        : state === 'failed'
                                          ? 'danger'
                                          : 'neutral'
                                  }
                                >
                                  {state}
                                </Badge>
                              </td>
                              <td className="py-2 pr-3 font-mono text-gray-200">
                                {count}
                              </td>
                            </tr>
                          ),
                        )}
                      </tbody>
                    </table>
                  )}
                </CardBody>
              </Card>
            </div>

            <Card>
              <CardBody>
                <h2 className="text-lg font-semibold text-gray-200 mb-3">
                  By severity
                </h2>
                {summary.per_severity.length === 0 ? (
                  <p className="text-gray-500 text-sm">
                    No remediation requests recorded yet.
                  </p>
                ) : (
                  <table className="w-full text-sm">
                    <thead className="text-left text-gray-400 border-b border-gray-800">
                      <tr>
                        <th className="py-2 pr-3">Severity</th>
                        <th className="py-2 pr-3">Requested</th>
                        <th className="py-2 pr-3">Approved</th>
                        <th className="py-2 pr-3">Rejected</th>
                        <th className="py-2 pr-3">Cancelled</th>
                        <th className="py-2 pr-3">Total</th>
                      </tr>
                    </thead>
                    <tbody>
                      {summary.per_severity.map((row) => (
                        <tr
                          key={row.severity}
                          className="border-b border-gray-900/50"
                        >
                          <td className="py-2 pr-3">
                            <Badge
                              variant={severityBadgeVariant(
                                row.severity as keyof typeof SEVERITY_LABELS,
                              )}
                            >
                              {SEVERITY_LABELS[
                                row.severity as keyof typeof SEVERITY_LABELS
                              ] ?? row.severity}
                            </Badge>
                          </td>
                          <td className="py-2 pr-3 font-mono text-yellow-400">
                            {row.requested}
                          </td>
                          <td className="py-2 pr-3 font-mono text-emerald-400">
                            {row.approved}
                          </td>
                          <td className="py-2 pr-3 font-mono text-red-400">
                            {row.rejected}
                          </td>
                          <td className="py-2 pr-3 font-mono text-gray-400">
                            {row.cancelled}
                          </td>
                          <td className="py-2 pr-3 font-mono text-gray-200">
                            {row.total}
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
                <div className="flex items-center justify-between mb-3">
                  <h2 className="text-lg font-semibold text-gray-200">
                    Recent remediation requests
                  </h2>
                  <span className="text-xs text-gray-400">
                    {recent?.total ?? 0} total
                  </span>
                </div>
                {recent && recent.items.length === 0 ? (
                  <EmptyState
                    title="No remediation requests yet"
                    description="Open a request from a failing evidence row. Approved requests appear here with their plan previews and execution attempts."
                  />
                ) : recent ? (
                  <div className="overflow-x-auto">
                    <table className="w-full text-sm">
                      <thead className="text-left text-gray-400 border-b border-gray-800">
                        <tr>
                          <th className="py-2 pr-3">Request</th>
                          <th className="py-2 pr-3">State</th>
                          <th className="py-2 pr-3">Policy</th>
                          <th className="py-2 pr-3">Check</th>
                          <th className="py-2 pr-3">System</th>
                          <th className="py-2 pr-3">Severity</th>
                          <th className="py-2 pr-3">Created</th>
                          <th className="py-2 pr-3"></th>
                        </tr>
                      </thead>
                      <tbody>
                        {recent.items.map((r) => (
                          <tr
                            key={r.id}
                            className="border-b border-gray-900/50 hover:bg-gray-900/30"
                          >
                            <td className="py-2 pr-3 font-mono">#{r.id}</td>
                            <td className="py-2 pr-3">
                              <Badge
                                variant={remediationRequestStateBadgeVariant(
                                  r.state,
                                )}
                              >
                                {humanizeStatus(r.state)}
                              </Badge>
                            </td>
                            <td className="py-2 pr-3 font-mono text-xs">
                              <Link
                                href={`/compliance/policies/${r.policy_id}`}
                                className="text-blue-400 hover:underline"
                              >
                                {r.policy_slug}
                              </Link>
                            </td>
                            <td className="py-2 pr-3 font-mono text-xs text-gray-300">
                              {r.check_slug}
                            </td>
                            <td className="py-2 pr-3">
                              <Link
                                href={`/compliance/systems/${r.system_id}/remediation`}
                                className="text-blue-400 hover:underline"
                              >
                                {hostNames[r.system_id] ?? `#${r.system_id}`}
                              </Link>
                            </td>
                            <td className="py-2 pr-3">
                              <Badge
                                variant={severityBadgeVariant(r.severity_snapshot)}
                              >
                                {SEVERITY_LABELS[r.severity_snapshot]}
                              </Badge>
                            </td>
                            <td className="py-2 pr-3 text-xs text-gray-300">
                              {formatTimestamp(r.created_at)}
                            </td>
                            <td className="py-2 pr-3 text-right">
                              <Link
                                href={`/compliance/remediation/requests/${r.id}`}
                                className="inline-flex items-center gap-1 text-xs text-gray-300 hover:text-gray-100"
                              >
                                Open <ExternalLink size={12} />
                              </Link>
                            </td>
                          </tr>
                        ))}
                      </tbody>
                    </table>
                  </div>
                ) : null}
              </CardBody>
            </Card>
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
  <div className="min-w-[8rem]">
    <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
    <p className="text-2xl font-semibold text-gray-100 mt-0.5">{value}</p>
  </div>
);

export default ComplianceRemediationDashboardPage;
