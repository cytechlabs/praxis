import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody, StatCard } from '@/components/ui';
import ExportButton from '@/components/ExportButton';
import HelpLink from '@/components/help/HelpLink';
import { RefreshCw, Package, Shield, Lock, AlertTriangle } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import Head from 'next/head';
import {
  createReportSchedule,
  deleteReportSchedule,
  listReportRuns,
  listReportSchedules,
  REPORT_CADENCE_LABELS,
  REPORT_CADENCE_VALUES,
  REPORT_KIND_LABELS,
  REPORT_KIND_VALUES,
  type ReportCadence,
  type ReportKind,
  type ReportRun,
  type ReportSchedule,
} from '@/services/reportRunService';
import { useAuth } from '@/context/AuthContext';
import { useEntitlements } from '@/context/EntitlementsContext';
import { ENTITLEMENTS } from '@/services/editionService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface Summary {
  total_packages: number;
  total_installed: number;
  security_critical_count: number;
  held_count: number;
  updates_available_count: number;
  systems_with_stale_scans: number;
  packages_per_system_avg: number;
  system_count: number;
}

interface OutdatedItem {
  package_name: string;
  installed_version: string;
  available_version: string;
  system_id: number;
  system_hostname: string;
  is_security_critical: boolean;
}

interface ComplianceItem {
  system_id: number;
  hostname: string;
  total_packages: number;
  up_to_date_count: number;
  outdated_count: number;
  held_count: number;
  compliance_percentage: number;
}

interface ComplianceResponse {
  systems: ComplianceItem[];
  fleet_average_compliance: number;
}

const complianceColor = (pct: number) => {
  if (pct >= 90) return 'bg-green-600';
  if (pct >= 70) return 'bg-yellow-600';
  return 'bg-red-600';
};

const complianceText = (pct: number) => {
  if (pct >= 90) return 'text-green-400';
  if (pct >= 70) return 'text-yellow-400';
  return 'text-red-400';
};

const PackageReports: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const { canWrite } = useAuth();
  // PRA-132: scheduled/recurring report exports are a paid feature. Read access
  // to existing schedules stays free; creating/deleting them is gated here and
  // enforced server-side.
  const { hasEntitlement } = useEntitlements();
  const scheduledExportsEntitled = hasEntitlement(ENTITLEMENTS.REPORTS_SCHEDULED_EXPORTS);
  const canManageSchedules = canWrite && scheduledExportsEntitled;
  const [summary, setSummary] = useState<Summary | null>(null);
  const [outdated, setOutdated] = useState<OutdatedItem[]>([]);
  const [outdatedTotal, setOutdatedTotal] = useState(0);
  const [outdatedPage, setOutdatedPage] = useState(1);
  const [securityOnly, setSecurityOnly] = useState(false);
  const [nameFilter, setNameFilter] = useState('');
  const [compliance, setCompliance] = useState<ComplianceResponse | null>(null);
  const [loading, setLoading] = useState(false);
  const [smartGroups, setSmartGroups] = useState<{ id: number; name: string; member_count: number }[]>([]);
  const [smartGroupId, setSmartGroupId] = useState<number | ''>('');
  // PRA-178 Slice 2: durable report-run history. Slice 1 manual
  // exports persist a row per successful download; this panel lists
  // the most recent rows so an operator can confirm an export
  // actually completed and see who triggered it.
  const [recentReports, setRecentReports] = useState<ReportRun[]>([]);
  const [recentReportsError, setRecentReportsError] = useState<string | null>(null);
  // PRA-178 Slice 5: scheduled report runs. Operators can list
  // existing schedules and create a new one with a plain-language
  // cadence (no cron). Read access is admin / maintainer / auditor;
  // create / disable / delete require canWrite.
  const [schedules, setSchedules] = useState<ReportSchedule[]>([]);
  const [schedulesError, setSchedulesError] = useState<string | null>(null);
  const [showCreateSchedule, setShowCreateSchedule] = useState(false);
  const [scheduleForm, setScheduleForm] = useState<{
    name: string;
    report_kind: ReportKind;
    cadence: ReportCadence;
    filters_json: string;
  }>({
    name: '',
    report_kind: 'patch_executions',
    cadence: 'daily',
    filters_json: '{}',
  });
  const [schedSaving, setSchedSaving] = useState(false);
  const pageSize = 25;

  const scopeParam = smartGroupId ? `smart_group_id=${smartGroupId}` : '';

  // PRA-358: params for the on-demand report exports. These mirror the live
  // filters/scope so the exported report matches what's on screen; the backend
  // records each download as a report_run visible in Recent Reports below.
  const outdatedExportParams = useMemo(() => {
    const p: Record<string, string> = {};
    if (securityOnly) p.security_only = 'true';
    if (nameFilter) p.name_filter = nameFilter;
    if (smartGroupId) p.smart_group_id = String(smartGroupId);
    return p;
  }, [securityOnly, nameFilter, smartGroupId]);

  const complianceExportParams = useMemo(() => {
    const p: Record<string, string> = {};
    if (smartGroupId) p.smart_group_id = String(smartGroupId);
    return p;
  }, [smartGroupId]);

  const loadSummary = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/backend/package-reports/summary${scopeParam ? '?' + scopeParam : ''}`);
      if (!res.ok) throw new Error('Failed to load summary');
      setSummary(await res.json());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load summary');
    }
  }, [scopeParam]);

  const loadOutdated = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', String(outdatedPage));
      params.set('page_size', String(pageSize));
      if (securityOnly) params.set('security_only', 'true');
      if (nameFilter) params.set('name_filter', nameFilter);
      if (smartGroupId) params.set('smart_group_id', String(smartGroupId));
      const res = await apiFetch(`/api/backend/package-reports/outdated?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load outdated packages');
      const data = await res.json();
      setOutdated(data.items);
      setOutdatedTotal(data.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load outdated packages');
    } finally {
      setLoading(false);
    }
  }, [outdatedPage, securityOnly, nameFilter, smartGroupId]);

  const loadCompliance = useCallback(async () => {
    try {
      const res = await apiFetch(`/api/backend/package-reports/compliance${scopeParam ? '?' + scopeParam : ''}`);
      if (!res.ok) throw new Error('Failed to load compliance');
      setCompliance(await res.json());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load compliance');
    }
  }, [scopeParam]);

  const loadRecentReports = useCallback(async () => {
    try {
      const page = await listReportRuns({ limit: 10 });
      setRecentReports(page.items);
      setRecentReportsError(null);
    } catch (err) {
      setRecentReports([]);
      setRecentReportsError(
        err instanceof Error ? err.message : 'Failed to load recent reports',
      );
    }
  }, []);

  const loadSchedules = useCallback(async () => {
    try {
      const page = await listReportSchedules();
      setSchedules(page.items);
      setSchedulesError(null);
    } catch (err) {
      setSchedules([]);
      setSchedulesError(
        err instanceof Error ? err.message : 'Failed to load report schedules',
      );
    }
  }, []);

  const handleCreateSchedule = useCallback(async () => {
    setSchedSaving(true);
    try {
      let filters: Record<string, unknown> = {};
      if (scheduleForm.filters_json.trim()) {
        try {
          filters = JSON.parse(scheduleForm.filters_json);
        } catch {
          toast.error('filters_snapshot must be valid JSON');
          setSchedSaving(false);
          return;
        }
      }
      await createReportSchedule({
        name: scheduleForm.name.trim(),
        report_kind: scheduleForm.report_kind,
        cadence: scheduleForm.cadence,
        filters_snapshot: filters,
      });
      toast.success('Schedule created');
      setShowCreateSchedule(false);
      setScheduleForm({
        name: '',
        report_kind: 'patch_executions',
        cadence: 'daily',
        filters_json: '{}',
      });
      await loadSchedules();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to create schedule');
    } finally {
      setSchedSaving(false);
    }
  }, [scheduleForm, loadSchedules]);

  const handleDeleteSchedule = useCallback(
    async (id: number) => {
      try {
        await deleteReportSchedule(id);
        toast.success('Schedule deleted');
        await loadSchedules();
      } catch (err) {
        toast.error(
          err instanceof Error ? err.message : 'Failed to delete schedule',
        );
      }
    },
    [loadSchedules],
  );

  useEffect(() => {
    (async () => {
      try {
        const res = await apiFetch('/api/backend/smart-groups');
        if (res.ok) {
          const data = await res.json();
          setSmartGroups((data.smart_groups || []).map((g: { id: number; name: string; member_count: number }) => ({ id: g.id, name: g.name, member_count: g.member_count })));
        }
      } catch { /* ignore */ }
    })();
  }, []);

  useEffect(() => { loadSummary(); loadCompliance(); }, [loadSummary, loadCompliance]);
  useEffect(() => { loadOutdated(); }, [loadOutdated]);
  useEffect(() => { loadRecentReports(); }, [loadRecentReports]);
  useEffect(() => { loadSchedules(); }, [loadSchedules]);

  const totalPages = Math.max(1, Math.ceil(outdatedTotal / pageSize));

  return (
    <MainLayout>
        <Head>
          <title>Package Reports | Praxis</title>
        </Head>
        <PageHeader
          title="Package Reports"
          actions={
            <div className="flex items-center gap-2">
              <select
                value={smartGroupId}
                onChange={(e) => { setSmartGroupId(e.target.value ? Number(e.target.value) : ''); setOutdatedPage(1); }}
                className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                title="Scope report to a smart group"
              >
                <option value="">Fleet-wide</option>
                {smartGroups.map(g => (
                  <option key={g.id} value={g.id}>{g.name} ({g.member_count})</option>
                ))}
              </select>
              <Button
                variant="outline"
                size="sm"
                onClick={() => { loadSummary(); loadOutdated(); loadCompliance(); loadRecentReports(); loadSchedules(); }}
                icon={<RefreshCw className="w-4 h-4" />}
              >
                Refresh
              </Button>
              <HelpLink slug="monitoring-and-alerts" />
            </div>
          }
        />

        {/* Summary Cards */}
        {summary && (
          <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
            <StatCard label="Total Packages" value={summary.total_packages} icon={<Package className="w-5 h-5" />} />
            <StatCard label="Security Critical" value={summary.security_critical_count} icon={<Shield className="w-5 h-5" />} />
            <StatCard label="Held" value={summary.held_count} icon={<Lock className="w-5 h-5" />} />
            <StatCard label="Updates Available" value={summary.updates_available_count} icon={<AlertTriangle className="w-5 h-5" />} />
            <StatCard
              label="Avg Compliance"
              value={compliance ? `${compliance.fleet_average_compliance}%` : '-'}
              icon={<Package className="w-5 h-5" />}
            />
          </div>
        )}

        {/* Outdated Packages Table */}
        <Card className="mb-6">
          <CardBody>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-200">Outdated Packages</h2>
              {canWrite && (
                <ExportButton
                  endpoint="/api/backend/package-reports/outdated/export"
                  filename="outdated-packages"
                  params={outdatedExportParams}
                  label="Export report"
                />
              )}
            </div>

            <div className="flex flex-wrap items-end gap-4 mb-4">
              <div>
                <label className="block text-xs text-gray-400 mb-1">Package Name</label>
                <input
                  type="text"
                  value={nameFilter}
                  onChange={(e) => { setNameFilter(e.target.value); setOutdatedPage(1); }}
                  placeholder="Search..."
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                />
              </div>
              <div className="flex items-center gap-2">
                <input
                  type="checkbox"
                  id="securityOnly"
                  checked={securityOnly}
                  onChange={(e) => { setSecurityOnly(e.target.checked); setOutdatedPage(1); }}
                  className="rounded border-gray-800"
                />
                <label htmlFor="securityOnly" className="text-sm text-gray-300">Security only</label>
              </div>
            </div>

            <div className="grid grid-cols-12 gap-2 p-3 bg-gray-950 border-b border-gray-800 font-medium text-gray-200 text-sm rounded-t-lg">
              <div className="col-span-3">Package</div>
              <div className="col-span-2">Installed</div>
              <div className="col-span-2">Available</div>
              <div className="col-span-3">System</div>
              <div className="col-span-2">Security</div>
            </div>

            {loading && <div className="p-4 text-gray-400">Loading...</div>}
            {!loading && outdated.length === 0 && (
              <div className="p-8 text-center text-gray-400">No outdated packages found.</div>
            )}

            {!loading && outdated.map((item, idx) => (
              <div key={idx} className="grid grid-cols-12 gap-2 p-3 border-b border-gray-800 text-gray-300 text-sm items-center">
                <div className="col-span-3 font-medium">{item.package_name}</div>
                <div className="col-span-2 text-red-300">{item.installed_version}</div>
                <div className="col-span-2 text-green-300">{item.available_version}</div>
                <div className="col-span-3 truncate">{item.system_hostname}</div>
                <div className="col-span-2">
                  {item.is_security_critical && (
                    <span className="inline-block px-2 py-0.5 rounded text-xs border bg-red-900/50 text-red-300 border-red-700">Critical</span>
                  )}
                </div>
              </div>
            ))}

            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-gray-400">
                {outdatedTotal > 0
                  ? `Showing ${(outdatedPage - 1) * pageSize + 1}-${Math.min(outdatedPage * pageSize, outdatedTotal)} of ${outdatedTotal}`
                  : 'No results'}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={outdatedPage <= 1}
                  onClick={() => setOutdatedPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <span className="text-sm text-gray-400 self-center">Page {outdatedPage} of {totalPages}</span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={outdatedPage >= totalPages}
                  onClick={() => setOutdatedPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          </CardBody>
        </Card>

        {/* Compliance Section */}
        <Card>
          <CardBody>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg font-semibold text-gray-200">
                Update Compliance
                {compliance && (
                  <span className="ml-3 text-sm font-normal text-gray-400">
                    Fleet Average: <span className={complianceText(compliance.fleet_average_compliance)}>{compliance.fleet_average_compliance}%</span>
                  </span>
                )}
              </h2>
              {canWrite && (
                <ExportButton
                  endpoint="/api/backend/package-reports/compliance/export"
                  filename="update-compliance"
                  params={complianceExportParams}
                  label="Export report"
                />
              )}
            </div>

            {compliance && compliance.systems.length === 0 && (
              <div className="p-8 text-center text-gray-400">No systems found.</div>
            )}

            {compliance && compliance.systems.map((sys) => (
              <div key={sys.system_id} className="flex items-center gap-4 py-2 border-b border-gray-800/50">
                <div className="w-48 text-sm text-gray-300 truncate">{sys.hostname}</div>
                <div className="flex-1">
                  <div className="w-full bg-gray-800 rounded-full h-4 overflow-hidden">
                    <div
                      className={`h-full rounded-full ${complianceColor(sys.compliance_percentage)}`}
                      style={{ width: `${sys.compliance_percentage}%` }}
                    />
                  </div>
                </div>
                <div className={`w-16 text-right text-sm font-medium ${complianceText(sys.compliance_percentage)}`}>
                  {sys.compliance_percentage}%
                </div>
                <div className="w-40 text-xs text-gray-400">
                  {sys.up_to_date_count} ok / {sys.outdated_count} outdated / {sys.held_count} held
                </div>
              </div>
            ))}
          </CardBody>
        </Card>

        {/* PRA-178 Slice 2 + PRA-358: Recent Reports - durable history of
            every report run. Read-only here; exports trigger from this page
            (package outdated/compliance) and the patch/compliance pages. */}
        <Card className="mt-6">
          <CardBody>
            <h2 className="text-lg font-semibold text-gray-200 mb-4">
              Recent Reports
              <span className="ml-3 text-xs font-normal text-gray-500">
                Last 10 report runs across package, patch + compliance
              </span>
            </h2>
            {recentReportsError && (
              <div
                className="p-3 mb-3 text-xs text-red-300 bg-red-900/30 border border-red-700/40 rounded"
                data-testid="recent-reports-error"
              >
                {recentReportsError}
              </div>
            )}
            {!recentReportsError && recentReports.length === 0 && (
              <div
                className="p-6 text-center text-gray-400 text-sm"
                data-testid="recent-reports-empty"
              >
                No report runs yet. Export the Outdated Packages or Update
                Compliance report above - or an export on a patch/compliance
                page - to record one.
              </div>
            )}
            {recentReports.length > 0 && (
              <div className="overflow-x-auto" data-testid="recent-reports-table">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
                      <th className="text-left p-2">Kind</th>
                      <th className="text-left p-2">Format</th>
                      <th className="text-left p-2">State</th>
                      <th className="text-right p-2">Rows</th>
                      <th className="text-left p-2">Triggered by</th>
                      <th className="text-left p-2">Triggered</th>
                      <th className="text-left p-2">Completed</th>
                    </tr>
                  </thead>
                  <tbody>
                    {recentReports.map((r) => (
                      <tr
                        key={r.id}
                        className="border-b border-gray-800/50 text-gray-300"
                      >
                        <td className="p-2">{REPORT_KIND_LABELS[r.report_kind] ?? r.report_kind}</td>
                        <td className="p-2 uppercase text-xs text-gray-400">
                          {r.format ?? '-'}
                        </td>
                        <td className="p-2">
                          <span
                            className={
                              r.state === 'succeeded'
                                ? 'text-emerald-400'
                                : r.state === 'failed'
                                  ? 'text-red-400'
                                  : 'text-yellow-400'
                            }
                          >
                            {r.state}
                          </span>
                        </td>
                        <td className="p-2 text-right font-mono">
                          {r.row_count ?? '-'}
                        </td>
                        <td className="p-2 text-xs">
                          {r.triggered_by_username ?? r.triggered_by}
                        </td>
                        <td className="p-2 text-xs text-gray-400">
                          {formatTimestamp(r.started_at)}
                        </td>
                        <td className="p-2 text-xs text-gray-400">
                          {r.completed_at ? formatTimestamp(r.completed_at) : '-'}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>

        {/* PRA-178 Slice 5: Scheduled Reports - operators can list
            existing schedules and create new ones with a plain-language
            cadence (no cron). The scheduler tick fires due schedules
            every 5 minutes; each successful firing leaves a
            `triggered_by='system_scheduled'` row in the Recent
            Reports panel above. */}
        <Card className="mt-6">
          <CardBody>
            <h2 className="text-lg font-semibold text-gray-200 mb-4">
              Scheduled Reports
              <span className="ml-3 text-xs font-normal text-gray-500">
                Recurring exports fired by the in-process scheduler
              </span>
            </h2>
            {schedulesError && (
              <div
                className="p-3 mb-3 text-xs text-red-300 bg-red-900/30 border border-red-700/40 rounded"
                data-testid="report-schedules-error"
              >
                {schedulesError}
              </div>
            )}
            <div className="flex items-center justify-between mb-3">
              <div className="text-xs text-gray-400">
                {schedules.length} active schedule{schedules.length === 1 ? '' : 's'}
              </div>
              {!scheduledExportsEntitled ? (
                <span
                  className="inline-flex items-center gap-1 text-[11px] text-gray-500"
                  title="Scheduled report exports are part of the paid Praxis edition."
                  data-testid="report-schedules-paid-locked"
                >
                  <Lock size={11} /> Scheduled exports (Pro)
                </span>
              ) : canWrite ? (
                <button
                  onClick={() => setShowCreateSchedule((v) => !v)}
                  className="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded"
                  data-testid="report-schedules-new"
                >
                  {showCreateSchedule ? 'Hide' : 'New schedule'}
                </button>
              ) : (
                <span
                  className="text-[11px] text-gray-500"
                  title="Creating a scheduled report requires the admin or maintainer role."
                  data-testid="report-schedules-rbac-required"
                >
                  Create requires admin or maintainer
                </span>
              )}
            </div>
            {showCreateSchedule && canManageSchedules && (
              <div className="bg-gray-900/60 border border-gray-800 rounded p-3 mb-4 space-y-2 text-xs">
                <div className="grid grid-cols-1 sm:grid-cols-4 gap-2">
                  <label className="block">
                    <span className="text-gray-400">Name</span>
                    <input
                      type="text"
                      value={scheduleForm.name}
                      onChange={(e) => setScheduleForm((f) => ({ ...f, name: e.target.value }))}
                      className="mt-1 block w-full rounded border border-gray-800 bg-gray-950 p-1.5"
                      data-testid="report-schedule-name"
                    />
                  </label>
                  <label className="block">
                    <span className="text-gray-400">Report kind</span>
                    <select
                      value={scheduleForm.report_kind}
                      onChange={(e) => setScheduleForm((f) => ({ ...f, report_kind: e.target.value as ReportKind }))}
                      className="mt-1 block w-full rounded border border-gray-800 bg-gray-950 p-1.5"
                    >
                      {REPORT_KIND_VALUES.map((k) => (
                        <option key={k} value={k}>
                          {REPORT_KIND_LABELS[k]}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="block">
                    <span className="text-gray-400">Cadence</span>
                    <select
                      value={scheduleForm.cadence}
                      onChange={(e) => setScheduleForm((f) => ({ ...f, cadence: e.target.value as ReportCadence }))}
                      className="mt-1 block w-full rounded border border-gray-800 bg-gray-950 p-1.5"
                    >
                      {REPORT_CADENCE_VALUES.map((c) => (
                        <option key={c} value={c}>
                          {REPORT_CADENCE_LABELS[c]}
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="block">
                    <span className="text-gray-400">Filters (JSON)</span>
                    <input
                      type="text"
                      value={scheduleForm.filters_json}
                      onChange={(e) => setScheduleForm((f) => ({ ...f, filters_json: e.target.value }))}
                      className="mt-1 block w-full rounded border border-gray-800 bg-gray-950 p-1.5 font-mono"
                      placeholder='{"plan_id": 1}'
                    />
                  </label>
                </div>
                <div className="flex justify-end">
                  <button
                    onClick={handleCreateSchedule}
                    disabled={schedSaving || !scheduleForm.name.trim()}
                    className="text-xs px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded disabled:opacity-40"
                  >
                    {schedSaving ? 'Saving…' : 'Create schedule'}
                  </button>
                </div>
              </div>
            )}
            {!schedulesError && schedules.length === 0 ? (
              <div
                className="p-6 text-center text-gray-400 text-sm"
                data-testid="report-schedules-empty"
              >
                No scheduled reports yet. Create one above to start a recurring
                CSV/JSON export.
              </div>
            ) : (
              <div className="overflow-x-auto" data-testid="report-schedules-table">
                <table className="w-full text-sm">
                  <thead>
                    <tr className="border-b border-gray-800 text-gray-400 text-xs uppercase">
                      <th className="text-left p-2">Name</th>
                      <th className="text-left p-2">Kind</th>
                      <th className="text-left p-2">Cadence</th>
                      <th className="text-left p-2">Enabled</th>
                      <th className="text-left p-2">Next run</th>
                      <th className="text-left p-2">Last run</th>
                      <th className="text-right p-2">Actions</th>
                    </tr>
                  </thead>
                  <tbody>
                    {schedules.map((s) => (
                      <tr key={s.id} className="border-b border-gray-800/50 text-gray-300">
                        <td className="p-2">{s.name}</td>
                        <td className="p-2">{REPORT_KIND_LABELS[s.report_kind] ?? s.report_kind}</td>
                        <td className="p-2">{REPORT_CADENCE_LABELS[s.cadence] ?? s.cadence}</td>
                        <td className="p-2">{s.enabled ? 'yes' : 'no'}</td>
                        <td className="p-2 text-xs text-gray-400">
                          {s.next_run_at ? formatTimestamp(s.next_run_at) : '-'}
                        </td>
                        <td className="p-2 text-xs text-gray-400">
                          {s.last_run_at ? `${s.last_run_state} ${formatTimestamp(s.last_run_at)}` : '-'}
                        </td>
                        <td className="p-2 text-right">
                          {canManageSchedules ? (
                            <button
                              onClick={() => handleDeleteSchedule(s.id)}
                              className="text-xs px-2 py-1 bg-gray-800 hover:bg-red-900 text-gray-200 rounded"
                            >
                              Delete
                            </button>
                          ) : (
                            <span className="text-[11px] text-gray-500">-</span>
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
    </MainLayout>
  );
};

export default PackageReports;
