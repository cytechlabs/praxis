import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Badge, StatCard, Card, CardHeader, CardBody, SkeletonCards, EmptyState, ConfirmModal, statusToBadgeVariant } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import HealthBanner from '@/components/dashboard/HealthBanner';
import Link from 'next/link';
import { RefreshCw, Activity, AlertTriangle, CheckCircle2, Clock, Server, Package as PackageIcon, PlayCircle, ClipboardCheck, ShieldAlert, ShieldCheck } from 'lucide-react';
import {
  fetchFleetDashboard,
  checkAllSystems,
  FleetDashboard,
  groupAttentionByHost,
} from '@/services/fleetHealthService';
import {
  ADVISORY_SEVERITY_VALUES,
  type AdvisorySeverity,
  type FleetAdvisoryCounts,
  getFleetAdvisoryCounts,
  SEVERITY_LABELS,
} from '@/services/patchAdvisoryService';
import { apiFetch } from '@/utils/api';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const statusBarColors: Record<string, string> = {
  Active: 'bg-emerald-500',
  Inactive: 'bg-gray-600',
  Maintenance: 'bg-yellow-500',
  Decommissioned: 'bg-gray-700',
  Unreachable: 'bg-red-500',
};

const FleetDashboardPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const [data, setData] = useState<FleetDashboard | null>(null);
  const [loading, setLoading] = useState(false);
  const [checking, setChecking] = useState(false);
  const [showCheckConfirm, setShowCheckConfirm] = useState(false);
  const [drift, setDrift] = useState<{ drifted_systems: number; baselines: number } | null>(null);
  // PRA-156 #3d: lifecycle bucket counts. Underscore key from the
  // server response (Python idiom); the canonical hyphenated value
  // ``approaching-eol`` is used for the URL filter param.
  const [lifecycle, setLifecycle] = useState<{
    counts: { supported: number; approaching_eol: number; unsupported: number; unknown: number };
    // PRA-240: WHY hosts are unknown, so an all-unknown tile is actionable.
    unknown_reasons?: { freshness: number; missing_distro_facts: number; no_lifecycle_row: number; other: number };
    total: number;
    staleness_threshold_seconds?: number;
  } | null>(null);
  // PRA-163 #4: fleet-wide applicable advisory counts by severity.
  // Failure leaves the tile unrendered rather than blocking the
  // dashboard - same defensive pattern as the lifecycle and drift
  // widgets above.
  const [advisoryCounts, setAdvisoryCounts] = useState<FleetAdvisoryCounts | null>(null);

  const loadDashboard = useCallback(async () => {
    setLoading(true);
    try {
      const result = await fetchFleetDashboard();
      setData(result);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load dashboard');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => {
    loadDashboard();
    const interval = setInterval(loadDashboard, 30000);
    return () => clearInterval(interval);
  }, [loadDashboard]);

  useEffect(() => {
    const loadDrift = async () => {
      try {
        const res = await apiFetch('/api/backend/baselines/-/drift/summary');
        if (res.ok) setDrift(await res.json());
      } catch { /* ignore */ }
    };
    loadDrift();
    const t = setInterval(loadDrift, 30000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    // PRA-156 #3d: lifecycle bucket counts. Failure leaves the card
    // unrendered rather than blocking the dashboard - same defensive
    // pattern as the drift summary above.
    const loadLifecycle = async () => {
      try {
        const res = await apiFetch('/api/backend/lifecycle/summary');
        if (res.ok) setLifecycle(await res.json());
      } catch { /* ignore */ }
    };
    loadLifecycle();
    const t = setInterval(loadLifecycle, 30000);
    return () => clearInterval(t);
  }, []);

  useEffect(() => {
    // PRA-163 #4: fleet advisory severity counts.
    const loadAdvisoryCounts = async () => {
      try {
        const counts = await getFleetAdvisoryCounts();
        setAdvisoryCounts(counts);
      } catch { /* ignore */ }
    };
    loadAdvisoryCounts();
    const t = setInterval(loadAdvisoryCounts, 30000);
    return () => clearInterval(t);
  }, []);

  const handleCheckAll = async () => {
    setShowCheckConfirm(false);
    setChecking(true);
    try {
      const result = await checkAllSystems();
      if (result.status === 'already_running') {
        // PRA-323: a fleet sweep is already in progress (single-flight).
        toast.info(result.message || 'A fleet health check is already running');
      } else {
        toast.success(`Checked ${result.total} systems: ${result.ok} ok, ${result.failed} failed`);
        loadDashboard();
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Health check failed');
    } finally {
      setChecking(false);
    }
  };

  if (!data && loading) {
    return (
      <MainLayout>
        <Head><title>Fleet Dashboard | Praxis</title></Head>
        <PageHeader title="Fleet Operations Dashboard" subtitle="Loading..." actions={<HelpLink slug="getting-started" />} />
        <SkeletonCards count={4} />
      </MainLayout>
    );
  }

  if (!data) {
    return (
      <MainLayout>
        <EmptyState title="Failed to load dashboard" description="Could not connect to the fleet health API." />
      </MainLayout>
    );
  }

  const totalSystems = Object.values(data.status_counts).reduce((a, b) => a + b, 0);
  const upToDatePct = data.patch_compliance.total > 0
    ? Math.round((data.patch_compliance.up_to_date / data.patch_compliance.total) * 100)
    : 0;

  return (
    <MainLayout>
      <Head><title>Fleet Dashboard | Praxis</title></Head>

      <PageHeader
        title="Fleet Operations Dashboard"
        subtitle={`Last updated: ${formatTimestamp(data.generated_at, { timeOnly: true })} (auto-refresh every 30s)`}
        actions={
          <>
            <Button
              variant="outline"
              icon={<Activity className={`w-4 h-4 ${checking ? 'animate-pulse' : ''}`} />}
              onClick={() => setShowCheckConfirm(true)}
              loading={checking}
            >
              Check All Systems
            </Button>
            <Button
              variant="ghost"
              icon={<RefreshCw className={`w-4 h-4 ${loading ? 'animate-spin' : ''}`} />}
              onClick={loadDashboard}
              disabled={loading}
            >
              Refresh
            </Button>
            <HelpLink slug="getting-started" />
          </>
        }
      />

      {/* Hero attention banner */}
      <HealthBanner
        unreachable={data.health.unreachable}
        securityUpdates={data.patch_compliance.pending_security_updates}
        systemsWithSecurityUpdates={data.patch_compliance.with_security_updates}
        pendingUpdates={data.patch_compliance.pending_package_updates}
        systemsWithUpdates={data.patch_compliance.with_updates}
        totalSystems={totalSystems}
      />

      {/* Stat cards - every card is a link to its filtered view */}
      <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-5 gap-4 mb-6">
        <StatCard
          label="Total Systems"
          value={totalSystems}
          icon={<Server className="w-3.5 h-3.5" />}
          href="/system-management/all-systems"
        />
        <StatCard
          label="Patch Compliance"
          value={`${upToDatePct}%`}
          icon={<CheckCircle2 className="w-3.5 h-3.5" />}
          subtitle={`${data.patch_compliance.up_to_date} of ${data.patch_compliance.total} up to date`}
          href="/package-management/available-updates"
        />
        <StatCard
          label="Unreachable"
          value={data.health.unreachable}
          icon={<AlertTriangle className="w-3.5 h-3.5" />}
          subtitle="Need attention"
          href="/system-management/all-systems?status=Unreachable"
        />
        <StatCard
          label="Active Jobs"
          value={data.active_jobs.length}
          icon={<PlayCircle className="w-3.5 h-3.5" />}
          subtitle="Currently running"
          href="/job-scheduling/active-jobs"
        />
        <StatCard
          label="Drifted Systems"
          value={drift?.drifted_systems ?? 0}
          icon={<ClipboardCheck className="w-3.5 h-3.5" />}
          subtitle={drift ? `Across ${drift.baselines} baseline${drift.baselines === 1 ? '' : 's'}` : 'Loading…'}
          href="/monitoring-reporting/drift"
        />
      </div>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        {/* Systems by Status */}
        <Card>
          <CardHeader>Systems by Status</CardHeader>
          <CardBody>
            <div className="space-y-3">
              {Object.entries(data.status_counts).map(([status, count]) => {
                const pct = totalSystems > 0 ? (count / totalSystems) * 100 : 0;
                return (
                  <div key={status}>
                    <div className="flex items-center justify-between text-sm mb-1.5">
                      <Badge variant={statusToBadgeVariant(status)}>{status}</Badge>
                      <span className="text-content-subtle text-xs tabular-nums">{count} ({Math.round(pct)}%)</span>
                    </div>
                    <div className="w-full h-1.5 bg-surface-overlay rounded-full overflow-hidden">
                      <div
                        className={`h-1.5 rounded-full transition-all duration-500 ${statusBarColors[status] || 'bg-gray-600'}`}
                        style={{ width: `${pct}%` }}
                      />
                    </div>
                  </div>
                );
              })}
            </div>
          </CardBody>
        </Card>

        {/* Patch Compliance */}
        <Card>
          <CardHeader>
            <span className="flex items-center gap-2"><PackageIcon className="w-4 h-4 text-content-subtle" /> Patch Compliance</span>
          </CardHeader>
          <CardBody>
            <div className="grid grid-cols-3 gap-4 mb-4">
              <div className="text-center">
                <div className="text-2xl font-bold text-emerald-400 tabular-nums">{data.patch_compliance.up_to_date}</div>
                <div className="text-xs text-content-subtle mt-1">Systems Up to Date</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-orange-400 tabular-nums">{data.patch_compliance.with_updates}</div>
                <div className="text-xs text-content-subtle mt-1">Systems with Updates</div>
              </div>
              <div className="text-center">
                <div className="text-2xl font-bold text-red-400 tabular-nums">{data.patch_compliance.with_security_updates}</div>
                <div className="text-xs text-content-subtle mt-1">Systems with Security Updates</div>
              </div>
            </div>
            <div className="w-full h-2 bg-surface-overlay rounded-full overflow-hidden flex">
              <div className="h-2 bg-emerald-500 transition-all duration-500" style={{ width: `${upToDatePct}%` }} />
              <div className="h-2 bg-orange-500 transition-all duration-500" style={{ width: `${100 - upToDatePct}%` }} />
            </div>
          </CardBody>
        </Card>
      </div>

      {/* PRA-163 #4: fleet advisory severity tile. Counts of
          state='applicable' advisory rows by severity, joining
          patch_advisory_host_applicability with patch_advisories.
          Each tile links into the advisory list page filtered to
          that severity. Hidden when the counts endpoint fails or
          returns null so a backend issue doesn't dominate the
          dashboard - same defensive pattern as the lifecycle tile
          below. */}
      {advisoryCounts && advisoryCounts.total > 0 && (
        <Card className="mb-4">
          <CardHeader>
            <span className="flex items-center gap-2">
              <ShieldCheck className="w-4 h-4 text-content-subtle" /> Open Patch Advisories
              <span className="ml-2 text-xs font-normal text-content-subtle">
                {advisoryCounts.total} applicable rows across the fleet
              </span>
            </span>
          </CardHeader>
          <CardBody>
            <div className="grid grid-cols-2 md:grid-cols-6 gap-3">
              {ADVISORY_SEVERITY_VALUES.map((s) => (
                <AdvisorySeverityTile
                  key={s}
                  label={SEVERITY_LABELS[s]}
                  count={advisoryCounts.severity[s] ?? 0}
                  total={advisoryCounts.total}
                  severity={s}
                  accent={SEVERITY_ACCENTS[s]}
                />
              ))}
            </div>
          </CardBody>
        </Card>
      )}

      {/* PRA-156 #3d: Lifecycle bucket widget - links to the
          all-systems lifecycle filter (server-side via
          /lifecycle/systems). Hidden when the summary endpoint
          fails / returns null so a backend issue doesn't dominate
          the dashboard. */}
      {lifecycle && (
        <Card className="mb-4">
          <CardHeader>
            <span className="flex items-center gap-2">
              <ShieldAlert className="w-4 h-4 text-content-subtle" /> Distro Lifecycle
            </span>
          </CardHeader>
          <CardBody>
            <div className="grid grid-cols-2 md:grid-cols-4 gap-3">
              <LifecycleBucketTile
                label="Supported"
                count={lifecycle.counts.supported}
                total={lifecycle.total}
                statusValue="supported"
                accent="bg-emerald-500"
              />
              <LifecycleBucketTile
                label="Approaching EOL"
                count={lifecycle.counts.approaching_eol}
                total={lifecycle.total}
                statusValue="approaching-eol"
                accent="bg-yellow-500"
              />
              <LifecycleBucketTile
                label="Unsupported"
                count={lifecycle.counts.unsupported}
                total={lifecycle.total}
                statusValue="unsupported"
                accent="bg-red-500"
              />
              <LifecycleBucketTile
                label="Unknown"
                count={lifecycle.counts.unknown}
                total={lifecycle.total}
                statusValue="unknown"
                accent="bg-gray-500"
              />
            </div>

            {/* PRA-240: explain WHY hosts are unknown so an all-unknown fleet is
                actionable instead of an opaque gray tile. */}
            {lifecycle.counts.unknown > 0 && lifecycle.unknown_reasons && (
              <div className="mt-3 border-t border-border pt-3">
                <p className="text-xs text-content-subtle mb-2">
                  Why {lifecycle.counts.unknown}{' '}
                  {lifecycle.counts.unknown === 1 ? 'host is' : 'hosts are'} unknown:
                </p>
                <div className="grid grid-cols-1 sm:grid-cols-3 gap-2">
                  <LifecycleUnknownReason
                    count={lifecycle.unknown_reasons.freshness}
                    label="Stale / missing facts"
                    hint={`Facts older than ${Math.round(
                      (lifecycle.staleness_threshold_seconds ?? 86400) / 3600
                    )}h (or never collected) - refresh host facts or check enrollment`}
                  />
                  <LifecycleUnknownReason
                    count={lifecycle.unknown_reasons.missing_distro_facts}
                    label="No distro in facts"
                    hint="Facts collected but no distro id / release reported"
                  />
                  <LifecycleUnknownReason
                    count={lifecycle.unknown_reasons.no_lifecycle_row}
                    label="No EOL data"
                    hint="Distro / release not in the lifecycle seed - coverage gap"
                  />
                </div>
                {lifecycle.unknown_reasons.other > 0 && (
                  <p className="mt-2 text-xs text-content-subtle">
                    {lifecycle.unknown_reasons.other} unclassified.
                  </p>
                )}
              </div>
            )}
          </CardBody>
        </Card>
      )}

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4 mb-4">
        {/* Systems by Group */}
        <Card>
          <CardHeader>Systems by Group</CardHeader>
          <CardBody>
            {data.systems_by_group.length === 0 ? (
              <p className="text-content-subtle text-sm">No groups configured</p>
            ) : (
              <div className="space-y-2">
                {data.systems_by_group.map((g) => (
                  <div key={g.group} className="flex items-center justify-between text-sm">
                    <span className="text-content">{g.group}</span>
                    <span className="text-content-subtle tabular-nums">{g.count}</span>
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>

        {/* Systems by Distro */}
        <Card>
          <CardHeader>Systems by Distro</CardHeader>
          <CardBody>
            {data.systems_by_distro.length === 0 ? (
              <p className="text-content-subtle text-sm">No data</p>
            ) : (
              <div className="space-y-2">
                {data.systems_by_distro.map((d) => (
                  <div key={d.distro} className="flex items-center justify-between text-sm">
                    <span className="text-content">{d.distro}</span>
                    <span className="text-content-subtle tabular-nums">{d.count}</span>
                  </div>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      {/* Active Jobs */}
      <Card className="mb-4">
        <CardHeader>
          <span className="flex items-center gap-2"><PlayCircle className="w-4 h-4 text-content" /> Active Jobs</span>
        </CardHeader>
        <CardBody>
          {data.active_jobs.length === 0 ? (
            <p className="text-content-subtle text-sm">No jobs running</p>
          ) : (
            <div className="space-y-3">
              {data.active_jobs.map((job) => (
                <div key={job.job_id} className="bg-surface-raised/50 border border-border rounded-lg p-3">
                  <div className="flex items-center justify-between mb-2">
                    <div>
                      <span className="text-content font-medium text-sm">{job.name}</span>
                      <span className="text-xs text-content-subtle ml-2 capitalize">{job.job_type.replace('_', ' ')}</span>
                    </div>
                    <span className="text-xs text-content-muted tabular-nums">
                      {job.systems_completed + job.systems_failed} / {job.systems_targeted} ({job.progress_pct}%)
                    </span>
                  </div>
                  <div className="w-full h-1.5 bg-surface-overlay rounded-full overflow-hidden">
                    <div className="h-1.5 bg-slate-500 rounded-full transition-all duration-500" style={{ width: `${job.progress_pct}%` }} />
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
        {/* Recent Jobs */}
        <Card>
          <CardHeader>
            <span className="flex items-center gap-2"><Clock className="w-4 h-4 text-content-subtle" /> Recent Jobs</span>
          </CardHeader>
          <CardBody>
            {data.recent_jobs.length === 0 ? (
              <p className="text-content-subtle text-sm">No recent jobs</p>
            ) : (
              <div className="space-y-1">
                {data.recent_jobs.map((j) => (
                  <Link
                    key={j.history_id}
                    href="/job-scheduling/job-history"
                    className="flex items-center justify-between p-2 hover:bg-white/[0.03] rounded transition-colors text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="text-content truncate">{j.job_name}</div>
                      <div className="text-xs text-content-subtle">{j.ended_at ? formatTimestamp(j.ended_at) : '-'}</div>
                    </div>
                    <Badge variant={statusToBadgeVariant(j.status)}>{j.status}</Badge>
                  </Link>
                ))}
              </div>
            )}
          </CardBody>
        </Card>

        {/* Systems Needing Attention */}
        <Card>
          <CardHeader>
            <span className="flex items-center gap-2"><AlertTriangle className="w-4 h-4 text-yellow-500" /> Systems Needing Attention</span>
          </CardHeader>
          <CardBody>
            {data.attention.length === 0 ? (
              <div className="flex items-center gap-2 text-emerald-500 text-sm">
                <CheckCircle2 className="w-4 h-4" /> All systems healthy
              </div>
            ) : (
              <div className="space-y-1">
                {groupAttentionByHost(data.attention).map((a) => (
                  <Link
                    key={a.system_id}
                    href={`/system-management/system/${a.system_id}`}
                    className="flex items-center justify-between gap-2 p-2 hover:bg-white/[0.03] rounded transition-colors text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                  >
                    <div className="flex-1 min-w-0">
                      <div className="text-content truncate">{a.hostname}</div>
                      <div className="text-xs text-content-subtle truncate">
                        {a.reasons.map((r) => r.detail).filter(Boolean).join(' · ')}
                      </div>
                    </div>
                    <div className="flex flex-wrap items-center justify-end gap-1">
                      {a.reasons.map((r, i) => (
                        <Badge
                          key={`${r.reason}-${i}`}
                          variant={r.reason === 'unreachable' ? 'danger' : 'warning'}
                        >
                          {humanizeStatus(r.reason)}
                        </Badge>
                      ))}
                    </div>
                  </Link>
                ))}
              </div>
            )}
          </CardBody>
        </Card>
      </div>

      <ConfirmModal
        open={showCheckConfirm}
        onClose={() => setShowCheckConfirm(false)}
        onConfirm={handleCheckAll}
        title="Run Health Check"
        message="Run health check on all active systems? This may take a moment."
        confirmLabel="Check All"
        variant="warning"
      />
    </MainLayout>
  );
};

// PRA-156 #3d: lifecycle bucket tile. Click navigates to all-systems
// with the canonical hyphenated lifecycle.status as the URL filter
// (matches the smart-group predicate value, NOT the underscore key
// used in the summary response).
const LifecycleBucketTile: React.FC<{
  label: string;
  count: number;
  total: number;
  statusValue: 'supported' | 'approaching-eol' | 'unsupported' | 'unknown';
  accent: string;
}> = ({ label, count, total, statusValue, accent }) => {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <Link
      href={`/system-management/all-systems?lifecycle=${statusValue}`}
      className="block rounded-lg border border-border bg-surface-raised/30 p-3 hover:bg-white/[0.03] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs uppercase tracking-wide text-content-subtle">{label}</span>
        <span className="text-2xl font-bold text-content tabular-nums">{count}</span>
      </div>
      <div className="w-full h-1.5 bg-surface-overlay rounded-full overflow-hidden">
        <div
          className={`h-1.5 rounded-full transition-all duration-500 ${accent}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="mt-1 text-xs text-content-subtle tabular-nums">{pct}% of fleet</div>
    </Link>
  );
};

// PRA-240: one row of the Unknown-lifecycle reason breakdown. Dense +
// actionable: a count, a short reason label, and a one-line remediation hint.
// Links to the all-systems unknown filter so an operator can jump to the hosts.
const LifecycleUnknownReason: React.FC<{
  count: number;
  label: string;
  hint: string;
}> = ({ count, label, hint }) => (
  <Link
    href="/system-management/all-systems?lifecycle=unknown"
    className="block rounded-lg border border-border bg-surface-raised/30 p-2.5 hover:bg-white/[0.03] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
  >
    <div className="flex items-center justify-between">
      <span className="text-xs text-content-muted">{label}</span>
      <span className="text-lg font-bold text-content tabular-nums">{count}</span>
    </div>
    <p className="mt-1 text-[11px] leading-snug text-content-subtle">{hint}</p>
  </Link>
);

// PRA-163 #4: per-severity accents for the dashboard tile.
const SEVERITY_ACCENTS: Record<AdvisorySeverity, string> = {
  critical: 'bg-red-500',
  high: 'bg-orange-500',
  medium: 'bg-yellow-500',
  low: 'bg-blue-500',
  negligible: 'bg-gray-500',
  unknown: 'bg-gray-600',
};

const AdvisorySeverityTile: React.FC<{
  label: string;
  count: number;
  total: number;
  severity: AdvisorySeverity;
  accent: string;
}> = ({ label, count, total, severity, accent }) => {
  const pct = total > 0 ? Math.round((count / total) * 100) : 0;
  return (
    <Link
      href={`/patch-advisories/all?severity=${severity}`}
      className="block rounded-lg border border-border bg-surface-raised/30 p-3 hover:bg-white/[0.03] transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
    >
      <div className="flex items-center justify-between mb-2">
        <span className="text-xs uppercase tracking-wide text-content-subtle">{label}</span>
        <span className="text-2xl font-bold text-content tabular-nums">{count}</span>
      </div>
      <div className="w-full h-1.5 bg-surface-overlay rounded-full overflow-hidden">
        <div
          className={`h-1.5 rounded-full transition-all duration-500 ${accent}`}
          style={{ width: `${pct}%` }}
        />
      </div>
      <div className="mt-1 text-xs text-content-subtle tabular-nums">{pct}% of open</div>
    </Link>
  );
};

export default FleetDashboardPage;
