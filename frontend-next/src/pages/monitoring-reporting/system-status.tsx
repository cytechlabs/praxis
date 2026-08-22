import React, { useCallback, useEffect, useState, useRef } from 'react';
import { toast } from 'sonner';
import { useRouter } from 'next/router';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody, StatCard, Badge, statusToBadgeVariant, nativeSelectClass } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { RefreshCw, AlertTriangle, ChevronDown, ChevronUp } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import Head from 'next/head';

interface SystemStatusItem {
  id: number;
  hostname: string;
  ip_address: string;
  status: string;
  connection_status: string;
  last_connection: string | null;
  consecutive_failures: number;
  last_audited: string | null;
  distro_name: string | null;
  group_name: string | null;
  group_id: number;
}

interface StatusOverview {
  status_counts: Record<string, number>;
  connection_counts: Record<string, number>;
  stale_scan_count: number;
  avg_consecutive_failures_unreachable: number;
  health: {
    total_systems: number;
    unreachable: number;
    never_checked: number;
  };
}

interface EolEntry {
  system_id: number;
  hostname: string;
  distro_name: string;
  distro_version: string;
  end_of_life_date: string;
  days_until_eol: number;
}

interface EolData {
  eol_systems: EolEntry[];
  warning_systems: EolEntry[];
  ok_systems_count: number;
}

interface SystemListResponse {
  items: SystemStatusItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

interface GroupOption {
  id: number;
  name: string;
}

function timeAgo(dateStr: string | null): string {
  if (!dateStr) return 'Never';
  const date = new Date(dateStr);
  const now = new Date();
  const diffMs = now.getTime() - date.getTime();
  const diffMin = Math.floor(diffMs / 60000);
  if (diffMin < 1) return 'Just now';
  if (diffMin < 60) return `${diffMin}m ago`;
  const diffHr = Math.floor(diffMin / 60);
  if (diffHr < 24) return `${diffHr}h ago`;
  const diffDays = Math.floor(diffHr / 24);
  return `${diffDays}d ago`;
}

const SystemStatus: React.FC = () => {
  const router = useRouter();
  const [overview, setOverview] = useState<StatusOverview | null>(null);
  const [systems, setSystems] = useState<SystemStatusItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [loading, setLoading] = useState(false);
  const [overviewLoading, setOverviewLoading] = useState(false);

  const [statusFilter, setStatusFilter] = useState('');
  const [connFilter, setConnFilter] = useState('');
  const [groupFilter, setGroupFilter] = useState('');
  const [sortBy, setSortBy] = useState('hostname');
  const [sortDir, setSortDir] = useState('asc');
  const [groups, setGroups] = useState<GroupOption[]>([]);
  const [autoRefresh, setAutoRefresh] = useState(false);
  const intervalRef = useRef<NodeJS.Timeout | null>(null);

  // EOL state
  const [eolData, setEolData] = useState<EolData | null>(null);
  const [eolExpanded, setEolExpanded] = useState(false);

  const loadGroups = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/systems/groups');
      if (res.ok) setGroups(await res.json());
    } catch { /* ignore */ }
  }, []);

  const loadOverview = useCallback(async () => {
    setOverviewLoading(true);
    try {
      const res = await apiFetch('/api/backend/system-status/overview');
      if (!res.ok) throw new Error('Failed to load overview');
      setOverview(await res.json());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load overview');
    } finally {
      setOverviewLoading(false);
    }
  }, []);

  const loadSystems = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('page_size', String(pageSize));
      params.set('sort_by', sortBy);
      params.set('sort_dir', sortDir);
      if (statusFilter) params.set('status', statusFilter);
      if (connFilter) params.set('connection_status', connFilter);
      if (groupFilter) params.set('group_id', groupFilter);

      const res = await apiFetch(`/api/backend/system-status/systems?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load systems');
      const data: SystemListResponse = await res.json();
      setSystems(data.items);
      setTotal(data.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load systems');
    } finally {
      setLoading(false);
    }
  }, [page, sortBy, sortDir, statusFilter, connFilter, groupFilter]);

  const loadEol = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/systems/eol-status');
      if (res.ok) setEolData(await res.json());
    } catch { /* ignore */ }
  }, []);

  const refreshAll = useCallback(() => {
    loadOverview();
    loadSystems();
    loadEol();
  }, [loadOverview, loadSystems, loadEol]);

  useEffect(() => { loadGroups(); }, [loadGroups]);
  useEffect(() => { loadOverview(); loadEol(); }, [loadOverview, loadEol]);
  useEffect(() => { loadSystems(); }, [loadSystems]);

  useEffect(() => {
    if (autoRefresh) {
      intervalRef.current = setInterval(refreshAll, 30000);
    } else if (intervalRef.current) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
    return () => { if (intervalRef.current) clearInterval(intervalRef.current); };
  }, [autoRefresh, refreshAll]);

  const handleSort = (col: string) => {
    if (sortBy === col) {
      setSortDir(d => d === 'asc' ? 'desc' : 'asc');
    } else {
      setSortBy(col);
      setSortDir('asc');
    }
    setPage(1);
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  const connBadge = (s: string) => {
    const variantMap: Record<string, 'success' | 'warning' | 'danger' | 'neutral'> = {
      connected: 'success',
      disconnected: 'warning',
      unreachable: 'danger',
      never_checked: 'neutral',
    };
    return (
      <Badge variant={variantMap[s] || 'neutral'}>
        {s.replace('_', ' ')}
      </Badge>
    );
  };

  const SortIcon = ({ col }: { col: string }) => {
    if (sortBy !== col) return null;
    return sortDir === 'asc' ? <ChevronUp className="w-3 h-3 inline ml-1" /> : <ChevronDown className="w-3 h-3 inline ml-1" />;
  };

  const sc = overview?.status_counts || {};
  const totalSystems = overview?.health?.total_systems || 0;
  const pct = (n: number) => totalSystems > 0 ? Math.round((n / totalSystems) * 100) : 0;

  const eolCount = (eolData?.eol_systems.length || 0) + (eolData?.warning_systems.length || 0);

  return (
    <MainLayout>
        <Head>
          <title>System Status | Praxis</title>
        </Head>
        <PageHeader
          title="System Status"
          actions={
            <>
              <label className="flex items-center gap-2 text-sm text-content-muted cursor-pointer">
                <input
                  type="checkbox"
                  checked={autoRefresh}
                  onChange={(e) => setAutoRefresh(e.target.checked)}
                  className="rounded"
                />
                Auto-refresh (30s)
              </label>
              <Button
                variant="outline"
                size="sm"
                onClick={refreshAll}
                disabled={overviewLoading || loading}
                icon={<RefreshCw className={`w-4 h-4 ${(overviewLoading || loading) ? 'animate-spin' : ''}`} />}
              >
                Refresh
              </Button>
              <HelpLink slug="monitoring-and-alerts" />
            </>
          }
        />

        {/* Summary cards */}
        <div className="grid grid-cols-2 md:grid-cols-5 gap-4 mb-6">
          <StatCard label="Total Systems" value={totalSystems} />
          <StatCard label="Active" value={sc['Active'] || 0} subtitle={`${pct(sc['Active'] || 0)}%`} />
          <StatCard label="Unreachable" value={sc['Unreachable'] || 0} subtitle={`${pct(sc['Unreachable'] || 0)}%`} />
          <StatCard label="Maintenance" value={sc['Maintenance'] || 0} subtitle={`${pct(sc['Maintenance'] || 0)}%`} />
          <StatCard label="Never Checked" value={overview?.connection_counts?.['never_checked'] || 0} subtitle={`${pct(overview?.connection_counts?.['never_checked'] || 0)}%`} />
        </div>

        {/* EOL warnings banner */}
        {eolData && eolCount > 0 && (
          <Card className="mb-6">
            <CardBody>
              <button
                onClick={() => setEolExpanded(!eolExpanded)}
                className="flex items-center justify-between w-full text-left"
              >
                <div className="flex items-center gap-2">
                  <AlertTriangle className="w-5 h-5 text-yellow-400" />
                  <span className="text-yellow-300 font-medium">
                    Distro EOL Warnings: {eolData.eol_systems.length} past EOL, {eolData.warning_systems.length} within 90 days
                  </span>
                </div>
                {eolExpanded ? <ChevronUp className="w-4 h-4 text-content-muted" /> : <ChevronDown className="w-4 h-4 text-content-muted" />}
              </button>
              {eolExpanded && (
                <div className="mt-4 space-y-2">
                  {eolData.eol_systems.length > 0 && (
                    <div>
                      <div className="text-xs text-red-400 font-medium mb-1 uppercase">Past End of Life</div>
                      {eolData.eol_systems.map((e) => (
                        <div key={e.system_id} className="flex items-center gap-3 py-1 text-sm">
                          <Badge variant="danger">EOL</Badge>
                          <button onClick={() => router.push(`/system-management/system/${e.system_id}`)} className="text-content hover:text-white underline">
                            {e.hostname}
                          </button>
                          <span className="text-content-subtle">{e.distro_name} {e.distro_version}</span>
                          <span className="text-red-400 text-xs">EOL {Math.abs(e.days_until_eol)}d ago</span>
                        </div>
                      ))}
                    </div>
                  )}
                  {eolData.warning_systems.length > 0 && (
                    <div>
                      <div className="text-xs text-yellow-400 font-medium mb-1 uppercase mt-2">EOL Within 90 Days</div>
                      {eolData.warning_systems.map((e) => (
                        <div key={e.system_id} className="flex items-center gap-3 py-1 text-sm">
                          <Badge variant="warning">EOL Soon</Badge>
                          <button onClick={() => router.push(`/system-management/system/${e.system_id}`)} className="text-content hover:text-white underline">
                            {e.hostname}
                          </button>
                          <span className="text-content-subtle">{e.distro_name} {e.distro_version}</span>
                          <span className="text-yellow-400 text-xs">{e.days_until_eol}d remaining</span>
                        </div>
                      ))}
                    </div>
                  )}
                </div>
              )}
            </CardBody>
          </Card>
        )}

        {/* Systems table */}
        <Card>
          <CardBody>
            {/* Filters */}
            <div className="flex flex-wrap items-end gap-4 mb-4">
              <div>
                <label className="block text-xs text-content-muted mb-1">Status</label>
                <select
                  value={statusFilter}
                  onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
                  className={`border border-border rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                >
                  <option value="">All</option>
                  <option value="Active">Active</option>
                  <option value="Inactive">Inactive</option>
                  <option value="Maintenance">Maintenance</option>
                  <option value="Unreachable">Unreachable</option>
                  <option value="Decommissioned">Decommissioned</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">Connection</label>
                <select
                  value={connFilter}
                  onChange={(e) => { setConnFilter(e.target.value); setPage(1); }}
                  className={`border border-border rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                >
                  <option value="">All</option>
                  <option value="connected">Connected</option>
                  <option value="disconnected">Disconnected</option>
                  <option value="unreachable">Unreachable</option>
                  <option value="never_checked">Never Checked</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">Group</label>
                <select
                  value={groupFilter}
                  onChange={(e) => { setGroupFilter(e.target.value); setPage(1); }}
                  className={`border border-border rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                >
                  <option value="">All</option>
                  {groups.map((g) => (
                    <option key={g.id} value={g.id}>{g.name}</option>
                  ))}
                </select>
              </div>
              <Button
                variant="outline"
                size="sm"
                onClick={() => { setStatusFilter(''); setConnFilter(''); setGroupFilter(''); setPage(1); }}
              >
                Reset
              </Button>
            </div>

            {/* Table */}
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-surface-sunken border-b border-border text-content">
                    <th scope="col" className="px-4 py-3 text-left cursor-pointer" onClick={() => handleSort('hostname')}>
                      Hostname <SortIcon col="hostname" />
                    </th>
                    <th scope="col" className="px-4 py-3 text-left">IP</th>
                    <th scope="col" className="px-4 py-3 text-left cursor-pointer" onClick={() => handleSort('status')}>
                      Status <SortIcon col="status" />
                    </th>
                    <th scope="col" className="px-4 py-3 text-left">Connection</th>
                    <th scope="col" className="px-4 py-3 text-left cursor-pointer" onClick={() => handleSort('last_connection')}>
                      Last Connection <SortIcon col="last_connection" />
                    </th>
                    <th scope="col" className="px-4 py-3 text-left">Last Scan</th>
                    <th scope="col" className="px-4 py-3 text-left">Distro</th>
                    <th scope="col" className="px-4 py-3 text-left">Group</th>
                  </tr>
                </thead>
                <tbody>
                  {loading && (
                    <tr><td colSpan={8} className="px-4 py-8 text-center text-content-muted">Loading...</td></tr>
                  )}
                  {!loading && systems.length === 0 && (
                    <tr><td colSpan={8} className="px-4 py-8 text-center text-content-muted">No systems found.</td></tr>
                  )}
                  {!loading && systems.map((s) => (
                    <tr
                      key={s.id}
                      className="border-b border-border/50 hover:bg-surface-overlay/50 cursor-pointer"
                      onClick={() => router.push(`/system-management/system/${s.id}`)}
                    >
                      <td className="px-4 py-3 text-content font-medium">{s.hostname}</td>
                      <td className="px-4 py-3 text-content">{s.ip_address}</td>
                      <td className="px-4 py-3"><Badge variant={statusToBadgeVariant(s.status)}>{s.status}</Badge></td>
                      <td className="px-4 py-3">{connBadge(s.connection_status)}</td>
                      <td className="px-4 py-3 text-content-muted">{timeAgo(s.last_connection)}</td>
                      <td className="px-4 py-3 text-content-muted">{timeAgo(s.last_audited)}</td>
                      <td className="px-4 py-3 text-content">{s.distro_name || '-'}</td>
                      <td className="px-4 py-3 text-content">{s.group_name || '-'}</td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-content-muted">
                {total > 0
                  ? `Showing ${(page - 1) * pageSize + 1}-${Math.min(page * pageSize, total)} of ${total}`
                  : 'No results'}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <span className="text-sm text-content-muted self-center">Page {page} of {totalPages}</span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          </CardBody>
        </Card>
    </MainLayout>
  );
};

export default SystemStatus;
