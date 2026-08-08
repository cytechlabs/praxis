import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { useAuth } from '@/context/AuthContext';
import { fetchAllSystems, SystemListItem } from '@/services/systemService';
import {
  getExecutionHistory,
  CommandExecutionResponse,
} from '@/services/commandExecutionService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Card, CardBody, Button, EmptyState } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

const statusBadgeClass = (statusRaw: string | null | undefined): string => {
  const status = (statusRaw || '').toLowerCase();
  if (['completed', 'success', 'succeeded'].includes(status))
    return 'bg-green-900 text-green-200 border-green-700';
  if (['failed', 'error', 'timeout', 'killed'].includes(status))
    return 'bg-red-900 text-red-200 border-red-700';
  if (['running', 'pending', 'queued'].includes(status))
    return 'bg-yellow-900 text-yellow-200 border-yellow-700';
  return 'bg-surface-overlay text-content border-border-strong';
};

const validationBadgeClass = (statusRaw: string | null | undefined): string => {
  const status = (statusRaw || '').toLowerCase();
  if (['passed', 'valid', 'allowed'].includes(status))
    return 'bg-green-900 text-green-200 border-green-700';
  if (['failed', 'rejected', 'blocked'].includes(status))
    return 'bg-red-900 text-red-200 border-red-700';
  if (['bypassed', 'skipped'].includes(status))
    return 'bg-orange-900 text-orange-200 border-orange-700';
  return 'bg-gray-800 text-gray-300 border-gray-600';
};

const riskBadgeClass = (riskRaw: string | null | undefined): string => {
  const risk = (riskRaw || '').toLowerCase();
  if (risk === 'low') return 'bg-green-900 text-green-200 border-green-700';
  if (risk === 'medium') return 'bg-yellow-900 text-yellow-200 border-yellow-700';
  if (risk === 'high') return 'bg-orange-900 text-orange-200 border-orange-700';
  if (risk === 'critical') return 'bg-red-900 text-red-200 border-red-700';
  return 'bg-surface-overlay text-content border-border-strong';
};

const InlineBadge: React.FC<{ label: string; className: string }> = ({ label, className }) => (
  <span className={`inline-block px-2 py-0.5 text-xs rounded border ${className}`}>
    {label}
  </span>
);

const CommandHistoryPage: React.FC = () => {
  const router = useRouter();
  const { user, loading: authLoading } = useAuth();
  // PRA-258: subscribe to timestamp preferences so this page re-renders when
  // they load/change. formatDateTime is a local closure over the bound formatter.
  const formatTimestamp = useFormatTimestamp();
  const formatDateTime = (iso: string | null | undefined): string => {
    if (!iso) return '-';
    try {
      return formatTimestamp(iso);
    } catch {
      return iso;
    }
  };

  const [systems, setSystems] = useState<SystemListItem[]>([]);
  const [rows, setRows] = useState<CommandExecutionResponse[]>([]);
  const [loading, setLoading] = useState(true);

  const [systemFilter, setSystemFilter] = useState<string>('');
  const [statusFilter, setStatusFilter] = useState<string>('');
  const [riskFilter, setRiskFilter] = useState<string>('');
  const [userFilter, setUserFilter] = useState<string>('');
  const [dateFrom, setDateFrom] = useState<string>('');
  const [dateTo, setDateTo] = useState<string>('');
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const [limit] = useState(100);
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    if (authLoading) return;
    if (!user) {
      router.push('/login');
      return;
    }
    (async () => {
      try {
        const list = await fetchAllSystems();
        setSystems(list);
      } catch {
        // ignore
      }
    })();
  }, [authLoading, user, router]);

  const fetchRows = useCallback(async () => {
    setLoading(true);
    try {
      const sid = systemFilter ? parseInt(systemFilter, 10) : undefined;
      const data = await getExecutionHistory(sid, limit, offset);
      setRows(data);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load history');
    } finally {
      setLoading(false);
    }
  }, [systemFilter, limit, offset]);

  useEffect(() => {
    if (authLoading || !user) return;
    fetchRows();
  }, [authLoading, user, fetchRows]);

  const systemHostnameMap = useMemo(() => {
    const m = new Map<number, string>();
    systems.forEach((s) => m.set(s.id, s.hostname));
    return m;
  }, [systems]);

  const userOptions = useMemo(() => {
    const set = new Set<number>();
    rows.forEach((r) => set.add(r.user_id));
    return Array.from(set).sort((a, b) => a - b);
  }, [rows]);

  const filteredRows = useMemo(() => {
    return rows.filter((r) => {
      if (statusFilter && (r.execution_status || '').toLowerCase() !== statusFilter)
        return false;
      if (riskFilter && (r.risk_level || '').toLowerCase() !== riskFilter) return false;
      if (userFilter && String(r.user_id) !== userFilter) return false;
      if (dateFrom) {
        const start = r.started_at ? new Date(r.started_at).getTime() : 0;
        const fromMs = new Date(dateFrom).getTime();
        if (start < fromMs) return false;
      }
      if (dateTo) {
        const start = r.started_at ? new Date(r.started_at).getTime() : 0;
        const toMs = new Date(dateTo).getTime() + 86400000;
        if (start > toMs) return false;
      }
      return true;
    });
  }, [rows, statusFilter, riskFilter, userFilter, dateFrom, dateTo]);

  const toggleExpand = (id: number) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id);
    else next.add(id);
    setExpanded(next);
  };

  const gotoExecution = (id: number) => {
    router.push(`/ssh/command-execution?view=${id}`);
  };

  return (
    <MainLayout>
        <Head>
          <title>Command History | Praxis</title>
        </Head>
      <div className="space-y-4">
        <PageHeader title="Command History" actions={<HelpLink slug="ssh-and-security" />} />

        {/* Filters */}
        <Card>
          <CardBody>
            <div className="grid grid-cols-1 md:grid-cols-3 lg:grid-cols-6 gap-3">
              <div>
                <label className="block text-xs text-content-muted uppercase mb-1">System</label>
                <select
                  value={systemFilter}
                  onChange={(e) => {
                    setSystemFilter(e.target.value);
                    setOffset(0);
                  }}
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-2 py-1 text-sm"
                >
                  <option value="">All</option>
                  {systems.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.hostname}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted uppercase mb-1">User ID</label>
                <select
                  value={userFilter}
                  onChange={(e) => setUserFilter(e.target.value)}
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-2 py-1 text-sm"
                >
                  <option value="">All</option>
                  {userOptions.map((u) => (
                    <option key={u} value={u}>
                      User {u}
                    </option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted uppercase mb-1">Status</label>
                <select
                  value={statusFilter}
                  onChange={(e) => setStatusFilter(e.target.value)}
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-2 py-1 text-sm"
                >
                  <option value="">All</option>
                  <option value="completed">Completed</option>
                  <option value="failed">Failed</option>
                  <option value="running">Running</option>
                  <option value="timeout">Timeout</option>
                  <option value="killed">Killed</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted uppercase mb-1">Risk</label>
                <select
                  value={riskFilter}
                  onChange={(e) => setRiskFilter(e.target.value)}
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-2 py-1 text-sm"
                >
                  <option value="">All</option>
                  <option value="low">Low</option>
                  <option value="medium">Medium</option>
                  <option value="high">High</option>
                  <option value="critical">Critical</option>
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted uppercase mb-1">From</label>
                <input
                  type="date"
                  value={dateFrom}
                  onChange={(e) => setDateFrom(e.target.value)}
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-2 py-1 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-content-muted uppercase mb-1">To</label>
                <input
                  type="date"
                  value={dateTo}
                  onChange={(e) => setDateTo(e.target.value)}
                  className="w-full bg-white/[0.02] border border-border-strong text-content rounded px-2 py-1 text-sm"
                />
              </div>
            </div>
          </CardBody>
        </Card>

        {/* Table */}
        <Card>
          <CardBody>
            <div className="flex items-center justify-between mb-2">
              <div className="text-sm text-content-muted">
                Showing {filteredRows.length} of {rows.length} loaded rows
              </div>
              <div className="flex items-center gap-2 text-xs">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                  disabled={offset === 0}
                >
                  Prev
                </Button>
                <span className="text-content-subtle">offset {offset}</span>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setOffset(offset + limit)}
                  disabled={rows.length < limit}
                >
                  Next
                </Button>
              </div>
            </div>
            {loading ? (
              <div className="text-sm text-content-subtle">Loading...</div>
            ) : filteredRows.length === 0 ? (
              <EmptyState title="No executions match" />
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="text-content-muted uppercase text-xs">
                    <tr>
                      <th scope="col" className="text-left py-1">Time</th>
                      <th scope="col" className="text-left py-1">System</th>
                      <th scope="col" className="text-left py-1">User</th>
                      <th scope="col" className="text-left py-1">Command</th>
                      <th scope="col" className="text-left py-1">Status</th>
                      <th scope="col" className="text-right py-1">Exit</th>
                      <th scope="col" className="text-right py-1">Time (ms)</th>
                      <th scope="col" className="text-left py-1">Validation</th>
                      <th scope="col" className="text-left py-1">Risk</th>
                    </tr>
                  </thead>
                  <tbody className="text-content">
                    {filteredRows.map((r) => {
                      const isExpanded = expanded.has(r.id);
                      return (
                        <React.Fragment key={r.id}>
                          <tr
                            className="border-t border-border hover:bg-surface-overlay cursor-pointer"
                            onClick={() => gotoExecution(r.id)}
                          >
                            <td className="py-1 text-xs">{formatDateTime(r.started_at)}</td>
                            <td className="py-1 text-xs">
                              {r.system_hostname || systemHostnameMap.get(r.system_id) || `#${r.system_id}`}
                            </td>
                            <td className="py-1 text-xs">{r.username || `#${r.user_id}`}</td>
                            <td
                              className="py-1 font-mono text-xs max-w-xs"
                              onClick={(e) => {
                                e.stopPropagation();
                                toggleExpand(r.id);
                              }}
                            >
                              {isExpanded ? (
                                <span className="whitespace-pre-wrap break-all">{r.command}</span>
                              ) : (
                                <span className="truncate block">{r.command}</span>
                              )}
                            </td>
                            <td className="py-1">
                              <InlineBadge
                                label={r.execution_status || '-'}
                                className={statusBadgeClass(r.execution_status)}
                              />
                            </td>
                            <td className="py-1 text-right">{r.exit_code ?? '-'}</td>
                            <td className="py-1 text-right">{r.execution_time_ms ?? '-'}</td>
                            <td className="py-1">
                              <InlineBadge
                                label={r.validation_status || '-'}
                                className={validationBadgeClass(r.validation_status)}
                              />
                            </td>
                            <td className="py-1">
                              <InlineBadge
                                label={r.risk_level || '-'}
                                className={riskBadgeClass(r.risk_level)}
                              />
                            </td>
                          </tr>
                        </React.Fragment>
                      );
                    })}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>
      </div>
    </MainLayout>
  );
};

export default CommandHistoryPage;
