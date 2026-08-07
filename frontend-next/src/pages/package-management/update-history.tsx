import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { AlertCircle } from 'lucide-react';
import { fetchAllSystems } from '@/services/systemService';
import {
  fetchAllHistory,
  fetchSystemHistory,
  PackageHistoryItem,
} from '@/services/packageService';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, Card, CardBody, StatCard, StatusBadge } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { usePackageScope } from '@/hooks/usePackageScope';
import PackageScopeControl from '@/components/packages/PackageScopeControl';
import { isScopeReady } from '@/services/packageScope';

interface SystemOption {
  id: number;
  hostname: string;
}

const UpdateHistory = () => {
  const formatTimestamp = useFormatTimestamp();
  const [systems, setSystems] = useState<SystemOption[]>([]);
  // Cohort scope. Single-system uses the per-host history endpoint;
  // every other scope aggregates through the scoped `/history/all` endpoint.
  const { scope, setScope, systems: scopeSystems, groups, smartGroups, ready } = usePackageScope();
  const selectedSystem: number | null =
    scope.type === 'system' && scope.id != null ? scope.id : null;
  const scopeReady = isScopeReady(scope);
  const [history, setHistory] = useState<PackageHistoryItem[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [expandedError, setExpandedError] = useState<number | null>(null);
  const limit = 50;

  useEffect(() => {
    fetchAllSystems()
      .then((data) => {
        const opts = data.map((s) => ({ id: s.id, hostname: s.hostname }));
        setSystems(opts);
      })
      .catch(() => toast.error('Failed to load systems'));
  }, []);

  const loadHistory = useCallback(async () => {
    // A cohort scope with no target must never widen to a fleet-wide query.
    if (!ready || !isScopeReady(scope)) {
      setHistory([]);
      setTotal(0);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      const data =
        scope.type === 'system' && scope.id != null
          ? await fetchSystemHistory(scope.id, limit, offset)
          : await fetchAllHistory(limit, offset, scope);
      setHistory(data.history);
      setTotal(data.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load history');
    } finally {
      setLoading(false);
    }
  }, [scope, ready, offset]);

  useEffect(() => {
    loadHistory();
  }, [loadHistory]);

  useEffect(() => {
    setOffset(0);
  }, [scope]);

  const systemMap = useMemo(() => {
    const map = new Map<number, string>();
    systems.forEach((s) => map.set(s.id, s.hostname));
    return map;
  }, [systems]);

  const stats = useMemo(() => {
    const updates = history.filter((h) => h.operation === 'update').length;
    const installs = history.filter((h) => h.operation === 'install').length;
    const removals = history.filter((h) => h.operation === 'remove').length;
    return { updates, installs, removals };
  }, [history]);

  const escapeCsvField = (value: string) => {
    if (value.includes(',') || value.includes('"') || value.includes('\n')) {
      return `"${value.replace(/"/g, '""')}"`;
    }
    return value;
  };

  const handleExport = () => {
    const headers = ['Date', 'System', 'Package', 'Old Version', 'New Version', 'Operation', 'Status', 'Performed By'];
    const rows = history.map((item) => [
      formatTimestamp(item.performed_at),
      systemMap.get(item.system_id) || `System #${item.system_id}`,
      item.package_name,
      item.old_version || '',
      item.new_version || '',
      item.operation,
      item.status,
      item.performed_by || 'System',
    ]);

    const csvContent = [
      headers.map(escapeCsvField).join(','),
      ...rows.map((row) => row.map(escapeCsvField).join(',')),
    ].join('\n');

    const blob = new Blob([csvContent], { type: 'text/csv;charset=utf-8;' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    const date = new Date().toISOString().split('T')[0];
    link.href = url;
    link.download = `praxis-update-history-${date}.csv`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  const formatDate = (dateStr: string) => {
    return formatTimestamp(dateStr);
  };

  return (
    <MainLayout>
        <Head>
          <title>Update History | Praxis</title>
        </Head>
      <PageHeader
        title="Update History"
        subtitle="View package update history across all systems"
        actions={
          <div className="flex flex-wrap items-end gap-3">
            <PackageScopeControl
              value={scope}
              onChange={setScope}
              systems={scopeSystems}
              groups={groups}
              smartGroups={smartGroups}
            />
            <Button variant="outline" disabled={history.length === 0} onClick={handleExport}>
              Export Log
            </Button>
            <HelpLink slug="packages" />
          </div>
        }
      />
      <Card>
        <CardBody>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-4 mb-6">
            <StatCard label="Total Updates" value={total} subtitle="Operations performed" />
            <StatCard label="Updates" value={stats.updates} subtitle="Packages updated" />
            <StatCard label="Installs" value={stats.installs} subtitle="Packages installed" />
            <StatCard label="Removals" value={stats.removals} subtitle="Packages removed" />
          </div>

          <div className="border border-gray-800 rounded-lg">
            <div className="grid grid-cols-[0.9fr_1fr_1.2fr_2fr_0.7fr_0.7fr_1fr] gap-3 p-4 bg-gray-950 border-b border-gray-800 font-medium text-gray-200">
              <div>Date</div>
              <div>System</div>
              <div>Package</div>
              <div>Version Change</div>
              <div>Operation</div>
              <div>Status</div>
              <div>Performed By</div>
            </div>
            {!scopeReady ? (
              <div className="p-4 text-gray-400">
                Select a group or smart group above to view its update history.
              </div>
            ) : loading ? (
              <div className="p-4 text-gray-400">Loading history...</div>
            ) : history.length === 0 ? (
              <div className="p-4 text-gray-400">
                No update history available. History will appear here after operations are performed.
              </div>
            ) : (
              history.map((item) => (
                <div key={item.id}>
                  <div
                    className={`grid grid-cols-[0.9fr_1fr_1.2fr_2fr_0.7fr_0.7fr_1fr] gap-3 p-4 border-b border-gray-800 last:border-b-0 hover:bg-gray-950 ${
                      item.status === 'failed' && item.error_message ? 'cursor-pointer' : ''
                    }`}
                    onClick={() => {
                      if (item.status === 'failed' && item.error_message) {
                        setExpandedError(expandedError === item.id ? null : item.id);
                      }
                    }}
                  >
                    <div className="text-sm text-gray-400">{formatDate(item.performed_at)}</div>
                    <div className="font-medium text-gray-300">
                      {systemMap.get(item.system_id) || `System #${item.system_id}`}
                    </div>
                    <div className="font-medium text-gray-300 break-words">{item.package_name}</div>
                    <div className="text-gray-400 font-mono text-xs break-all">
                      {item.old_version && item.new_version
                        ? `${item.old_version} → ${item.new_version}`
                        : item.new_version
                          ? `→ ${item.new_version}`
                          : item.old_version
                            ? `${item.old_version} →`
                            : '-'}
                    </div>
                    <div>
                      <span
                        className={`px-2 py-1 rounded text-sm ${
                          item.operation === 'install'
                            ? 'bg-green-900 text-green-300'
                            : item.operation === 'update'
                              ? 'bg-slate-900 text-slate-300'
                              : item.operation === 'remove'
                                ? 'bg-red-900 text-red-300'
                                : 'bg-gray-800 text-gray-300'
                        }`}
                      >
                        {item.operation}
                      </span>
                    </div>
                    <div className="flex items-center gap-1">
                      <StatusBadge status={item.status} />
                      {item.status === 'failed' && item.error_message && (
                        <AlertCircle size={14} className="text-red-400" />
                      )}
                    </div>
                    <div className="text-sm text-gray-400">
                      {item.performed_by || 'System'}
                    </div>
                  </div>
                  {expandedError === item.id && item.error_message && (
                    <div className="px-4 py-3 bg-red-950/30 border-b border-gray-800 text-sm text-red-300">
                      <span className="font-medium">Error: </span>{item.error_message}
                    </div>
                  )}
                </div>
              ))
            )}
          </div>

          {totalPages > 1 && (
            <div className="mt-4 flex justify-between items-center text-sm text-gray-400">
              <div>
                Showing {offset + 1}-{Math.min(offset + limit, total)} of {total} entries
              </div>
              <div className="flex space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                >
                  Previous
                </Button>
                <span className="px-3 py-1 text-gray-300">
                  Page {currentPage} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset + limit >= total}
                  onClick={() => setOffset(offset + limit)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}
        </CardBody>
      </Card>
    </MainLayout>
  );
};

export default UpdateHistory;
