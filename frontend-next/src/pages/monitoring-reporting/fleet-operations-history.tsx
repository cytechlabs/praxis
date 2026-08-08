import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody, Badge, statusToBadgeVariant } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { RefreshCw, Filter, X, CheckCircle, XCircle, Clock, AlertTriangle } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface FleetOperation {
  id: number;
  operation_type: string;
  user_id: number;
  username: string | null;
  target_count: number;
  success_count: number;
  failure_count: number;
  status: string;
  parameters: unknown;
  created_at: string | null;
  completed_at: string | null;
}

interface FleetOperationResult {
  id: number;
  system_id: number | null;
  system_hostname: string | null;
  status: string;
  error_message: string | null;
  created_at: string | null;
}

interface FleetOperationDetail {
  operation: FleetOperation;
  results: FleetOperationResult[];
}

interface ListResponse {
  items: FleetOperation[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

interface FilterOptions {
  operation_types: string[];
  statuses: string[];
  users: { id: number; username: string }[];
}

const statusIcon = (status: string) => {
  switch (status) {
    case 'completed': return <CheckCircle className="w-3 h-3" />;
    case 'failed': return <XCircle className="w-3 h-3" />;
    case 'running': return <Clock className="w-3 h-3" />;
    case 'partial': return <AlertTriangle className="w-3 h-3" />;
    default: return null;
  }
};

const FleetOperationsHistory: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [items, setItems] = useState<FleetOperation[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [loading, setLoading] = useState(false);
  const [options, setOptions] = useState<FilterOptions | null>(null);
  const [operationTypeFilter, setOperationTypeFilter] = useState('');
  const [statusFilter, setStatusFilter] = useState('');
  const [userFilter, setUserFilter] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');

  const [detail, setDetail] = useState<FleetOperationDetail | null>(null);
  const [detailLoading, setDetailLoading] = useState(false);

  const loadOptions = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/fleet/operations/filters/options');
      if (!res.ok) throw new Error('Failed to load filter options');
      setOptions(await res.json());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed');
    }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('page_size', String(pageSize));
      if (operationTypeFilter) params.set('operation_type', operationTypeFilter);
      if (statusFilter) params.set('status', statusFilter);
      if (userFilter) params.set('user_id', userFilter);
      if (fromDate) params.set('from_date', new Date(fromDate).toISOString());
      if (toDate) params.set('to_date', new Date(toDate).toISOString());
      const res = await apiFetch(`/api/backend/fleet/operations?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load fleet operations');
      const data: ListResponse = await res.json();
      setItems(data.items);
      setTotal(data.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [page, operationTypeFilter, statusFilter, userFilter, fromDate, toDate]);

  useEffect(() => { loadOptions(); }, [loadOptions]);
  useEffect(() => { load(); }, [load]);

  const openDetail = async (id: number) => {
    setDetailLoading(true);
    setDetail(null);
    try {
      const res = await apiFetch(`/api/backend/fleet/operations/${id}`);
      if (!res.ok) throw new Error('Failed to load operation detail');
      setDetail(await res.json());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load detail');
    } finally {
      setDetailLoading(false);
    }
  };

  const resetFilters = () => {
    setOperationTypeFilter('');
    setStatusFilter('');
    setUserFilter('');
    setFromDate('');
    setToDate('');
    setPage(1);
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <MainLayout>
        <Head>
          <title>Fleet Operations History | Praxis</title>
        </Head>
        <PageHeader
          title="Fleet Operations History"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => load()}
                icon={<RefreshCw className="w-4 h-4" />}
              >
                Refresh
              </Button>
              <HelpLink slug="monitoring-and-alerts" />
            </div>
          }
        />

        <Card>
          <CardBody>
            <div className="flex flex-wrap items-end gap-4 mb-4">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-content-muted" />
                <span className="text-sm text-content-muted">Filters:</span>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">Operation Type</label>
                <select
                  value={operationTypeFilter}
                  onChange={(e) => { setOperationTypeFilter(e.target.value); setPage(1); }}
                  className="bg-surface-sunken border border-border rounded px-2 py-1 text-content text-sm"
                >
                  <option value="">All</option>
                  {options?.operation_types.map((t) => <option key={t} value={t}>{t}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">Status</label>
                <select
                  value={statusFilter}
                  onChange={(e) => { setStatusFilter(e.target.value); setPage(1); }}
                  className="bg-surface-sunken border border-border rounded px-2 py-1 text-content text-sm"
                >
                  <option value="">All</option>
                  {options?.statuses.map((s) => <option key={s} value={s}>{s}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">User</label>
                <select
                  value={userFilter}
                  onChange={(e) => { setUserFilter(e.target.value); setPage(1); }}
                  className="bg-surface-sunken border border-border rounded px-2 py-1 text-content text-sm"
                >
                  <option value="">All</option>
                  {options?.users.map((u) => <option key={u.id} value={u.id}>{u.username}</option>)}
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">From</label>
                <input
                  type="date"
                  value={fromDate}
                  onChange={(e) => { setFromDate(e.target.value); setPage(1); }}
                  className="bg-surface-sunken border border-border rounded px-2 py-1 text-content text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">To</label>
                <input
                  type="date"
                  value={toDate}
                  onChange={(e) => { setToDate(e.target.value); setPage(1); }}
                  className="bg-surface-sunken border border-border rounded px-2 py-1 text-content text-sm"
                />
              </div>
              <Button variant="outline" size="sm" onClick={resetFilters}>
                Reset
              </Button>
            </div>

            <div className="grid grid-cols-12 gap-2 p-3 bg-surface-sunken border-b border-border font-medium text-content text-sm rounded-t-lg">
              <div className="col-span-3">Operation Type</div>
              <div className="col-span-2">User</div>
              <div className="col-span-1">Target</div>
              <div className="col-span-1">Success</div>
              <div className="col-span-1">Failed</div>
              <div className="col-span-2">Status</div>
              <div className="col-span-2">Started</div>
            </div>

            {loading && <div className="p-4 text-content-muted">Loading...</div>}
            {!loading && items.length === 0 && (
              <div className="p-8 text-center text-content-muted">No fleet operations found.</div>
            )}

            {!loading && items.map((o) => (
              <div
                key={o.id}
                onClick={() => openDetail(o.id)}
                className="grid grid-cols-12 gap-2 p-3 border-b border-border text-content hover:bg-surface-overlay/50 text-sm items-center cursor-pointer"
              >
                <div className="col-span-3 font-medium">{o.operation_type}</div>
                <div className="col-span-2 truncate">{o.username || `#${o.user_id}`}</div>
                <div className="col-span-1">{o.target_count}</div>
                <div className="col-span-1 text-green-400">{o.success_count}</div>
                <div className="col-span-1 text-red-400">{o.failure_count}</div>
                <div className="col-span-2">
                  <Badge variant={statusToBadgeVariant(o.status)}>
                    <span className="inline-flex items-center gap-1">
                      {statusIcon(o.status)} {o.status}
                    </span>
                  </Badge>
                </div>
                <div className="col-span-2">{o.created_at ? formatTimestamp(o.created_at) : '-'}</div>
              </div>
            ))}

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

        {/* Detail modal */}
        {(detail || detailLoading) && (
          <div className="fixed inset-0 bg-surface/80 flex items-center justify-center z-50 p-4">
            <div className="bg-surface-overlay border border-border rounded-lg p-6 max-w-4xl w-full max-h-[90vh] overflow-y-auto">
              <div className="flex items-center justify-between mb-4">
                <h2 className="text-xl font-semibold text-content">
                  {detailLoading ? 'Loading...' : `Operation #${detail?.operation.id} -- ${detail?.operation.operation_type}`}
                </h2>
                <button
                  onClick={() => { setDetail(null); }}
                  className="text-content-muted hover:text-content"
                >
                  <X className="w-5 h-5" />
                </button>
              </div>

              {detail && (
                <>
                  <div className="grid grid-cols-2 gap-4 mb-4 text-sm">
                    <div><span className="text-content-muted">User:</span> <span className="text-content">{detail.operation.username || `#${detail.operation.user_id}`}</span></div>
                    <div><span className="text-content-muted">Status:</span> <Badge variant={statusToBadgeVariant(detail.operation.status)}>{detail.operation.status}</Badge></div>
                    <div><span className="text-content-muted">Target:</span> <span className="text-content">{detail.operation.target_count}</span></div>
                    <div><span className="text-content-muted">Success / Failure:</span> <span className="text-green-400">{detail.operation.success_count}</span> / <span className="text-red-400">{detail.operation.failure_count}</span></div>
                    <div><span className="text-content-muted">Started:</span> <span className="text-content">{detail.operation.created_at ? formatTimestamp(detail.operation.created_at) : '-'}</span></div>
                    <div><span className="text-content-muted">Completed:</span> <span className="text-content">{detail.operation.completed_at ? formatTimestamp(detail.operation.completed_at) : '-'}</span></div>
                  </div>

                  {detail.operation.parameters !== null && detail.operation.parameters !== undefined && (
                    <div className="mb-4">
                      <div className="text-xs text-content-muted mb-1">Parameters</div>
                      <pre className="bg-surface-sunken border border-border rounded p-2 text-xs text-content overflow-auto max-h-40">
                        {JSON.stringify(detail.operation.parameters, null, 2)}
                      </pre>
                    </div>
                  )}

                  <h3 className="text-sm font-semibold text-content mb-2">Per-System Results</h3>
                  <div className="border border-border rounded">
                    <div className="grid grid-cols-12 gap-2 p-2 bg-surface-sunken text-xs font-medium text-content border-b border-border">
                      <div className="col-span-4">System</div>
                      <div className="col-span-2">Status</div>
                      <div className="col-span-6">Error</div>
                    </div>
                    {detail.results.length === 0 && (
                      <div className="p-4 text-center text-content-muted text-sm">No per-system results recorded.</div>
                    )}
                    {detail.results.map((r) => (
                      <div key={r.id} className="grid grid-cols-12 gap-2 p-2 text-xs text-content border-b border-border/50">
                        <div className="col-span-4 truncate">{r.system_hostname || (r.system_id ? `#${r.system_id}` : '-')}</div>
                        <div className="col-span-2">
                          <Badge variant={statusToBadgeVariant(r.status)}>{r.status}</Badge>
                        </div>
                        <div className="col-span-6 text-red-300 break-all">{r.error_message || '-'}</div>
                      </div>
                    ))}
                  </div>
                </>
              )}
            </div>
          </div>
        )}
    </MainLayout>
  );
};

export default FleetOperationsHistory;
