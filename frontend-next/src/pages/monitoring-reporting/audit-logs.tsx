import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody, EmptyState } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { RefreshCw, Filter, ChevronDown, ChevronRight } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import ExportButton from '@/components/ExportButton';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface AuditItem {
  id: number;
  system_id: number;
  system_hostname: string | null;
  audit_type: string;
  operation: string;
  changed_by: number;
  changed_by_username: string | null;
  changed_at: string | null;
  old_value: string | null;
  new_value: string | null;
}

interface AuditListResponse {
  items: AuditItem[];
  total: number;
  page: number;
  page_size: number;
  total_pages: number;
}

interface FilterOptions {
  audit_types: string[];
  operations: string[];
  systems: { id: number; hostname: string }[];
  users: { id: number; username: string }[];
}

const truncate = (s: string | null, n = 60) => {
  if (!s) return '-';
  return s.length > n ? s.slice(0, n) + '...' : s;
};

const AuditLogs: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [items, setItems] = useState<AuditItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [loading, setLoading] = useState(false);
  const [expanded, setExpanded] = useState<Set<number>>(new Set());

  const [options, setOptions] = useState<FilterOptions | null>(null);
  const [systemFilter, setSystemFilter] = useState<string>('');
  const [userFilter, setUserFilter] = useState<string>('');
  const [operationFilter, setOperationFilter] = useState<string>('');
  const [auditTypeFilter, setAuditTypeFilter] = useState<string>('');
  const [fromDate, setFromDate] = useState<string>('');
  const [toDate, setToDate] = useState<string>('');

  const loadOptions = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/audits/filters/options');
      if (!res.ok) throw new Error('Failed to load filter options');
      setOptions(await res.json());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load filters');
    }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('page_size', String(pageSize));
      if (systemFilter) params.set('system_id', systemFilter);
      if (userFilter) params.set('user_id', userFilter);
      if (operationFilter) params.set('operation', operationFilter);
      if (auditTypeFilter) params.set('audit_type', auditTypeFilter);
      if (fromDate) params.set('from_date', new Date(fromDate).toISOString());
      if (toDate) params.set('to_date', new Date(toDate).toISOString());

      const res = await apiFetch(`/api/backend/audits?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load audit logs');
      const data: AuditListResponse = await res.json();
      setItems(data.items);
      setTotal(data.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load audit logs');
    } finally {
      setLoading(false);
    }
  }, [page, systemFilter, userFilter, operationFilter, auditTypeFilter, fromDate, toDate]);

  useEffect(() => { loadOptions(); }, [loadOptions]);
  useEffect(() => { load(); }, [load]);

  const toggleExpanded = (id: number) => {
    const next = new Set(expanded);
    if (next.has(id)) next.delete(id); else next.add(id);
    setExpanded(next);
  };

  const resetFilters = () => {
    setSystemFilter('');
    setUserFilter('');
    setOperationFilter('');
    setAuditTypeFilter('');
    setFromDate('');
    setToDate('');
    setPage(1);
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <MainLayout>
        <Head>
          <title>Audit Logs | Praxis</title>
        </Head>
        <PageHeader
          title="Audit Logs"
          actions={
            <>
              <ExportButton
                endpoint="/api/backend/export/audits"
                filename="audits-export"
                params={{
                  ...(fromDate ? { from_date: new Date(fromDate).toISOString() } : {}),
                  ...(toDate ? { to_date: new Date(toDate).toISOString() } : {}),
                }}
              />
              <Button
                variant="outline"
                size="sm"
                onClick={() => load()}
                icon={<RefreshCw className="w-4 h-4" />}
              >
                Refresh
              </Button>
              <HelpLink slug="monitoring-and-alerts" />
            </>
          }
        />

        <Card>
          <CardBody>
            {/* Filters */}
            <div className="flex flex-wrap items-end gap-4 mb-4">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-gray-400" />
                <span className="text-sm text-gray-400">Filters:</span>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">System</label>
                <select
                  value={systemFilter}
                  onChange={(e) => { setSystemFilter(e.target.value); setPage(1); }}
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                >
                  <option value="">All</option>
                  {options?.systems.map((s) => (
                    <option key={s.id} value={s.id}>{s.hostname}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">User</label>
                <select
                  value={userFilter}
                  onChange={(e) => { setUserFilter(e.target.value); setPage(1); }}
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                >
                  <option value="">All</option>
                  {options?.users.map((u) => (
                    <option key={u.id} value={u.id}>{u.username}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Operation</label>
                <select
                  value={operationFilter}
                  onChange={(e) => { setOperationFilter(e.target.value); setPage(1); }}
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                >
                  <option value="">All</option>
                  {options?.operations.map((o) => (
                    <option key={o} value={o}>{o}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">Audit Type</label>
                <select
                  value={auditTypeFilter}
                  onChange={(e) => { setAuditTypeFilter(e.target.value); setPage(1); }}
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                >
                  <option value="">All</option>
                  {options?.audit_types.map((t) => (
                    <option key={t} value={t}>{t}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">From</label>
                <input
                  type="date"
                  value={fromDate}
                  onChange={(e) => { setFromDate(e.target.value); setPage(1); }}
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-gray-400 mb-1">To</label>
                <input
                  type="date"
                  value={toDate}
                  onChange={(e) => { setToDate(e.target.value); setPage(1); }}
                  className="bg-gray-950 border border-gray-800 rounded px-2 py-1 text-gray-200 text-sm"
                />
              </div>
              <Button variant="outline" size="sm" onClick={resetFilters}>
                Reset
              </Button>
            </div>

            {/* Table header */}
            <div className="grid grid-cols-12 gap-2 p-3 bg-gray-950 border-b border-gray-800 font-medium text-gray-200 text-sm rounded-t-lg">
              <div className="col-span-1"></div>
              <div className="col-span-2">Timestamp</div>
              <div className="col-span-2">User</div>
              <div className="col-span-2">System</div>
              <div className="col-span-2">Audit Type</div>
              <div className="col-span-1">Operation</div>
              <div className="col-span-2">Change</div>
            </div>

            {loading && <div className="p-4 text-gray-400">Loading...</div>}
            {!loading && items.length === 0 && (
              <EmptyState
                title="No audit entries"
                description="Audit entries appear here whenever a tracked field changes (system metadata, credential assignments, role grants, etc.). Try adjusting filters above."
              />
            )}

            {!loading && items.map((a, rowIdx) => {
              const isOpen = expanded.has(a.id);
              const isDestructive = a.operation === 'delete' || a.operation === 'DELETE';
              return (
                <div
                  key={a.id}
                  className={`border-b border-gray-800 ${isDestructive ? 'border-l-2 border-l-red-600/70' : 'border-l-2 border-l-transparent'} ${rowIdx % 2 === 1 ? 'bg-white/[0.012]' : ''}`}
                >
                  <div
                    className="grid grid-cols-12 gap-2 p-3 text-gray-300 hover:bg-gray-950/50 text-sm items-center cursor-pointer"
                    onClick={() => toggleExpanded(a.id)}
                  >
                    <div className="col-span-1">
                      {isOpen ? <ChevronDown className="w-4 h-4" /> : <ChevronRight className="w-4 h-4" />}
                    </div>
                    <div className="col-span-2">{a.changed_at ? formatTimestamp(a.changed_at) : '-'}</div>
                    <div className="col-span-2 truncate">{a.changed_by_username || `#${a.changed_by}`}</div>
                    <div className="col-span-2 truncate">{a.system_hostname || `#${a.system_id}`}</div>
                    <div className="col-span-2 truncate">{a.audit_type}</div>
                    <div className="col-span-1 truncate">{a.operation}</div>
                    <div className="col-span-2 truncate text-xs">
                      <span className="text-red-400">{truncate(a.old_value, 20)}</span>
                      <span className="text-gray-500 mx-1">&rarr;</span>
                      <span className="text-green-400">{truncate(a.new_value, 20)}</span>
                    </div>
                  </div>
                  {isOpen && (
                    <div className="p-4 bg-gray-950/50 border-t border-gray-800 text-sm">
                      <div className="grid grid-cols-2 gap-4">
                        <div>
                          <div className="text-xs text-gray-400 mb-1">Old Value</div>
                          <pre className="bg-gray-950 p-2 rounded border border-gray-800 text-red-300 whitespace-pre-wrap break-all">{a.old_value || '(none)'}</pre>
                        </div>
                        <div>
                          <div className="text-xs text-gray-400 mb-1">New Value</div>
                          <pre className="bg-gray-950 p-2 rounded border border-gray-800 text-green-300 whitespace-pre-wrap break-all">{a.new_value || '(none)'}</pre>
                        </div>
                      </div>
                    </div>
                  )}
                </div>
              );
            })}

            <div className="flex items-center justify-between pt-4">
              <span className="text-sm text-gray-400">
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
                <span className="text-sm text-gray-400 self-center">Page {page} of {totalPages}</span>
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

export default AuditLogs;
