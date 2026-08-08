import { useCallback, useEffect, useMemo, useState } from 'react';
import Head from 'next/head';
import { toast } from 'sonner';
import { FileSearch, Filter } from 'lucide-react';
import MainLayout from '../components/MainLayout';
import { Badge, Button, Card, CardBody, CardHeader, EmptyState, Input, Modal, Select } from '@/components/ui';
import { AuditEvent, listAuditEvents } from '../services/auditService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const outcomeVariant = (o: AuditEvent['outcome']) => {
  switch (o) {
    case 'success': return 'success';
    case 'failure': return 'warning';
    case 'denied': return 'danger';
    default: return 'neutral';
  }
};

const AuditPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const [events, setEvents] = useState<AuditEvent[]>([]);
  const [total, setTotal] = useState(0);
  const [loading, setLoading] = useState(true);
  const [selected, setSelected] = useState<AuditEvent | null>(null);

  const [filters, setFilters] = useState({
    action: '',
    outcome: '',
    actor_user_id: '',
    system_id: '',
  });

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params: Record<string, string | number> = { limit: 200 };
      if (filters.action) params.action = filters.action;
      if (filters.outcome) params.outcome = filters.outcome;
      if (filters.actor_user_id) params.actor_user_id = Number(filters.actor_user_id);
      if (filters.system_id) params.system_id = Number(filters.system_id);
      const res = await listAuditEvents(params);
      setEvents(res.events);
      setTotal(res.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load audit events');
    } finally {
      setLoading(false);
    }
  }, [filters]);

  useEffect(() => { load(); }, [load]);

  const actions = useMemo(() => {
    const set = new Set(events.map(e => e.action));
    return Array.from(set).sort();
  }, [events]);

  return (
    <MainLayout>
      <Head><title>Audit Log | Praxis</title></Head>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-content flex items-center gap-2">
            <FileSearch size={18} /> Audit Log
          </h1>
          <p className="text-sm text-content-muted mt-1">
            Every security-relevant action emits a structured event. See{' '}
            <code className="font-mono text-content">docs/audit-schema.md</code> for the wire format.
            Configure external sinks (syslog / HTTP / file) under Settings → Audit Export.
          </p>
        </div>
        <div className="text-xs text-content-subtle">{total.toLocaleString()} total events</div>
      </div>

      <Card className="mb-4">
        <CardHeader>
          <div className="flex items-center gap-2 text-sm">
            <Filter size={14} /> Filters
          </div>
        </CardHeader>
        <CardBody>
          <div className="grid grid-cols-1 md:grid-cols-4 gap-3">
            <div>
              <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Action</label>
              <Select value={filters.action} onChange={e => setFilters(f => ({ ...f, action: e.target.value }))}>
                <option value="">All</option>
                {actions.map(a => <option key={a} value={a}>{a}</option>)}
              </Select>
            </div>
            <div>
              <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Outcome</label>
              <Select value={filters.outcome} onChange={e => setFilters(f => ({ ...f, outcome: e.target.value }))}>
                <option value="">All</option>
                <option value="success">Success</option>
                <option value="failure">Failure</option>
                <option value="denied">Denied</option>
              </Select>
            </div>
            <div>
              <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Actor User ID</label>
              <Input type="number" value={filters.actor_user_id} onChange={e => setFilters(f => ({ ...f, actor_user_id: e.target.value }))} />
            </div>
            <div>
              <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">System ID</label>
              <Input type="number" value={filters.system_id} onChange={e => setFilters(f => ({ ...f, system_id: e.target.value }))} />
            </div>
          </div>
        </CardBody>
      </Card>

      <Card>
        <CardBody>
          {loading ? (
            <div className="text-content-subtle text-sm">Loading…</div>
          ) : events.length === 0 ? (
            <EmptyState title="No events" description="No audit events match the current filters." icon={<FileSearch size={28} />} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-content-subtle border-b border-border">
                    <th className="py-2 pr-4">Time</th>
                    <th className="py-2 pr-4">Action</th>
                    <th className="py-2 pr-4">Outcome</th>
                    <th className="py-2 pr-4">Actor</th>
                    <th className="py-2 pr-4">Target</th>
                  </tr>
                </thead>
                <tbody>
                  {events.map(e => (
                    <tr
                      key={e.event_uuid}
                      onClick={() => setSelected(e)}
                      className="border-b border-border hover:bg-white/5 cursor-pointer"
                    >
                      <td className="py-2 pr-4 text-xs text-content-muted">
                        {e.timestamp ? formatTimestamp(e.timestamp) : '-'}
                      </td>
                      <td className="py-2 pr-4 font-mono text-xs text-content">{e.action}</td>
                      <td className="py-2 pr-4"><Badge variant={outcomeVariant(e.outcome)}>{humanizeStatus(e.outcome)}</Badge></td>
                      <td className="py-2 pr-4 text-xs text-content-muted">
                        {e.actor.username ? (
                          <span className="font-mono">{e.actor.username}</span>
                        ) : '-'}
                        {e.actor.ip && <span className="ml-2 text-content-subtle">{e.actor.ip}</span>}
                      </td>
                      <td className="py-2 pr-4 text-xs text-content-muted">
                        {e.target.kind && <span className="text-content-subtle">{e.target.kind}:</span>}{' '}
                        {e.target.id || '-'}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      <Modal open={selected !== null} onClose={() => setSelected(null)} title="Event detail" maxWidth="max-w-2xl">
        <pre className="text-xs font-mono text-content whitespace-pre-wrap break-words max-h-96 overflow-auto">
          {selected ? JSON.stringify(selected, null, 2) : ''}
        </pre>
        <div className="flex justify-end mt-3">
          <Button variant="ghost" size="sm" onClick={() => setSelected(null)}>Close</Button>
        </div>
      </Modal>
    </MainLayout>
  );
};

export default AuditPage;
