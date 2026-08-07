import { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import { Plus, Send, Trash2 } from 'lucide-react';
import { Badge, Button, Card, CardBody, CardHeader, ConfirmModal, EmptyState, Input, Modal, Select } from '@/components/ui';
import {
  AuditDelivery,
  AuditSink,
  NewAuditSink,
  createAuditSink,
  deleteAuditSink,
  listAuditSinks,
  listSinkDeliveries,
  retryDelivery,
} from '../../services/auditService';

const kindLabels: Record<AuditSink['kind'], string> = {
  syslog: 'Syslog (RFC 5424 over TCP/TLS)',
  http: 'HTTP JSON (HMAC-signed)',
  file: 'Local file (JSONL)',
};

const AuditExportTab = () => {
  const [sinks, setSinks] = useState<AuditSink[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [deleteTarget, setDeleteTarget] = useState<AuditSink | null>(null);

  const [form, setForm] = useState<NewAuditSink>({
    name: '',
    kind: 'http',
    target: '',
    hmac_secret: '',
    enabled: true,
  });

  const [deliveriesSink, setDeliveriesSink] = useState<AuditSink | null>(null);
  const [deliveries, setDeliveries] = useState<AuditDelivery[]>([]);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setSinks(await listAuditSinks());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Load failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const loadDeliveries = useCallback(async (sink: AuditSink) => {
    try {
      setDeliveries(await listSinkDeliveries(sink.id));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Load deliveries failed');
    }
  }, []);

  useEffect(() => {
    if (deliveriesSink) loadDeliveries(deliveriesSink);
  }, [deliveriesSink, loadDeliveries]);

  const handleCreate = async () => {
    if (!form.name || !form.target) {
      toast.error('Name and target are required');
      return;
    }
    try {
      await createAuditSink({
        ...form,
        hmac_secret: form.hmac_secret || null,
      });
      toast.success('Sink created');
      setShowNew(false);
      setForm({ name: '', kind: 'http', target: '', hmac_secret: '', enabled: true });
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Create failed');
    }
  };

  const handleDelete = async () => {
    if (!deleteTarget) return;
    try {
      await deleteAuditSink(deleteTarget.id);
      toast.success('Sink deleted');
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setDeleteTarget(null);
    }
  };

  const handleRetry = async (id: number) => {
    try {
      await retryDelivery(id);
      toast.success('Retry queued');
      if (deliveriesSink) await loadDeliveries(deliveriesSink);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Retry failed');
    }
  };

  const targetHelp = (kind: AuditSink['kind']) => {
    switch (kind) {
      case 'syslog': return 'host:port - defaults to 6514 if no port';
      case 'http': return 'https://siem.example/audit-ingest';
      case 'file': return '/var/log/praxis/audit.jsonl';
    }
  };

  return (
    <div className="space-y-4">
      <Card>
        <CardHeader
          action={
            <Button variant="primary" size="sm" onClick={() => setShowNew(true)}>
              <Plus size={14} className="mr-1" /> New sink
            </Button>
          }
        >
          <div>
            <div>Audit Export Sinks</div>
            <div className="text-xs font-normal text-gray-500 mt-0.5">
              Forward every audit event to an external system. Retry + dead-letter are built in.
            </div>
          </div>
        </CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-gray-500 text-sm">Loading…</div>
          ) : sinks.length === 0 ? (
            <EmptyState title="No sinks configured" description="Events are persisted in the built-in audit log either way." icon={<Send size={28} />} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-gray-500 border-b border-gray-800">
                    <th className="py-2 pr-4">Name</th>
                    <th className="py-2 pr-4">Kind</th>
                    <th className="py-2 pr-4">Target</th>
                    <th className="py-2 pr-4">HMAC</th>
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4 text-right" />
                  </tr>
                </thead>
                <tbody>
                  {sinks.map(s => (
                    <tr key={s.id} className="border-b border-gray-900 hover:bg-white/5">
                      <td className="py-2 pr-4 text-gray-200">{s.name}</td>
                      <td className="py-2 pr-4"><Badge variant="info">{s.kind}</Badge></td>
                      <td className="py-2 pr-4 font-mono text-xs text-gray-400 truncate max-w-xs">{s.target}</td>
                      <td className="py-2 pr-4 text-xs">
                        {s.hmac_secret_set ? <Badge variant="success">set</Badge> : <span className="text-gray-500">-</span>}
                      </td>
                      <td className="py-2 pr-4">
                        <Badge variant={s.enabled ? 'success' : 'neutral'}>{s.enabled ? 'enabled' : 'disabled'}</Badge>
                      </td>
                      <td className="py-2 pr-4 text-right">
                        <div className="flex gap-1 justify-end">
                          <button
                            onClick={() => setDeliveriesSink(s)}
                            aria-label="Deliveries"
                            className="p-1.5 rounded-md text-gray-500 hover:text-gray-200 hover:bg-white/5"
                          >
                            <Send size={14} />
                          </button>
                          <button
                            onClick={() => setDeleteTarget(s)}
                            aria-label="Delete"
                            className="p-1.5 rounded-md text-gray-500 hover:text-red-400 hover:bg-red-500/10"
                          >
                            <Trash2 size={14} />
                          </button>
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

      {/* New sink modal */}
      <Modal open={showNew} onClose={() => setShowNew(false)} title="New audit sink" maxWidth="max-w-lg">
        <div className="space-y-3">
          <div>
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Name</label>
            <Input value={form.name} onChange={e => setForm(f => ({ ...f, name: e.target.value }))} placeholder="prod-siem" />
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Kind</label>
            <Select value={form.kind} onChange={e => setForm(f => ({ ...f, kind: e.target.value as AuditSink['kind'] }))}>
              {Object.entries(kindLabels).map(([k, v]) => <option key={k} value={k}>{v}</option>)}
            </Select>
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Target</label>
            <Input value={form.target} onChange={e => setForm(f => ({ ...f, target: e.target.value }))} placeholder={targetHelp(form.kind)} />
          </div>
          {form.kind === 'http' && (
            <div>
              <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">HMAC secret (optional)</label>
              <Input
                type="password"
                value={form.hmac_secret || ''}
                onChange={e => setForm(f => ({ ...f, hmac_secret: e.target.value }))}
                placeholder="receiver uses this to verify X-Praxis-Signature"
              />
            </div>
          )}
          <div className="flex justify-end gap-2">
            <Button variant="ghost" size="sm" onClick={() => setShowNew(false)}>Cancel</Button>
            <Button variant="primary" size="sm" onClick={handleCreate}>Create</Button>
          </div>
        </div>
      </Modal>

      {/* Deliveries modal */}
      <Modal open={deliveriesSink !== null} onClose={() => { setDeliveriesSink(null); setDeliveries([]); }} title={`${deliveriesSink?.name} - recent deliveries`} maxWidth="max-w-3xl">
        {deliveries.length === 0 ? (
          <div className="text-gray-500 text-sm py-4 text-center">No deliveries yet.</div>
        ) : (
          <div className="overflow-x-auto max-h-96">
            <table className="w-full text-xs">
              <thead>
                <tr className="text-left uppercase tracking-wide text-gray-500 border-b border-gray-800">
                  <th className="py-2 pr-3">Event</th>
                  <th className="py-2 pr-3">Status</th>
                  <th className="py-2 pr-3">Attempts</th>
                  <th className="py-2 pr-3">Error</th>
                  <th className="py-2 pr-3 text-right" />
                </tr>
              </thead>
              <tbody>
                {deliveries.map(d => (
                  <tr key={d.id} className="border-b border-gray-900">
                    <td className="py-2 pr-3 font-mono text-gray-400">#{d.event_id}</td>
                    <td className="py-2 pr-3">
                      <Badge variant={d.status === 'delivered' ? 'success' : d.status === 'dead_letter' ? 'danger' : d.status === 'pending' ? 'warning' : 'neutral'}>
                        {d.status}
                      </Badge>
                    </td>
                    <td className="py-2 pr-3 text-gray-400">{d.attempts}</td>
                    <td className="py-2 pr-3 text-red-300 truncate max-w-xs">{d.last_error || '-'}</td>
                    <td className="py-2 pr-3 text-right">
                      {d.status === 'dead_letter' && (
                        <Button size="sm" variant="ghost" onClick={() => handleRetry(d.id)}>Retry</Button>
                      )}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </Modal>

      <ConfirmModal
        open={deleteTarget !== null}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDelete}
        title="Delete audit sink"
        message={`Delete sink '${deleteTarget?.name}'? Events stop forwarding immediately; already-delivered events are retained on the receiver.`}
        confirmLabel="Delete"
        variant="danger"
      />
    </div>
  );
};

export default AuditExportTab;
