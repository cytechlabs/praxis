import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Plus, Check, X, Clock } from 'lucide-react';
import Head from 'next/head';
import MainLayout from '../components/MainLayout';
import { useAuth } from '../context/AuthContext';
import { Badge, Button, Card, CardBody, CardHeader, EmptyState, Input, Modal, Select } from '@/components/ui';
import {
  AccessRequest,
  approveAccessRequest,
  createAccessRequest,
  listAccessRequests,
  rejectAccessRequest,
  revokeAccessRequest,
} from '../services/accessRequestService';
import { FleetRole, listFleetRoles } from '../services/fleetAccessService';
import { apiFetch } from '../utils/api';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

interface GroupBrief { id: number; name: string; }
interface SmartGroupBrief { id: number; name: string; }

const statusVariant = (s: AccessRequest['status']) => {
  switch (s) {
    case 'pending': return 'warning';
    case 'approved': return 'success';
    case 'rejected': return 'danger';
    case 'expired': return 'neutral';
    case 'revoked': return 'neutral';
    default: return 'neutral';
  }
};

const fmtDuration = (seconds: number) => {
  const h = Math.floor(seconds / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (h >= 1) return `${h}h${m ? ` ${m}m` : ''}`;
  return `${m}m`;
};

const AccessRequestsPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const { isAdmin } = useAuth();
  const [viewAll, setViewAll] = useState(false);
  const [rows, setRows] = useState<AccessRequest[]>([]);
  const [roles, setRoles] = useState<FleetRole[]>([]);
  const [groups, setGroups] = useState<GroupBrief[]>([]);
  const [smartGroups, setSmartGroups] = useState<SmartGroupBrief[]>([]);
  const [loading, setLoading] = useState(true);
  const [showNew, setShowNew] = useState(false);
  const [form, setForm] = useState({
    fleet_role_id: 0,
    scope_kind: 'group' as 'group' | 'smart_group',
    scope_id: 0,
    duration_hours: 1,
    justification: '',
  });
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const [reqs, rolesData, groupsRes, sgRes] = await Promise.all([
        listAccessRequests({ mine_only: !viewAll }),
        listFleetRoles(),
        apiFetch('/api/backend/groups').then(r => r.ok ? r.json() : { groups: [] }),
        apiFetch('/api/backend/smart-groups').then(r => r.ok ? r.json() : { smart_groups: [] }),
      ]);
      setRows(reqs);
      setRoles(rolesData);
      setGroups(groupsRes.groups || groupsRes || []);
      setSmartGroups(sgRes.smart_groups || []);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [viewAll]);

  useEffect(() => { load(); }, [load]);

  const rolesById = useMemo(() => new Map(roles.map(r => [r.id, r])), [roles]);
  const groupsById = useMemo(() => new Map(groups.map(g => [g.id, g])), [groups]);
  const sgById = useMemo(() => new Map(smartGroups.map(g => [g.id, g])), [smartGroups]);

  const openNew = () => {
    setForm({
      fleet_role_id: roles[0]?.id || 0,
      scope_kind: 'group',
      scope_id: groups[0]?.id || 0,
      duration_hours: 1,
      justification: '',
    });
    setShowNew(true);
  };

  const handleSubmit = async () => {
    if (!form.fleet_role_id || !form.scope_id) {
      toast.error('Role and scope are required');
      return;
    }
    setSubmitting(true);
    try {
      await createAccessRequest({
        fleet_role_id: form.fleet_role_id,
        scope_group_id: form.scope_kind === 'group' ? form.scope_id : null,
        scope_smart_group_id: form.scope_kind === 'smart_group' ? form.scope_id : null,
        justification: form.justification.trim() || null,
        duration_seconds: Math.round(form.duration_hours * 3600),
      });
      toast.success('Access request submitted');
      setShowNew(false);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Submit failed');
    } finally {
      setSubmitting(false);
    }
  };

  const handleApprove = async (id: number) => {
    try { await approveAccessRequest(id); toast.success('Approved'); await load(); }
    catch (e) { toast.error(e instanceof Error ? e.message : 'Approve failed'); }
  };
  const handleReject = async (id: number) => {
    try { await rejectAccessRequest(id); toast.success('Rejected'); await load(); }
    catch (e) { toast.error(e instanceof Error ? e.message : 'Reject failed'); }
  };
  const handleRevoke = async (id: number) => {
    try { await revokeAccessRequest(id); toast.success('Revoked'); await load(); }
    catch (e) { toast.error(e instanceof Error ? e.message : 'Revoke failed'); }
  };

  const scopeLabel = (r: AccessRequest) => {
    if (r.scope_group_id) return `group: ${groupsById.get(r.scope_group_id)?.name || `#${r.scope_group_id}`}`;
    if (r.scope_smart_group_id) return `smart: ${sgById.get(r.scope_smart_group_id)?.name || `#${r.scope_smart_group_id}`}`;
    return '-';
  };

  return (
    <MainLayout>
      <Head><title>Access Requests | Praxis</title></Head>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-gray-100">Access Requests</h1>
          <p className="text-sm text-gray-400 mt-1">
            Request time-bound access to fleet groups. Approval grants an access binding that auto-expires.
          </p>
        </div>
        <div className="flex gap-2">
          {isAdmin && (
            <Button variant={viewAll ? 'primary' : 'outline'} size="sm" onClick={() => setViewAll(v => !v)}>
              {viewAll ? 'Showing all' : 'My requests only'}
            </Button>
          )}
          <Button variant="primary" size="sm" onClick={openNew}>
            <Plus size={14} className="mr-1" /> New request
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>Requests</CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-gray-500 text-sm">Loading…</div>
          ) : rows.length === 0 ? (
            <EmptyState
              title="No requests"
              description={viewAll ? 'No access requests in the system yet.' : 'You have not submitted any access requests.'}
              icon={<Clock size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-gray-500 border-b border-gray-800">
                    <th className="py-2 pr-4">Scope</th>
                    <th className="py-2 pr-4">Role</th>
                    <th className="py-2 pr-4">Duration</th>
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4">Requested</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map(r => {
                    const role = rolesById.get(r.fleet_role_id);
                    return (
                      <tr key={r.id} className="border-b border-gray-900 hover:bg-white/5">
                        <td className="py-3 pr-4 text-gray-300">{scopeLabel(r)}</td>
                        <td className="py-3 pr-4"><Badge variant="info">{role?.name || `#${r.fleet_role_id}`}</Badge></td>
                        <td className="py-3 pr-4 text-gray-400">{fmtDuration(r.duration_seconds)}</td>
                        <td className="py-3 pr-4"><Badge variant={statusVariant(r.status)}>{humanizeStatus(r.status)}</Badge></td>
                        <td className="py-3 pr-4 text-xs text-gray-500">{formatTimestamp(r.requested_at)}</td>
                        <td className="py-3 pr-4 text-right">
                          {isAdmin && r.status === 'pending' && (
                            <div className="flex gap-1 justify-end">
                              <button onClick={() => handleApprove(r.id)} aria-label="Approve" className="p-1.5 rounded-md text-gray-500 hover:text-emerald-400 hover:bg-emerald-500/10">
                                <Check size={14} />
                              </button>
                              <button onClick={() => handleReject(r.id)} aria-label="Reject" className="p-1.5 rounded-md text-gray-500 hover:text-red-400 hover:bg-red-500/10">
                                <X size={14} />
                              </button>
                            </div>
                          )}
                          {isAdmin && r.status === 'approved' && (
                            <button onClick={() => handleRevoke(r.id)} aria-label="Revoke" className="p-1.5 rounded-md text-gray-500 hover:text-red-400 hover:bg-red-500/10">
                              <X size={14} />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      <Modal open={showNew} onClose={() => setShowNew(false)} title="Request access">
        <div className="space-y-4">
          <div>
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Fleet role</label>
            <Select value={form.fleet_role_id} onChange={e => setForm(f => ({ ...f, fleet_role_id: Number(e.target.value) }))}>
              {roles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
            </Select>
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Scope</label>
            <div className="flex gap-2">
              <div className="w-40">
                <Select
                  value={form.scope_kind}
                  onChange={e => setForm(f => ({
                    ...f,
                    scope_kind: e.target.value as 'group' | 'smart_group',
                    scope_id: (e.target.value === 'group' ? groups[0]?.id : smartGroups[0]?.id) || 0,
                  }))}
                >
                  <option value="group">Group</option>
                  <option value="smart_group">Smart Group</option>
                </Select>
              </div>
              <div className="flex-1">
                <Select value={form.scope_id} onChange={e => setForm(f => ({ ...f, scope_id: Number(e.target.value) }))}>
                  {form.scope_kind === 'group'
                    ? groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)
                    : smartGroups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                </Select>
              </div>
            </div>
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Duration (hours)</label>
            <Input
              type="number"
              min={0.25}
              max={168}
              step={0.25}
              value={form.duration_hours}
              onChange={e => setForm(f => ({ ...f, duration_hours: Number(e.target.value) }))}
            />
            <p className="text-xs text-gray-500 mt-1">5 min minimum, 7 days maximum.</p>
          </div>
          <div>
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Justification</label>
            <textarea
              value={form.justification}
              onChange={e => setForm(f => ({ ...f, justification: e.target.value }))}
              rows={3}
              className="w-full bg-gray-900/50 border border-gray-700 rounded-md text-sm text-gray-200 px-3 py-2 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
              placeholder="Why do you need this access? (optional but helpful)"
            />
          </div>
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" size="sm" onClick={() => setShowNew(false)} disabled={submitting}>Cancel</Button>
            <Button variant="primary" size="sm" onClick={handleSubmit} disabled={submitting} loading={submitting}>Submit</Button>
          </div>
        </div>
      </Modal>
    </MainLayout>
  );
};

export default AccessRequestsPage;
