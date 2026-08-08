import { useCallback, useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Plus, Play, RefreshCw, Shield, Trash2, Users, AlertTriangle } from 'lucide-react';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ConfirmModal,
  EmptyState,
  Modal,
  Select,
} from '@/components/ui';
import { apiFetch } from '../../utils/api';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import {
  AccessBinding,
  FleetRole,
  NewBindingPayload,
  createBinding,
  deleteBinding,
  listBindings,
  listFleetRoles,
  reconcileAll,
  recomputeGrants,
} from '../../services/fleetAccessService';
import EffectiveAccessCard from './EffectiveAccessCard';

interface UserBrief { id: number; username: string; email: string; }
interface RoleBrief { id: number; name: string; }
interface GroupBrief { id: number; name: string; }
interface SmartGroupBrief { id: number; name: string; }

type SubjectKind = 'user' | 'app_role';
type ScopeKind = 'group' | 'smart_group';

const FleetAccessTab = () => {
  const formatTimestamp = useFormatTimestamp();
  const [roles, setRoles] = useState<FleetRole[]>([]);
  const [bindings, setBindings] = useState<AccessBinding[]>([]);
  const [users, setUsers] = useState<UserBrief[]>([]);
  const [appRoles, setAppRoles] = useState<RoleBrief[]>([]);
  const [groups, setGroups] = useState<GroupBrief[]>([]);
  const [smartGroups, setSmartGroups] = useState<SmartGroupBrief[]>([]);
  const [loading, setLoading] = useState(true);
  const [reconciling, setReconciling] = useState(false);

  const [isCreateOpen, setIsCreateOpen] = useState(false);
  const [deleteCandidate, setDeleteCandidate] = useState<AccessBinding | null>(null);

  // Create dialog form state
  const [form, setForm] = useState({
    fleet_role_id: 0,
    subject_kind: 'user' as SubjectKind,
    subject_id: 0,
    scope_kind: 'group' as ScopeKind,
    scope_id: 0,
  });
  const [creating, setCreating] = useState(false);

  const loadAll = useCallback(async () => {
    setLoading(true);
    try {
      const [rolesData, bindingsData, usersRes, groupsRes, sgRes, appRolesRes] = await Promise.all([
        listFleetRoles(),
        listBindings(),
        apiFetch('/api/backend/users/').then(r => r.ok ? r.json() : { users: [] }),
        apiFetch('/api/backend/groups').then(r => r.ok ? r.json() : { groups: [] }),
        apiFetch('/api/backend/smart-groups').then(r => r.ok ? r.json() : { smart_groups: [] }),
        apiFetch('/api/backend/users/roles').then(r => r.ok ? r.json() : { roles: [] }),
      ]);
      setRoles(rolesData);
      setBindings(bindingsData);
      setUsers(Array.isArray(usersRes) ? usersRes : (usersRes.users || usersRes));
      setGroups(groupsRes.groups || groupsRes || []);
      setSmartGroups(sgRes.smart_groups || []);
      setAppRoles(appRolesRes.roles || appRolesRes || []);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load fleet access data');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { loadAll(); }, [loadAll]);

  const rolesById = useMemo(() => new Map(roles.map(r => [r.id, r])), [roles]);
  const usersById = useMemo(() => new Map(users.map(u => [u.id, u])), [users]);
  const appRolesById = useMemo(() => new Map(appRoles.map(r => [r.id, r])), [appRoles]);
  const groupsById = useMemo(() => new Map(groups.map(g => [g.id, g])), [groups]);
  const smartGroupsById = useMemo(() => new Map(smartGroups.map(g => [g.id, g])), [smartGroups]);

  const handleReconcile = async () => {
    setReconciling(true);
    try {
      const r = await reconcileAll();
      toast.success(
        `Reconciled ${r.hosts ?? 0} host(s) - ${r.provisioned} provisioned, ${r.removed} removed, ${r.errors} errors`,
      );
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Reconcile failed');
    } finally {
      setReconciling(false);
    }
  };

  const handleRecompute = async () => {
    try {
      const count = await recomputeGrants();
      toast.success(`Recomputed grants: ${count} rows`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Recompute failed');
    }
  };

  const openCreate = () => {
    setForm({
      fleet_role_id: roles[0]?.id || 0,
      subject_kind: 'user',
      subject_id: users[0]?.id || 0,
      scope_kind: 'group',
      scope_id: groups[0]?.id || 0,
    });
    setIsCreateOpen(true);
  };

  const handleCreate = async () => {
    if (!form.fleet_role_id || !form.subject_id || !form.scope_id) {
      toast.error('All fields are required');
      return;
    }
    const payload: NewBindingPayload = {
      fleet_role_id: form.fleet_role_id,
      subject_user_id: form.subject_kind === 'user' ? form.subject_id : null,
      subject_app_role_id: form.subject_kind === 'app_role' ? form.subject_id : null,
      scope_group_id: form.scope_kind === 'group' ? form.scope_id : null,
      scope_smart_group_id: form.scope_kind === 'smart_group' ? form.scope_id : null,
      enabled: true,
    };
    setCreating(true);
    try {
      const b = await createBinding(payload);
      setBindings(prev => [...prev, b]);
      toast.success('Binding created');
      setIsCreateOpen(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Create failed');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async () => {
    if (!deleteCandidate) return;
    try {
      await deleteBinding(deleteCandidate.id);
      setBindings(prev => prev.filter(b => b.id !== deleteCandidate.id));
      toast.success('Binding deleted');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Delete failed');
    } finally {
      setDeleteCandidate(null);
    }
  };

  const describeSubject = (b: AccessBinding): string => {
    if (b.subject_user_id) {
      const u = usersById.get(b.subject_user_id);
      return u ? `user: ${u.username}` : `user #${b.subject_user_id}`;
    }
    if (b.subject_app_role_id) {
      const r = appRolesById.get(b.subject_app_role_id);
      return r ? `role: ${r.name}` : `role #${b.subject_app_role_id}`;
    }
    return '-';
  };

  const describeScope = (b: AccessBinding): string => {
    if (b.scope_group_id) {
      const g = groupsById.get(b.scope_group_id);
      return g ? `group: ${g.name}` : `group #${b.scope_group_id}`;
    }
    if (b.scope_smart_group_id) {
      const g = smartGroupsById.get(b.scope_smart_group_id);
      return g ? `smart: ${g.name}` : `smart #${b.scope_smart_group_id}`;
    }
    return '-';
  };

  return (
    <div className="space-y-6">
      {/* Header + actions */}
      <div className="flex items-start justify-between gap-4">
        <div>
          <h2 className="text-lg font-semibold text-content flex items-center gap-2">
            <Shield size={18} /> Fleet Access
          </h2>
          <p className="text-sm text-content-muted mt-1 max-w-2xl">
            Define who can access which systems, as which Linux login, under which fleet role.
            Reconcile pushes the current state to every host: creates accounts, writes principals,
            removes revoked access with home directory archived. Fleet roles grant no standing
            sudo - privileged host work is done by Praxis automation, and root is out-of-band.
          </p>
        </div>
        <div className="flex gap-2 shrink-0">
          <Button variant="ghost" onClick={handleRecompute} disabled={loading}>
            <RefreshCw size={14} className="mr-1.5" />
            Recompute Grants
          </Button>
          <Button variant="primary" onClick={handleReconcile} disabled={loading || reconciling}>
            <Play size={14} className="mr-1.5" />
            {reconciling ? 'Reconciling…' : 'Reconcile All'}
          </Button>
        </div>
      </div>

      {/* Fleet roles */}
      <Card>
        <CardHeader>
          <div>
            <div>Fleet Roles</div>
            <div className="text-xs font-normal text-content-subtle mt-0.5">
              Permission bundles applied per-fleet. Built-in roles are managed by Praxis.
            </div>
          </div>
        </CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-content-subtle text-sm">Loading…</div>
          ) : roles.length === 0 ? (
            <EmptyState title="No fleet roles" description="No roles have been configured." icon={<Shield size={28} />} />
          ) : (
            <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
              {roles.map(r => (
                <div key={r.id} className="rounded-lg border border-border bg-black/40 p-4">
                  <div className="flex items-center justify-between">
                    <div className="flex items-center gap-2">
                      <h3 className="font-semibold text-content">{r.name}</h3>
                      {r.is_builtin && <Badge variant="info">built-in</Badge>}
                    </div>
                    <Badge variant={r.login_mode === 'per_user' ? 'success' : 'warning'}>
                      {r.login_mode === 'per_user' ? 'per-user' : `role: ${r.role_account_name}`}
                    </Badge>
                  </div>
                  {r.description && <p className="text-xs text-content-muted mt-2">{r.description}</p>}
                  <div className="mt-3 space-y-1 text-xs text-content-subtle">
                    <div>actions: <span className="text-content">{r.allowed_actions.join(', ') || 'none'}</span></div>
                    <div>os groups: <span className="text-content">{r.os_groups.join(', ') || '-'}</span></div>
                    <div>
                      approval: {r.session_requires_approval ? 'required' : 'no'} · totp: {r.totp_required ? 'required' : 'no'}
                    </div>
                  </div>
                </div>
              ))}
            </div>
          )}
        </CardBody>
      </Card>

      {/* Effective access (read-only, current state) */}
      <EffectiveAccessCard />

      {/* Access bindings */}
      <Card>
        <CardHeader
          action={
            <Button variant="primary" size="sm" onClick={openCreate} disabled={loading}>
              <Plus size={14} className="mr-1" /> New Binding
            </Button>
          }
        >
          <div>
            <div>Access Bindings</div>
            <div className="text-xs font-normal text-content-subtle mt-0.5">
              Grants a subject (user or app-role) access to a scope (group or smart group) under a fleet role.
            </div>
          </div>
        </CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-content-subtle text-sm">Loading…</div>
          ) : bindings.length === 0 ? (
            <EmptyState
              title="No bindings yet"
              description="App-admins automatically reach every host. For other users, create a binding."
              icon={<Users size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-content-subtle border-b border-border">
                    <th className="py-2 pr-4">Subject</th>
                    <th className="py-2 pr-4">Scope</th>
                    <th className="py-2 pr-4">Fleet Role</th>
                    <th className="py-2 pr-4">State</th>
                    <th className="py-2 pr-4">Expires</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {bindings.map(b => {
                    const role = rolesById.get(b.fleet_role_id);
                    return (
                      <tr key={b.id} className="border-b border-border hover:bg-white/5">
                        <td className="py-3 pr-4 text-content">{describeSubject(b)}</td>
                        <td className="py-3 pr-4 text-content">{describeScope(b)}</td>
                        <td className="py-3 pr-4">
                          <Badge variant="info">{role?.name || `#${b.fleet_role_id}`}</Badge>
                        </td>
                        <td className="py-3 pr-4">
                          <Badge variant={b.enabled ? 'success' : 'neutral'}>
                            {b.enabled ? 'enabled' : 'disabled'}
                          </Badge>
                        </td>
                        <td className="py-3 pr-4 text-content-muted text-xs">
                          {b.expires_at ? formatTimestamp(b.expires_at) : 'never'}
                        </td>
                        <td className="py-3 pr-4 text-right">
                          <button
                            onClick={() => setDeleteCandidate(b)}
                            className="p-1.5 rounded-md text-content-subtle hover:text-red-400 hover:bg-red-500/10"
                            aria-label="Delete binding"
                          >
                            <Trash2 size={14} />
                          </button>
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

      {/* Create binding modal */}
      <Modal open={isCreateOpen} onClose={() => setIsCreateOpen(false)} title="New Access Binding">
        <div className="space-y-4">
          <div>
            <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Subject</label>
            <div className="flex gap-2">
              <div className="w-40">
                <Select
                  value={form.subject_kind}
                  onChange={e => setForm(f => ({
                    ...f,
                    subject_kind: e.target.value as SubjectKind,
                    subject_id: (e.target.value === 'user' ? users[0]?.id : appRoles[0]?.id) || 0,
                  }))}
                >
                  <option value="user">User</option>
                  <option value="app_role">App Role</option>
                </Select>
              </div>
              <div className="flex-1">
                <Select
                  value={form.subject_id}
                  onChange={e => setForm(f => ({ ...f, subject_id: Number(e.target.value) }))}
                >
                  {form.subject_kind === 'user'
                    ? users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)
                    : appRoles.map(r => <option key={r.id} value={r.id}>{r.name}</option>)}
                </Select>
              </div>
            </div>
            {form.subject_kind === 'app_role' && (
              <p className="text-xs text-content-subtle mt-1">All users holding this app role will inherit the binding.</p>
            )}
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Scope</label>
            <div className="flex gap-2">
              <div className="w-40">
                <Select
                  value={form.scope_kind}
                  onChange={e => setForm(f => ({
                    ...f,
                    scope_kind: e.target.value as ScopeKind,
                    scope_id: (e.target.value === 'group' ? groups[0]?.id : smartGroups[0]?.id) || 0,
                  }))}
                >
                  <option value="group">Group</option>
                  <option value="smart_group">Smart Group</option>
                </Select>
              </div>
              <div className="flex-1">
                <Select
                  value={form.scope_id}
                  onChange={e => setForm(f => ({ ...f, scope_id: Number(e.target.value) }))}
                >
                  {form.scope_kind === 'group'
                    ? groups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)
                    : smartGroups.map(g => <option key={g.id} value={g.id}>{g.name}</option>)}
                </Select>
              </div>
            </div>
          </div>

          <div>
            <label className="block text-xs uppercase tracking-wide text-content-subtle mb-1">Fleet Role</label>
            <Select
              value={form.fleet_role_id}
              onChange={e => setForm(f => ({ ...f, fleet_role_id: Number(e.target.value) }))}
            >
              {roles.map(r => (
                <option key={r.id} value={r.id}>
                  {r.name} - {r.allowed_actions.join(', ') || 'no actions'}
                </option>
              ))}
            </Select>
          </div>

          <div className="rounded-md bg-amber-500/10 border border-amber-500/30 p-3 flex gap-2 text-xs text-amber-200">
            <AlertTriangle size={14} className="mt-0.5 shrink-0" />
            <div>
              Host accounts are created on next reconcile. Removing a binding archives home directories
              and deletes accounts on the next reconcile.
            </div>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" onClick={() => setIsCreateOpen(false)} disabled={creating}>
              Cancel
            </Button>
            <Button variant="primary" onClick={handleCreate} disabled={creating}>
              {creating ? 'Creating…' : 'Create Binding'}
            </Button>
          </div>
        </div>
      </Modal>

      {/* Delete confirmation */}
      <ConfirmModal
        open={deleteCandidate !== null}
        onClose={() => setDeleteCandidate(null)}
        onConfirm={handleDelete}
        title="Delete binding"
        message="Revokes access. Affected host accounts will be removed on next reconcile (home directory archived)."
        confirmLabel="Delete"
        variant="danger"
      />
    </div>
  );
};

export default FleetAccessTab;
