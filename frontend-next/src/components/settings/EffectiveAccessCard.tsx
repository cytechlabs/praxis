import { useEffect, useMemo, useState } from 'react';
import { toast } from 'sonner';
import { Eye, AlertTriangle, ShieldCheck, ShieldX } from 'lucide-react';
import { Badge, Button, Card, CardBody, CardHeader, Select } from '@/components/ui';
import { apiFetch } from '../../utils/api';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { fetchAllSystems } from '../../services/systemService';
import {
  EACapability,
  EALoginDetail,
  EffectiveAccessSummary,
  getEffectiveAccess,
} from '../../services/fleetAccessService';

interface UserBrief { id: number; username: string; }
interface SystemBrief { id: number; hostname: string; }

const ACTION_LABEL: Record<string, string> = {
  session_open: 'Open session',
  command_exec: 'Run command',
  file_transfer: 'File transfer',
};

const CapabilityRow = ({ cap }: { cap: EACapability }) => (
  <div className="flex items-start justify-between gap-3 rounded border border-gray-800 bg-black/30 px-3 py-2">
    <div className="min-w-0">
      <div className="flex items-center gap-2">
        {cap.allowed ? (
          <Badge variant="success">allowed</Badge>
        ) : (
          <Badge variant="danger">denied</Badge>
        )}
        <span className="text-sm text-gray-200">
          {ACTION_LABEL[cap.action] ?? cap.action}
        </span>
        {cap.login && (
          <span className="text-xs text-gray-500">
            as <span className="font-mono text-gray-300">{cap.login}</span>
          </span>
        )}
      </div>
      {cap.allowed ? (
        <div className="mt-1 text-xs text-gray-500 space-x-2">
          {cap.fleet_role_name && <span>role: <span className="text-gray-300">{cap.fleet_role_name}</span></span>}
          {cap.requires_approval && <Badge variant="warning">requires approval</Badge>}
          {cap.requires_totp && <Badge variant="warning">requires TOTP</Badge>}
          {typeof cap.max_session_s === 'number' && (
            <span>max session: <span className="text-gray-300">{Math.round(cap.max_session_s / 60)}m</span></span>
          )}
          {typeof cap.recording_retention_days === 'number' && (
            <span>recording kept: <span className="text-gray-300">{cap.recording_retention_days}d</span></span>
          )}
        </div>
      ) : (
        <div className="mt-1 text-xs text-red-400/80">
          {cap.code && <span className="font-mono">{cap.code}</span>}
          {cap.reason && <span className="text-gray-500"> - {cap.reason}</span>}
        </div>
      )}
    </div>
  </div>
);

const hostBadge = (d: EALoginDetail) => {
  const s = d.host_state.state;
  if (s === 'provisioned' && d.host_state.converged) return <Badge variant="success">converged</Badge>;
  if (s === 'not_provisioned') return <Badge variant="warning">not provisioned</Badge>;
  if (s === 'error') return <Badge variant="danger">host error</Badge>;
  return <Badge variant="info">{s}</Badge>;
};

const LoginDetail = ({ d }: { d: EALoginDetail }) => {
  const formatTimestamp = useFormatTimestamp();
  return (
  <div className="rounded border border-gray-800 bg-black/30 p-3">
    <div className="flex items-center justify-between gap-2 flex-wrap">
      <div className="flex items-center gap-2">
        <span className="font-mono text-sm text-gray-200">{d.login}</span>
        <Badge variant={d.login_mode === 'per_user' ? 'success' : 'warning'}>
          {d.login_mode === 'role_account' ? `role: ${d.role_account_name ?? d.login}` : d.login_mode ?? 'unresolved'}
        </Badge>
        {d.resolved_fleet_role_name && (
          <span className="text-xs text-gray-500">role: <span className="text-gray-300">{d.resolved_fleet_role_name}</span></span>
        )}
      </div>
      <div className="flex items-center gap-2">
        {hostBadge(d)}
        {(d.revocation.pending > 0 || d.revocation.error > 0) && (
          <Badge variant="warning">
            reconcile pending: {d.revocation.pending + d.revocation.error}
          </Badge>
        )}
      </div>
    </div>
    <div className="mt-2 text-xs text-gray-500 space-x-3">
      <span>expiry: <span className="text-gray-300">{d.expiry_state}</span>{d.nearest_active_expiry ? ` (next ${formatTimestamp(d.nearest_active_expiry)})` : ''}</span>
      <span>active grants: <span className="text-gray-300">{d.active_grants.length}</span></span>
      {d.expired_grants.length > 0 && <span>expired: <span className="text-gray-400">{d.expired_grants.length}</span></span>}
      {d.host_state.last_error && <span className="text-red-400/80">host: {d.host_state.last_error}</span>}
    </div>
    {d.conflict && (
      <div className="mt-2 flex items-start gap-2 rounded border border-red-900/60 bg-red-950/30 px-2 py-1.5 text-xs text-red-300">
        <AlertTriangle size={14} className="mt-0.5 shrink-0" />
        <span>
          Shared-login conflict on <span className="font-mono">{d.conflict.login}</span> - roles{' '}
          {d.conflict.role_names.join(', ')} differ on {d.conflict.differing_fields.join(', ')}. Access fails closed until bindings are fixed.
        </span>
      </div>
    )}
  </div>
  );
};

const EffectiveAccessCard = () => {
  const [users, setUsers] = useState<UserBrief[]>([]);
  const [systems, setSystems] = useState<SystemBrief[]>([]);
  const [userId, setUserId] = useState<number>(0);
  const [systemId, setSystemId] = useState<number>(0);
  const [login, setLogin] = useState<string>('');
  const [summary, setSummary] = useState<EffectiveAccessSummary | null>(null);
  const [loading, setLoading] = useState(false);

  useEffect(() => {
    (async () => {
      try {
        const [usersRes, sysRes] = await Promise.all([
          apiFetch('/api/backend/users/').then(r => (r.ok ? r.json() : { users: [] })),
          fetchAllSystems().catch(() => []),
        ]);
        const u: UserBrief[] = Array.isArray(usersRes) ? usersRes : usersRes.users || [];
        setUsers(u);
        setSystems((sysRes as SystemBrief[]) || []);
        if (u[0]) setUserId(u[0].id);
        if ((sysRes as SystemBrief[])[0]) setSystemId((sysRes as SystemBrief[])[0].id);
      } catch {
        /* selectors stay empty; the load button will surface errors */
      }
    })();
  }, []);

  const load = async () => {
    if (!userId || !systemId) {
      toast.error('Select a user and a system');
      return;
    }
    setLoading(true);
    try {
      const s = await getEffectiveAccess({ userId, systemId, login: login.trim() || undefined });
      setSummary(s);
    } catch (err) {
      setSummary(null);
      toast.error(err instanceof Error ? err.message : 'Failed to load effective access');
    } finally {
      setLoading(false);
    }
  };

  const conflictBanner = useMemo(
    () => summary && summary.conflicts.length > 0,
    [summary],
  );

  return (
    <Card>
      <CardHeader>
        <div>
          <div className="flex items-center gap-2"><Eye size={16} /> Effective Access</div>
          <div className="text-xs font-normal text-gray-500 mt-0.5">
            Current enforced access for a user on a host - what they can do right now and why.
            Read-only; computed by the live authorization path (no simulation, no changes made).
          </div>
        </div>
      </CardHeader>
      <CardBody>
        <div className="flex flex-wrap items-end gap-3">
          <div className="min-w-[12rem]">
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">User</label>
            <Select value={userId} onChange={e => setUserId(Number(e.target.value))}>
              {users.map(u => <option key={u.id} value={u.id}>{u.username}</option>)}
            </Select>
          </div>
          <div className="min-w-[14rem]">
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">System</label>
            <Select value={systemId} onChange={e => setSystemId(Number(e.target.value))}>
              {systems.map(s => <option key={s.id} value={s.id}>{s.hostname}</option>)}
            </Select>
          </div>
          <div className="min-w-[10rem]">
            <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Login (optional)</label>
            <input
              value={login}
              onChange={e => setLogin(e.target.value)}
              placeholder="all logins"
              className="w-full rounded-md border border-gray-700 bg-black/40 px-3 py-2 text-sm text-gray-200 placeholder-gray-600 focus:border-gray-500 focus:outline-none"
            />
          </div>
          <Button variant="primary" onClick={load} disabled={loading}>
            <Eye size={14} className="mr-1.5" />
            {loading ? 'Loading…' : 'Show current access'}
          </Button>
        </div>

        {summary && (
          <div className="mt-5 space-y-4">
            {/* Identity + scope */}
            <div className="rounded-lg border border-gray-800 bg-black/40 p-3">
              <div className="flex flex-wrap items-center gap-2">
                <span className="text-sm text-gray-200">{summary.identity.username}</span>
                {summary.identity.is_active ? (
                  <Badge variant="success">active</Badge>
                ) : (
                  <Badge variant="danger">deactivated</Badge>
                )}
                {summary.identity.is_tenant_admin && <Badge variant="info">app admin</Badge>}
                {summary.scoped_api_access.allowed ? (
                  <span className="inline-flex items-center gap-1 text-xs text-green-400"><ShieldCheck size={13} /> fleet visibility</span>
                ) : (
                  <span className="inline-flex items-center gap-1 text-xs text-gray-500"><ShieldX size={13} /> no fleet visibility</span>
                )}
              </div>
              <div className="mt-1 text-xs text-gray-500">
                on <span className="text-gray-300">{summary.system.hostname}</span> ·
                {' '}cert principal <span className="font-mono text-gray-300">{summary.identity.cert_principal}</span> ·
                {' '}overall expiry <span className="text-gray-300">{summary.expiry.overall_state}</span>
              </div>
            </div>

            {conflictBanner && (
              <div className="flex items-start gap-2 rounded-lg border border-red-900/60 bg-red-950/30 p-3 text-sm text-red-300">
                <AlertTriangle size={16} className="mt-0.5 shrink-0" />
                <span>
                  {summary.conflicts.length} shared-login conflict(s) on this host. Affected actions
                  fail closed with <span className="font-mono">login_conflict</span> until the
                  conflicting bindings/roles are fixed.
                </span>
              </div>
            )}

            {/* Capabilities */}
            <div>
              <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">Capabilities</div>
              <div className="space-y-2">
                {summary.capabilities.map((c, i) => <CapabilityRow key={`${c.action}-${c.requested_login}-${i}`} cap={c} />)}
              </div>
            </div>

            {/* Logins */}
            {summary.logins.length > 0 && (
              <div>
                <div className="text-xs uppercase tracking-wide text-gray-500 mb-2">Logins &amp; host state</div>
                <div className="space-y-2">
                  {summary.logins.map(d => <LoginDetail key={d.login} d={d} />)}
                </div>
              </div>
            )}

            <p className="text-xs text-gray-600">
              {summary.notes.join(' ')}
            </p>
          </div>
        )}
      </CardBody>
    </Card>
  );
};

export default EffectiveAccessCard;
