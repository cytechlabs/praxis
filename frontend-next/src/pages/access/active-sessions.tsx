import { useCallback, useEffect, useMemo, useState } from 'react';
import Head from 'next/head';
import { toast } from 'sonner';
import { useRouter } from 'next/router';
import { Activity, Eye, Edit3, X, RefreshCw } from 'lucide-react';
import MainLayout from '../../components/MainLayout';
import { useAuth } from '../../context/AuthContext';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  ConfirmModal,
  EmptyState,
  nativeSelectClass,
  SearchInput,
} from '@/components/ui';
import {
  InteractiveSession,
  forceCloseSession,
  listSessions,
} from '../../services/sessionService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const POLL_MS = 5000;

type SortKey = 'duration' | 'last_activity' | 'started';

const fmtDuration = (start: string, end?: string | null) => {
  const s = new Date(start).getTime();
  const e = end ? new Date(end).getTime() : Date.now();
  const sec = Math.max(0, Math.floor((e - s) / 1000));
  if (sec < 60) return `${sec}s`;
  if (sec < 3600) return `${Math.floor(sec / 60)}m ${sec % 60}s`;
  const h = Math.floor(sec / 3600);
  const m = Math.floor((sec % 3600) / 60);
  return `${h}h ${m}m`;
};

const fmtRelative = (iso: string | null) => {
  if (!iso) return '-';
  const ms = Date.now() - new Date(iso).getTime();
  if (ms < 5_000) return 'just now';
  if (ms < 60_000) return `${Math.floor(ms / 1000)}s ago`;
  if (ms < 3_600_000) return `${Math.floor(ms / 60_000)}m ago`;
  return `${Math.floor(ms / 3_600_000)}h ago`;
};

const ActiveSessionsPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { user, canWrite } = useAuth();
  const [rows, setRows] = useState<InteractiveSession[]>([]);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState('');
  const [sortKey, setSortKey] = useState<SortKey>('duration');
  const [confirmId, setConfirmId] = useState<number | null>(null);
  const [busyId, setBusyId] = useState<number | null>(null);
  const [tick, setTick] = useState(0); // forces duration column to refresh

  const load = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true);
    try {
      const data = await listSessions({ active_only: true, mine_only: !canWrite });
      setRows(data);
    } catch (err) {
      if (showSpinner) toast.error(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [canWrite]);

  useEffect(() => { load(true); }, [load]);

  useEffect(() => {
    const id = setInterval(() => { load(false); setTick(t => t + 1); }, POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  const handleForceClose = async (id: number) => {
    setBusyId(id);
    try {
      await forceCloseSession(id);
      toast.success(`Session #${id} closed`);
      await load(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Force-close failed');
    } finally {
      setBusyId(null);
      setConfirmId(null);
    }
  };

  const filtered = useMemo(() => {
    const q = filter.trim().toLowerCase();
    let out = rows;
    if (q) {
      out = rows.filter(r =>
        (r.hostname || '').toLowerCase().includes(q) ||
        (r.fleet_role_name || '').toLowerCase().includes(q) ||
        (r.login || '').toLowerCase().includes(q) ||
        String(r.user_id).includes(q),
      );
    }
    const sorted = [...out];
    if (sortKey === 'duration') {
      sorted.sort((a, b) => new Date(a.started_at).getTime() - new Date(b.started_at).getTime());
    } else if (sortKey === 'last_activity') {
      sorted.sort((a, b) => {
        const at = a.last_activity_at ? new Date(a.last_activity_at).getTime() : 0;
        const bt = b.last_activity_at ? new Date(b.last_activity_at).getTime() : 0;
        return bt - at;
      });
    } else {
      sorted.sort((a, b) => new Date(b.started_at).getTime() - new Date(a.started_at).getTime());
    }
    return sorted;
    // tick triggers re-render so the duration column ages forward without reload
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [rows, filter, sortKey, tick]);

  const target = confirmId === null ? null : rows.find(r => r.id === confirmId);

  return (
    <MainLayout>
      <Head><title>Active Sessions | Praxis</title></Head>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-content flex items-center gap-2">
            <Activity size={18} /> Active Sessions
          </h1>
          <p className="text-sm text-content-muted mt-1">
            {canWrite
              ? 'Live view of every open SSH session. Force-close as needed for incident response.'
              : 'Live view of your open SSH sessions.'}
          </p>
        </div>
        <div className="flex items-center gap-2">
          <span className="text-xs text-content-subtle">Updates every {POLL_MS / 1000}s</span>
          <Button variant="outline" size="sm" onClick={() => load(true)} aria-label="Refresh now">
            <RefreshCw size={14} />
          </Button>
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <span>{filtered.length} {filtered.length === 1 ? 'session' : 'sessions'}</span>
            <div className="flex items-center gap-2">
              <SearchInput
                value={filter}
                onChange={(e) => setFilter(e.target.value)}
                placeholder="Filter by host, role, login…"
                className="w-64"
              />
              <select
                value={sortKey}
                onChange={(e) => setSortKey(e.target.value as SortKey)}
                className={`border border-border rounded-md px-2 py-1.5 text-xs ${nativeSelectClass}`}
              >
                <option value="duration">Longest running</option>
                <option value="started">Newest first</option>
                <option value="last_activity">Most recent activity</option>
              </select>
            </div>
          </div>
        </CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-content-subtle text-sm">Loading…</div>
          ) : filtered.length === 0 ? (
            <EmptyState
              title="No active sessions"
              description={rows.length === 0 ? 'Nobody is connected right now.' : 'No sessions match the filter.'}
              icon={<Activity size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-content-subtle border-b border-border">
                    <th className="py-2 pr-4">Host</th>
                    <th className="py-2 pr-4">User</th>
                    <th className="py-2 pr-4">Login</th>
                    <th className="py-2 pr-4">Role</th>
                    <th className="py-2 pr-4">Started</th>
                    <th className="py-2 pr-4">Duration</th>
                    <th className="py-2 pr-4">Last activity</th>
                    <th className="py-2 pr-4">Client IP</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map(r => (
                    <tr key={r.id} className="border-b border-border hover:bg-white/5">
                      <td className="py-3 pr-4 font-mono text-xs text-content">{r.hostname || `#${r.system_id}`}</td>
                      <td className="py-3 pr-4 text-xs text-content">
                        {r.user_id === user?.id ? <span className="text-emerald-400">you</span> : `#${r.user_id}`}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-content-muted">{r.login}</td>
                      <td className="py-3 pr-4 text-xs">
                        {r.fleet_role_name
                          ? <Badge variant="info">{r.fleet_role_name}</Badge>
                          : <span className="text-content-subtle">-</span>}
                      </td>
                      <td className="py-3 pr-4 text-xs text-content-subtle">{formatTimestamp(r.started_at)}</td>
                      <td className="py-3 pr-4 text-xs text-content tabular-nums">{fmtDuration(r.started_at)}</td>
                      <td className="py-3 pr-4 text-xs text-content-muted">
                        {fmtRelative(r.last_activity_at)}
                        {r.live && <span className="ml-1 inline-block w-1.5 h-1.5 rounded-full bg-emerald-500/70 align-middle" aria-label="live" />}
                      </td>
                      <td className="py-3 pr-4 font-mono text-xs text-content-subtle">{r.client_ip || '-'}</td>
                      <td className="py-3 pr-4 text-right">
                        {canWrite ? (
                          <div className="flex gap-1 justify-end">
                            {r.user_id !== user?.id && (
                              <>
                                <button
                                  onClick={() => router.push(`/hosts/${r.system_id}/session?join=observe&sid=${r.id}`)}
                                  aria-label="Observe session"
                                  title="Observe (read-only)"
                                  className="p-1.5 rounded-md text-content-subtle hover:text-sky-400 hover:bg-sky-500/10"
                                >
                                  <Eye size={14} />
                                </button>
                                <button
                                  onClick={() => router.push(`/hosts/${r.system_id}/session?join=participate&sid=${r.id}`)}
                                  aria-label="Participate in session"
                                  title="Participate (read/write)"
                                  className="p-1.5 rounded-md text-content-subtle hover:text-amber-400 hover:bg-amber-500/10"
                                >
                                  <Edit3 size={14} />
                                </button>
                              </>
                            )}
                            <button
                              onClick={() => setConfirmId(r.id)}
                              disabled={busyId === r.id}
                              aria-label="Force close"
                              className="p-1.5 rounded-md text-content-subtle hover:text-red-400 hover:bg-red-500/10 disabled:opacity-30"
                            >
                              <X size={14} />
                            </button>
                          </div>
                        ) : null}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      <ConfirmModal
        open={confirmId !== null}
        onClose={() => setConfirmId(null)}
        onConfirm={() => confirmId !== null && handleForceClose(confirmId)}
        title="Force-close session?"
        message={target
          ? `This will immediately terminate session #${target.id} on ${target.hostname || `system ${target.system_id}`} (login: ${target.login}). The action is recorded in the audit log.`
          : ''}
        confirmLabel="Force close"
        variant="danger"
        loading={busyId !== null}
      />
    </MainLayout>
  );
};

export default ActiveSessionsPage;
