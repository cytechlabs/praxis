import { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import { toast } from 'sonner';
import { Lock, ShieldOff, Unlock } from 'lucide-react';
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
  Modal,
} from '@/components/ui';
import {
  SessionLock,
  createLock,
  listLocks,
  releaseLock,
} from '../../services/sessionLockService';
import { fetchAvailableRoles, fetchUsers } from '../../services/userService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface UserRow { id: number; username: string }

const SessionLocksPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const { canWrite } = useAuth();
  const [rows, setRows] = useState<SessionLock[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [releaseId, setReleaseId] = useState<number | null>(null);
  const [submitting, setSubmitting] = useState(false);

  // Form state
  const [subjectKind, setSubjectKind] = useState<'user' | 'role'>('user');
  const [users, setUsers] = useState<UserRow[] | null>(null);
  const [roles, setRoles] = useState<string[] | null>(null);
  const [subjectUserId, setSubjectUserId] = useState<string>('');
  const [subjectRoleName, setSubjectRoleName] = useState<string>('');
  const [reason, setReason] = useState('');

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await listLocks());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Load failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  // Optional ergonomics: try to fetch user/role lists when the modal opens.
  // Maintainers get 403 on /users - fall back to free-form ID inputs.
  useEffect(() => {
    if (!createOpen) return;
    fetchUsers().then(setUsers).catch(() => setUsers([]));
    fetchAvailableRoles().then(setRoles).catch(() => setRoles([]));
  }, [createOpen]);

  const resetForm = () => {
    setSubjectKind('user');
    setSubjectUserId('');
    setSubjectRoleName('');
    setReason('');
  };

  const submitCreate = async () => {
    setSubmitting(true);
    try {
      const trimmed = reason.trim();
      if (!trimmed) throw new Error('Reason is required');
      const payload: Parameters<typeof createLock>[0] = { reason: trimmed };
      if (subjectKind === 'user') {
        if (!subjectUserId) throw new Error('Pick a user');
        const asInt = parseInt(subjectUserId, 10);
        if (!Number.isNaN(asInt) && String(asInt) === subjectUserId) {
          payload.subject_user_id = asInt;
        } else {
          payload.subject_username = subjectUserId;
        }
      } else {
        if (!subjectRoleName) throw new Error('Pick a role');
        payload.subject_role_name = subjectRoleName;
      }
      await createLock(payload);
      toast.success('Lock created');
      setCreateOpen(false);
      resetForm();
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Create failed');
    } finally {
      setSubmitting(false);
    }
  };

  const submitRelease = async () => {
    if (releaseId === null) return;
    setSubmitting(true);
    try {
      await releaseLock(releaseId);
      toast.success('Lock released');
      setReleaseId(null);
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Release failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (!canWrite) {
    return (
      <MainLayout>
        <Head><title>Session Locks | Praxis</title></Head>
        <EmptyState
          title="Admin or maintainer required"
          description="Session locks are an operator-only emergency control."
          icon={<ShieldOff size={28} />}
        />
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head><title>Session Locks | Praxis</title></Head>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-gray-100 flex items-center gap-2">
            <Lock size={18} /> Session Locks
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Emergency cut-off. While a lock is active, every gated action is denied for the subject and any live sessions are killed immediately.
          </p>
        </div>
        <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
          New lock
        </Button>
      </div>

      <Card>
        <CardHeader>{rows.length} {rows.length === 1 ? 'lock' : 'locks'}</CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-gray-500 text-sm">Loading…</div>
          ) : rows.length === 0 ? (
            <EmptyState title="No locks" description="No subject is currently locked out." icon={<Lock size={28} />} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-gray-500 border-b border-gray-800">
                    <th className="py-2 pr-4">Subject</th>
                    <th className="py-2 pr-4">Reason</th>
                    <th className="py-2 pr-4">Created by</th>
                    <th className="py-2 pr-4">Created</th>
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4">Released</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className="border-b border-gray-900 hover:bg-white/5">
                      <td className="py-3 pr-4 text-xs">
                        {r.subject_username
                          ? <span><Badge variant="neutral">user</Badge> <span className="font-mono ml-1">{r.subject_username}</span></span>
                          : <span><Badge variant="info">role</Badge> <span className="font-mono ml-1">{r.subject_role_name}</span></span>}
                      </td>
                      <td className="py-3 pr-4 text-xs text-gray-300 max-w-md truncate" title={r.reason}>{r.reason}</td>
                      <td className="py-3 pr-4 text-xs text-gray-400">{r.created_by_username || '-'}</td>
                      <td className="py-3 pr-4 text-xs text-gray-500">{formatTimestamp(r.created_at)}</td>
                      <td className="py-3 pr-4 text-xs">
                        {r.active
                          ? <Badge variant="danger">active</Badge>
                          : <Badge variant="neutral">released</Badge>}
                      </td>
                      <td className="py-3 pr-4 text-xs text-gray-500">
                        {r.released_at
                          ? `${r.released_by_username || '?'} · ${formatTimestamp(r.released_at)}`
                          : '-'}
                      </td>
                      <td className="py-3 pr-4 text-right">
                        {r.active && (
                          <button
                            onClick={() => setReleaseId(r.id)}
                            aria-label="Release lock"
                            className="p-1.5 rounded-md text-gray-500 hover:text-emerald-400 hover:bg-emerald-500/10"
                          >
                            <Unlock size={14} />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      {/* Create modal */}
      <Modal open={createOpen} onClose={() => { setCreateOpen(false); resetForm(); }} title="Create session lock" maxWidth="max-w-lg">
        <div className="space-y-4">
          <div className="flex gap-2 text-xs">
            <button
              onClick={() => setSubjectKind('user')}
              className={`px-3 py-1.5 rounded-md border ${subjectKind === 'user' ? 'border-red-500 bg-red-500/10 text-red-300' : 'border-gray-800 text-gray-400 hover:text-gray-200'}`}
            >Lock a user</button>
            <button
              onClick={() => setSubjectKind('role')}
              className={`px-3 py-1.5 rounded-md border ${subjectKind === 'role' ? 'border-red-500 bg-red-500/10 text-red-300' : 'border-gray-800 text-gray-400 hover:text-gray-200'}`}
            >Lock a role</button>
          </div>

          {subjectKind === 'user' ? (
            <div>
              <label className="block text-xs text-gray-400 mb-1">User</label>
              {users && users.length > 0 ? (
                <select
                  value={subjectUserId}
                  onChange={(e) => setSubjectUserId(e.target.value)}
                  className="w-full bg-[#0c0c0f] border border-gray-800 rounded-md px-2 py-2 text-sm text-gray-200"
                >
                  <option value="">Pick a user…</option>
                  {users.map((u) => <option key={u.id} value={u.id}>{u.username} (#{u.id})</option>)}
                </select>
              ) : (
                <input
                  value={subjectUserId}
                  onChange={(e) => setSubjectUserId(e.target.value)}
                  placeholder="Username or numeric user ID"
                  className="w-full bg-[#0c0c0f] border border-gray-800 rounded-md px-2 py-2 text-sm text-gray-200"
                />
              )}
            </div>
          ) : (
            <div>
              <label className="block text-xs text-gray-400 mb-1">Role</label>
              <select
                value={subjectRoleName}
                onChange={(e) => setSubjectRoleName(e.target.value)}
                className="w-full bg-[#0c0c0f] border border-gray-800 rounded-md px-2 py-2 text-sm text-gray-200"
              >
                <option value="">Pick a role…</option>
                {(roles || []).map((r) => <option key={r} value={r}>{r}</option>)}
              </select>
            </div>
          )}

          <div>
            <label className="block text-xs text-gray-400 mb-1">
              Reason <span className="text-red-400">*</span>
            </label>
            <textarea
              value={reason}
              onChange={(e) => setReason(e.target.value)}
              rows={3}
              placeholder="Why is this lock being created? (recorded in audit log)"
              className="w-full bg-[#0c0c0f] border border-gray-800 rounded-md px-2 py-2 text-sm text-gray-200"
              required
            />
            <p className="text-[11px] text-gray-500 mt-1">
              Required - surfaces in the audit log and on the lock list.
            </p>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" onClick={() => { setCreateOpen(false); resetForm(); }} disabled={submitting}>
              Cancel
            </Button>
            <Button
              variant="danger"
              onClick={submitCreate}
              loading={submitting}
              disabled={
                !reason.trim() ||
                (subjectKind === 'user' ? !subjectUserId : !subjectRoleName)
              }
            >
              Lock subject
            </Button>
          </div>
        </div>
      </Modal>

      <ConfirmModal
        open={releaseId !== null}
        onClose={() => setReleaseId(null)}
        onConfirm={submitRelease}
        title="Release lock?"
        message="The subject will regain access immediately. Existing sessions remain closed."
        confirmLabel="Release"
        variant="warning"
        loading={submitting}
      />
    </MainLayout>
  );
};

export default SessionLocksPage;
