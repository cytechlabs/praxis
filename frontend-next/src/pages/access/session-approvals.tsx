import { useCallback, useEffect, useMemo, useState } from 'react';
import Head from 'next/head';
import { toast } from 'sonner';
import { Check, ClipboardCheck, Clock, X } from 'lucide-react';
import MainLayout from '../../components/MainLayout';
import { useAuth } from '../../context/AuthContext';
import {
  Badge,
  Button,
  Card,
  CardBody,
  CardHeader,
  EmptyState,
  Modal,
} from '@/components/ui';
import {
  ApprovalState,
  SessionApproval,
  denyApproval,
  grantApproval,
  listApprovals,
} from '../../services/sessionApprovalService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const POLL_MS = 5000;

const stateVariant = (s: ApprovalState) => {
  switch (s) {
    case 'pending': return 'warning';
    case 'granted': return 'info';
    case 'consumed': return 'success';
    case 'denied': return 'danger';
    case 'expired': return 'neutral';
    default: return 'neutral';
  }
};

const SessionApprovalsPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const { canWrite } = useAuth();
  const [rows, setRows] = useState<SessionApproval[]>([]);
  const [loading, setLoading] = useState(true);
  const [showAll, setShowAll] = useState(false);
  const [decisionTarget, setDecisionTarget] = useState<{ row: SessionApproval; kind: 'grant' | 'deny' } | null>(null);
  const [decisionReason, setDecisionReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async (showSpinner = false) => {
    if (showSpinner) setLoading(true);
    try {
      setRows(await listApprovals(showAll ? {} : { state: 'pending' }));
    } catch (err) {
      if (showSpinner) toast.error(err instanceof Error ? err.message : 'Load failed');
    } finally {
      if (showSpinner) setLoading(false);
    }
  }, [showAll]);

  useEffect(() => { load(true); }, [load]);
  useEffect(() => {
    const id = setInterval(() => load(false), POLL_MS);
    return () => clearInterval(id);
  }, [load]);

  const submitDecision = async () => {
    if (!decisionTarget) return;
    setSubmitting(true);
    try {
      if (decisionTarget.kind === 'grant') {
        await grantApproval(decisionTarget.row.id, decisionReason || undefined);
        toast.success('Approval granted (5 min window)');
      } else {
        await denyApproval(decisionTarget.row.id, decisionReason || undefined);
        toast.success('Approval denied');
      }
      setDecisionTarget(null);
      setDecisionReason('');
      await load(false);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed');
    } finally {
      setSubmitting(false);
    }
  };

  const filtered = useMemo(() => rows, [rows]);

  if (!canWrite) {
    return (
      <MainLayout>
        <Head><title>Session Approvals | Praxis</title></Head>
        <EmptyState
          title="Operator-only"
          description="Session approvals are reviewed by admins and maintainers."
          icon={<ClipboardCheck size={28} />}
        />
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head><title>Session Approvals | Praxis</title></Head>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-gray-100 flex items-center gap-2">
            <ClipboardCheck size={18} /> Session Approvals
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Four-eyes gate for high-privilege fleet roles. Granted approvals are single-use and expire after 5 minutes.
          </p>
        </div>
        <Button variant={showAll ? 'primary' : 'outline'} size="sm" onClick={() => setShowAll((v) => !v)}>
          {showAll ? 'Showing all' : 'Pending only'}
        </Button>
      </div>

      <Card>
        <CardHeader>{filtered.length} {filtered.length === 1 ? 'request' : 'requests'}</CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-gray-500 text-sm">Loading…</div>
          ) : filtered.length === 0 ? (
            <EmptyState title="Nothing waiting" description="No requests to review." icon={<Clock size={28} />} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-gray-500 border-b border-gray-800">
                    <th className="py-2 pr-4">Requester</th>
                    <th className="py-2 pr-4">Host</th>
                    <th className="py-2 pr-4">Role</th>
                    <th className="py-2 pr-4">Login</th>
                    <th className="py-2 pr-4">Requested</th>
                    <th className="py-2 pr-4">State</th>
                    <th className="py-2 pr-4">Decision</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {filtered.map((r) => (
                    <tr key={r.id} className="border-b border-gray-900 hover:bg-white/5">
                      <td className="py-3 pr-4 text-xs font-mono text-gray-200">{r.requester_username || `#${r.requester_id}`}</td>
                      <td className="py-3 pr-4 text-xs font-mono text-gray-300">{r.hostname || `#${r.system_id}`}</td>
                      <td className="py-3 pr-4 text-xs"><Badge variant="info">{r.fleet_role_name || `#${r.fleet_role_id}`}</Badge></td>
                      <td className="py-3 pr-4 text-xs font-mono text-gray-400">{r.login}</td>
                      <td className="py-3 pr-4 text-xs text-gray-500">{formatTimestamp(r.created_at)}</td>
                      <td className="py-3 pr-4 text-xs"><Badge variant={stateVariant(r.state)}>{humanizeStatus(r.state)}</Badge></td>
                      <td className="py-3 pr-4 text-xs text-gray-500">
                        {r.approver_username
                          ? `${r.approver_username}${r.decision_reason ? ` · ${r.decision_reason}` : ''}`
                          : '-'}
                      </td>
                      <td className="py-3 pr-4 text-right">
                        {r.state === 'pending' && (
                          <div className="flex gap-1 justify-end">
                            <button
                              onClick={() => { setDecisionTarget({ row: r, kind: 'grant' }); setDecisionReason(''); }}
                              aria-label="Grant"
                              className="p-1.5 rounded-md text-gray-500 hover:text-emerald-400 hover:bg-emerald-500/10"
                            >
                              <Check size={14} />
                            </button>
                            <button
                              onClick={() => { setDecisionTarget({ row: r, kind: 'deny' }); setDecisionReason(''); }}
                              aria-label="Deny"
                              className="p-1.5 rounded-md text-gray-500 hover:text-red-400 hover:bg-red-500/10"
                            >
                              <X size={14} />
                            </button>
                          </div>
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

      <Modal
        open={decisionTarget !== null}
        onClose={() => { setDecisionTarget(null); setDecisionReason(''); }}
        title={decisionTarget?.kind === 'grant' ? 'Grant approval' : 'Deny approval'}
        maxWidth="max-w-md"
      >
        <div className="space-y-3">
          {decisionTarget && (
            <div className="text-xs text-gray-400">
              <div><span className="text-gray-500">Requester:</span> <span className="font-mono text-gray-200">{decisionTarget.row.requester_username}</span></div>
              <div><span className="text-gray-500">Host:</span> <span className="font-mono text-gray-200">{decisionTarget.row.hostname}</span></div>
              <div><span className="text-gray-500">Role / Login:</span> <span className="font-mono text-gray-200">{decisionTarget.row.fleet_role_name} as {decisionTarget.row.login}</span></div>
              {decisionTarget.row.reason && (
                <div className="mt-1"><span className="text-gray-500">Reason:</span> <span className="text-gray-300">{decisionTarget.row.reason}</span></div>
              )}
            </div>
          )}
          <div>
            <label className="block text-xs text-gray-400 mb-1">Decision note (optional)</label>
            <textarea
              value={decisionReason}
              onChange={(e) => setDecisionReason(e.target.value)}
              rows={3}
              className="w-full bg-[#0c0c0f] border border-gray-800 rounded-md px-2 py-2 text-sm text-gray-200"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" size="sm" onClick={() => { setDecisionTarget(null); setDecisionReason(''); }} disabled={submitting}>
              Cancel
            </Button>
            <Button
              variant={decisionTarget?.kind === 'grant' ? 'primary' : 'danger'}
              size="sm"
              loading={submitting}
              onClick={submitDecision}
            >
              {decisionTarget?.kind === 'grant' ? 'Grant (5 min)' : 'Deny'}
            </Button>
          </div>
        </div>
      </Modal>
    </MainLayout>
  );
};

export default SessionApprovalsPage;
