import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '../../components/MainLayout';
import { apiFetch, formatApiError } from '@/utils/api';
import { useAuth } from '../../context/AuthContext';
import { CheckCircle, XCircle, Clock, MessageSquare } from 'lucide-react';
import Head from 'next/head';
import { PageHeader, Button, Card, CardBody, EmptyState, SkeletonCards } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface Vote {
  user_id: number;
  decision: 'approve' | 'reject';
  comment: string | null;
  created_at: string | null;
}

interface Approval {
  id: number;
  command: string;
  system_id: number;
  system_hostname: string | null;
  whitelist_entry_id: number | null;
  requested_by: number;
  requester_username: string | null;
  decided_by: number | null;
  decider_username: string | null;
  status: string;
  comment: string | null;
  timeout_seconds: number | null;
  expires_at: string | null;
  required_approvals: number;
  approves_received: number;
  votes: Vote[];
  requested_at: string;
  decided_at: string | null;
}

const STATUS_COLORS: Record<string, string> = {
  pending: 'bg-yellow-900/50 text-yellow-400 border-yellow-700',
  approved: 'bg-green-900/50 text-green-400 border-green-700',
  rejected: 'bg-red-900/50 text-red-400 border-red-700',
  expired: 'bg-surface-overlay text-content-muted border-border-strong',
};

function expiryCountdown(iso: string | null): { label: string; urgent: boolean } | null {
  if (!iso) return null;
  const ms = new Date(iso).getTime() - Date.now();
  if (ms <= 0) return { label: 'expired', urgent: true };
  const mins = Math.floor(ms / 60000);
  if (mins < 60) return { label: `${mins}m left`, urgent: mins < 5 };
  const hrs = Math.floor(mins / 60);
  if (hrs < 24) return { label: `${hrs}h left`, urgent: false };
  return { label: `${Math.floor(hrs / 24)}d left`, urgent: false };
}

const ApprovalQueuePage: React.FC = () => {
  const { isAdmin } = useAuth();
  const [approvals, setApprovals] = useState<Approval[]>([]);
  const [loading, setLoading] = useState(true);
  const [filterStatus, setFilterStatus] = useState('pending');
  const [commentModal, setCommentModal] = useState<{ id: number; action: 'approve' | 'reject' } | null>(null);
  const [comment, setComment] = useState('');

  const loadData = useCallback(async () => {
    try {
      const params = filterStatus ? `?status=${filterStatus}` : '';
      const res = await apiFetch(`/api/backend/command-approvals${params}`);
      if (res.ok) {
        const data = await res.json();
        setApprovals(data.approvals);
      }
    } catch {
      toast.error('Failed to load approvals');
    } finally {
      setLoading(false);
    }
  }, [filterStatus]);

  useEffect(() => { loadData(); }, [loadData]);

  const handleDecision = async (id: number, action: 'approve' | 'reject', decisionComment?: string) => {
    try {
      const res = await apiFetch(`/api/backend/command-approvals/${id}/${action}`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ comment: decisionComment || null }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, `Failed to ${action}`));
      }
      toast.success(action === 'approve' ? 'Command approved and executing' : 'Command rejected');
      setCommentModal(null);
      setComment('');
      loadData();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : `Failed to ${action}`);
    }
  };

  const openCommentModal = (id: number, action: 'approve' | 'reject') => {
    setCommentModal({ id, action });
    setComment('');
  };

  const timeAgo = (dateStr: string) => {
    const diff = Date.now() - new Date(dateStr).getTime();
    const mins = Math.floor(diff / 60000);
    if (mins < 1) return 'just now';
    if (mins < 60) return `${mins}m ago`;
    const hours = Math.floor(mins / 60);
    if (hours < 24) return `${hours}h ago`;
    return `${Math.floor(hours / 24)}d ago`;
  };

  if (loading) {
    return <MainLayout>
        <Head>
          <title>Approval Queue | Praxis</title>
        </Head><SkeletonCards count={3} /></MainLayout>;
  }

  return (
    <MainLayout>
      <Head>
        <title>Approval Queue | Praxis</title>
      </Head>
        <PageHeader
          title="Approval Queue"
          actions={
            <div className="flex gap-2">
              {['pending', 'approved', 'rejected', ''].map((s) => (
                <Button
                  key={s}
                  variant={filterStatus === s ? 'primary' : 'outline'}
                  size="sm"
                  onClick={() => setFilterStatus(s)}
                >
                  {s || 'All'}
                </Button>
              ))}
              <HelpLink slug="ssh-and-security" />
            </div>
          }
        />

        <div className="space-y-4">
          {approvals.map((a) => (
            <Card key={a.id}>
              <CardBody>
                <div className="flex items-start justify-between">
                  <div className="flex-1">
                    <div className="flex items-center gap-3 mb-2 flex-wrap">
                      <span className={`text-xs px-2 py-0.5 rounded border ${STATUS_COLORS[a.status] || ''}`}>
                        {a.status}
                      </span>
                      <span className="text-xs text-content-subtle">#{a.id}</span>
                      <span className="text-xs text-content-subtle">
                        <Clock size={12} className="inline mr-1" />
                        {timeAgo(a.requested_at)}
                      </span>
                      {a.status === 'pending' && a.required_approvals > 1 && (
                        <span className="text-xs px-2 py-0.5 rounded bg-blue-900/40 text-blue-200">
                          Approvals: {a.approves_received} / {a.required_approvals}
                        </span>
                      )}
                      {a.status === 'pending' && (() => {
                        const c = expiryCountdown(a.expires_at);
                        if (!c) return null;
                        return (
                          <span className={`text-xs px-2 py-0.5 rounded ${c.urgent ? 'bg-red-900/50 text-red-200' : 'bg-gray-800 text-gray-300'}`}>
                            {c.label}
                          </span>
                        );
                      })()}
                    </div>
                    <code className="block text-sm bg-surface-sunken px-3 py-2 rounded text-content font-mono mb-2">
                      {a.command}
                    </code>
                    <div className="flex gap-4 text-xs text-content-muted">
                      <span>System: <strong className="text-content">{a.system_hostname || `#${a.system_id}`}</strong></span>
                      <span>Requested by: <strong className="text-content">{a.requester_username || `#${a.requested_by}`}</strong></span>
                      {a.decider_username && (
                        <span>{a.status === 'approved' ? 'Approved' : 'Rejected'} by: <strong className="text-content">{a.decider_username}</strong></span>
                      )}
                    </div>
                    {a.comment && (
                      <div className="mt-2 text-xs text-content-muted flex items-start gap-1">
                        <MessageSquare size={12} className="mt-0.5 shrink-0" />
                        <span>{a.comment}</span>
                      </div>
                    )}
                  </div>
                  {a.status === 'pending' && isAdmin && (
                    <div className="flex gap-2 ml-4">
                      {/* PRA-270: de-emphasize the repeated decision pair - labels
                          kept for clarity, but no wall of solid primary/danger.
                          The comment modal is the deliberate approve/reject step. */}
                      <Button
                        variant="secondary"
                        size="sm"
                        icon={<CheckCircle size={14} />}
                        onClick={() => openCommentModal(a.id, 'approve')}
                      >
                        Approve
                      </Button>
                      <Button
                        variant="ghost"
                        size="sm"
                        icon={<XCircle size={14} />}
                        onClick={() => openCommentModal(a.id, 'reject')}
                      >
                        Reject
                      </Button>
                    </div>
                  )}
                </div>
              </CardBody>
            </Card>
          ))}
          {approvals.length === 0 && (
            <EmptyState
              title={filterStatus === 'pending' ? 'No pending approvals' : 'No approvals found'}
            />
          )}
        </div>

        {/* Comment Modal */}
        {commentModal && (
          <div className="fixed inset-0 z-50 flex items-center justify-center bg-surface/60">
            <div className="bg-surface-overlay border border-border rounded-lg w-full max-w-md p-6">
              <h2 className="text-lg font-semibold text-content mb-4">
                {commentModal.action === 'approve' ? 'Approve Command' : 'Reject Command'}
              </h2>
              <div className="mb-4">
                <label className="block text-xs text-content-muted mb-1">Comment (optional)</label>
                <textarea value={comment} onChange={(e) => setComment(e.target.value)}
                  rows={3} placeholder={commentModal.action === 'reject' ? 'Reason for rejection...' : 'Optional note...'}
                  className="w-full bg-white/[0.02] border border-border-strong rounded px-3 py-2 text-sm text-content focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong focus:outline-none" />
              </div>
              <div className="flex justify-end gap-3">
                <Button variant="ghost" onClick={() => { setCommentModal(null); setComment(''); }}>
                  Cancel
                </Button>
                <Button
                  variant={commentModal.action === 'approve' ? 'primary' : 'danger'}
                  onClick={() => handleDecision(commentModal.id, commentModal.action, comment)}
                >
                  {commentModal.action === 'approve' ? 'Approve & Execute' : 'Reject'}
                </Button>
              </div>
            </div>
          </div>
        )}
    </MainLayout>
  );
};

export default ApprovalQueuePage;
