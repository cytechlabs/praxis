import { useCallback, useEffect, useMemo, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import { ArrowLeft, Check, ClipboardCheck, Clock, Download, X, RefreshCw } from 'lucide-react';
import MainLayout from '../../../components/MainLayout';
import { useAuth } from '../../../context/AuthContext';
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
  AccessReview,
  AccessReviewItem,
  ReviewAction,
  attestItem,
  completeReview,
  exportReviewCsvUrl,
  extendItem,
  getReview,
  revokeItem,
} from '../../../services/accessReviewService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const actionVariant = (a: ReviewAction) => {
  switch (a) {
    case 'pending': return 'neutral';
    case 'attest': return 'success';
    case 'extend': return 'info';
    case 'revoke': return 'danger';
    default: return 'neutral';
  }
};

type DecisionKind = 'attest' | 'revoke' | 'extend';

const ReviewDetailPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { canWrite } = useAuth();
  const reviewId = router.query.id ? Number(router.query.id) : null;

  const [review, setReview] = useState<AccessReview | null>(null);
  const [items, setItems] = useState<AccessReviewItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [decisionTarget, setDecisionTarget] = useState<{ items: AccessReviewItem[]; kind: DecisionKind } | null>(null);
  const [decisionNotes, setDecisionNotes] = useState('');
  const [decisionDays, setDecisionDays] = useState(90);
  const [submitting, setSubmitting] = useState(false);
  const [completeOpen, setCompleteOpen] = useState(false);
  const [completeSummary, setCompleteSummary] = useState('');
  const [selected, setSelected] = useState<Set<number>>(new Set());

  const load = useCallback(async () => {
    if (!reviewId) return;
    setLoading(true);
    try {
      const { review: r, items: i } = await getReview(reviewId);
      setReview(r);
      setItems(i);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Load failed');
    } finally {
      setLoading(false);
    }
  }, [reviewId]);

  useEffect(() => { load(); }, [load]);

  const pendingCount = useMemo(() => items.filter((i) => i.action === 'pending').length, [items]);

  const submitDecision = async () => {
    if (!decisionTarget || !reviewId) return;
    setSubmitting(true);
    try {
      const results = await Promise.allSettled(
        decisionTarget.items.map((it) => {
          if (decisionTarget.kind === 'attest') return attestItem(reviewId, it.id, decisionNotes || undefined);
          if (decisionTarget.kind === 'revoke') return revokeItem(reviewId, it.id, decisionNotes || undefined);
          return extendItem(reviewId, it.id, decisionDays, decisionNotes || undefined);
        }),
      );
      const failures = results.filter((r) => r.status === 'rejected').length;
      const successes = results.length - failures;
      if (successes) toast.success(`${successes} item${successes === 1 ? '' : 's'} updated`);
      if (failures) toast.error(`${failures} item${failures === 1 ? '' : 's'} failed`);
      setDecisionTarget(null);
      setDecisionNotes('');
      setSelected(new Set());
      await load();
    } finally {
      setSubmitting(false);
    }
  };

  const submitComplete = async () => {
    if (!reviewId) return;
    setSubmitting(true);
    try {
      await completeReview(reviewId, completeSummary || undefined);
      toast.success('Review completed');
      setCompleteOpen(false);
      setCompleteSummary('');
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Complete failed');
    } finally {
      setSubmitting(false);
    }
  };

  const toggleSelect = (id: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(id)) next.delete(id); else next.add(id);
      return next;
    });
  };

  const selectedItems = items.filter((i) => selected.has(i.id) && i.action === 'pending');

  if (!canWrite) {
    return (
      <MainLayout>
        <EmptyState title="Operator-only" description="Access reviews are reviewed by admins and maintainers." icon={<ClipboardCheck size={28} />} />
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head><title>Access Review #{reviewId} | Praxis</title></Head>

      <div className="flex items-center justify-between mb-6 gap-3">
        <div>
          <button onClick={() => router.push('/access/access-reviews')} className="text-xs text-content-muted hover:text-content flex items-center gap-1 mb-1">
            <ArrowLeft size={12} /> All reviews
          </button>
          <h1 className="text-xl font-semibold text-content flex items-center gap-2">
            <ClipboardCheck size={18} /> Access Review #{reviewId}
          </h1>
          {review && (
            <p className="text-sm text-content-muted mt-1">
              <Badge variant="neutral" className="mr-2">{review.scope}</Badge>
              <Badge variant={review.state === 'completed' ? 'success' : review.state === 'expired' ? 'danger' : 'warning'}>{humanizeStatus(review.state)}</Badge>
              <span className="ml-2">Due {formatTimestamp(review.due_at, { dateOnly: true })}</span>
              {review.completed_at && <span className="ml-2">· Completed {formatTimestamp(review.completed_at)}</span>}
            </p>
          )}
        </div>
        <div className="flex items-center gap-2">
          <Button variant="outline" size="sm" onClick={load} aria-label="Refresh"><RefreshCw size={14} /></Button>
          {review?.state === 'completed' && (
            <a href={exportReviewCsvUrl(review.id)} download>
              <Button variant="outline" size="sm"><Download size={14} className="mr-1" /> Export CSV</Button>
            </a>
          )}
          {review?.state === 'pending' && (
            <Button variant="primary" size="sm" disabled={pendingCount > 0} onClick={() => setCompleteOpen(true)} title={pendingCount > 0 ? `${pendingCount} items still pending` : ''}>
              Complete review
            </Button>
          )}
        </div>
      </div>

      <Card>
        <CardHeader>
          <div className="flex items-center justify-between gap-3">
            <span>{items.length} items · {pendingCount} pending</span>
            {selectedItems.length > 0 && (
              <div className="flex items-center gap-2 text-xs">
                <span className="text-content-subtle">{selectedItems.length} selected:</span>
                <button onClick={() => { setDecisionTarget({ items: selectedItems, kind: 'attest' }); setDecisionNotes(''); }} className="px-2 py-1 rounded-md text-emerald-400 hover:bg-emerald-500/10">Attest</button>
                <button onClick={() => { setDecisionTarget({ items: selectedItems, kind: 'extend' }); setDecisionNotes(''); }} className="px-2 py-1 rounded-md text-sky-400 hover:bg-sky-500/10">Extend</button>
                <button onClick={() => { setDecisionTarget({ items: selectedItems, kind: 'revoke' }); setDecisionNotes(''); }} className="px-2 py-1 rounded-md text-red-400 hover:bg-red-500/10">Revoke</button>
              </div>
            )}
          </div>
        </CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-content-subtle text-sm">Loading…</div>
          ) : items.length === 0 ? (
            <EmptyState title="No items" description="This review captured zero bindings." icon={<Clock size={28} />} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-content-subtle border-b border-border">
                    <th className="py-2 pr-2 w-6" />
                    <th className="py-2 pr-4">Binding</th>
                    <th className="py-2 pr-4">Subject</th>
                    <th className="py-2 pr-4">Scope</th>
                    <th className="py-2 pr-4">Fleet role</th>
                    <th className="py-2 pr-4">Expires</th>
                    <th className="py-2 pr-4">Decision</th>
                    <th className="py-2 pr-4">Notes</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {items.map((it) => {
                    const snap = it.binding_snapshot;
                    return (
                      <tr key={it.id} className="border-b border-border hover:bg-white/5">
                        <td className="py-3 pr-2">
                          {it.action === 'pending' && (
                            <input type="checkbox" checked={selected.has(it.id)} onChange={() => toggleSelect(it.id)} />
                          )}
                        </td>
                        <td className="py-3 pr-4 font-mono text-xs text-content">#{it.binding_id ?? '-'}</td>
                        <td className="py-3 pr-4 text-xs">
                          {snap?.subject_user_id ? <span><Badge variant="neutral">user</Badge> <span className="font-mono ml-1">#{snap.subject_user_id}</span></span> : null}
                          {snap?.subject_app_role_id ? <span><Badge variant="info">role</Badge> <span className="font-mono ml-1">#{snap.subject_app_role_id}</span></span> : null}
                        </td>
                        <td className="py-3 pr-4 text-xs">
                          {snap?.scope_group_id ? <span>group #{snap.scope_group_id}</span> : null}
                          {snap?.scope_smart_group_id ? <span>smart #{snap.scope_smart_group_id}</span> : null}
                        </td>
                        <td className="py-3 pr-4 text-xs font-mono text-content-muted">#{snap?.fleet_role_id}</td>
                        <td className="py-3 pr-4 text-xs text-content-subtle">{snap?.expires_at ? formatTimestamp(snap.expires_at, { dateOnly: true }) : '-'}</td>
                        <td className="py-3 pr-4 text-xs"><Badge variant={actionVariant(it.action)}>{it.action}</Badge></td>
                        <td className="py-3 pr-4 text-xs text-content-muted max-w-xs truncate" title={it.notes || ''}>{it.notes || '-'}</td>
                        <td className="py-3 pr-4 text-right">
                          {it.action === 'pending' && (
                            <div className="flex gap-1 justify-end">
                              <button onClick={() => { setDecisionTarget({ items: [it], kind: 'attest' }); setDecisionNotes(''); }} aria-label="Attest" className="p-1.5 rounded-md text-content-subtle hover:text-emerald-400 hover:bg-emerald-500/10"><Check size={14} /></button>
                              <button onClick={() => { setDecisionTarget({ items: [it], kind: 'extend' }); setDecisionNotes(''); setDecisionDays(90); }} aria-label="Extend" className="p-1.5 rounded-md text-content-subtle hover:text-sky-400 hover:bg-sky-500/10"><Clock size={14} /></button>
                              <button onClick={() => { setDecisionTarget({ items: [it], kind: 'revoke' }); setDecisionNotes(''); }} aria-label="Revoke" className="p-1.5 rounded-md text-content-subtle hover:text-red-400 hover:bg-red-500/10"><X size={14} /></button>
                            </div>
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

      <Modal
        open={decisionTarget !== null}
        onClose={() => { setDecisionTarget(null); setDecisionNotes(''); }}
        title={
          decisionTarget?.kind === 'attest' ? `Attest ${decisionTarget.items.length} item${decisionTarget.items.length === 1 ? '' : 's'}` :
          decisionTarget?.kind === 'revoke' ? `Revoke ${decisionTarget?.items.length} binding${decisionTarget?.items.length === 1 ? '' : 's'}` :
          `Extend ${decisionTarget?.items.length} binding${decisionTarget?.items.length === 1 ? '' : 's'}`
        }
        maxWidth="max-w-md"
      >
        <div className="space-y-3">
          {decisionTarget?.kind === 'extend' && (
            <div>
              <label className="block text-xs text-content-muted mb-1">Extend by (days)</label>
              <input
                type="number"
                min={1}
                max={730}
                value={decisionDays}
                onChange={(e) => setDecisionDays(parseInt(e.target.value, 10) || 90)}
                className="w-full bg-surface-sunken border border-border rounded-md px-2 py-2 text-sm text-content"
              />
            </div>
          )}
          <div>
            <label className="block text-xs text-content-muted mb-1">Notes (optional)</label>
            <textarea
              value={decisionNotes}
              onChange={(e) => setDecisionNotes(e.target.value)}
              rows={3}
              className="w-full bg-surface-sunken border border-border rounded-md px-2 py-2 text-sm text-content"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" size="sm" onClick={() => { setDecisionTarget(null); setDecisionNotes(''); }} disabled={submitting}>Cancel</Button>
            <Button
              variant={decisionTarget?.kind === 'revoke' ? 'danger' : 'primary'}
              size="sm"
              loading={submitting}
              onClick={submitDecision}
            >
              Confirm
            </Button>
          </div>
        </div>
      </Modal>

      <Modal open={completeOpen} onClose={() => setCompleteOpen(false)} title="Complete review" maxWidth="max-w-md">
        <div className="space-y-3">
          <p className="text-sm text-content-muted">All items are decided. Add a summary for the audit trail and lock the review.</p>
          <div>
            <label className="block text-xs text-content-muted mb-1">Summary (optional)</label>
            <textarea
              value={completeSummary}
              onChange={(e) => setCompleteSummary(e.target.value)}
              rows={4}
              className="w-full bg-surface-sunken border border-border rounded-md px-2 py-2 text-sm text-content"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" size="sm" onClick={() => setCompleteOpen(false)} disabled={submitting}>Cancel</Button>
            <Button variant="primary" size="sm" loading={submitting} onClick={submitComplete}>Complete</Button>
          </div>
        </div>
      </Modal>
    </MainLayout>
  );
};

export default ReviewDetailPage;
