import { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import { useRouter } from 'next/router';
import { toast } from 'sonner';
import { ClipboardList, Plus } from 'lucide-react';
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
  ReviewState,
  createReview,
  listReviews,
} from '../../../services/accessReviewService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const stateVariant = (s: ReviewState) => {
  switch (s) {
    case 'pending': return 'warning';
    case 'completed': return 'success';
    case 'expired': return 'danger';
    default: return 'neutral';
  }
};

const AccessReviewsPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { canWrite, isAdmin } = useAuth();
  const [rows, setRows] = useState<AccessReview[]>([]);
  const [loading, setLoading] = useState(true);
  const [createOpen, setCreateOpen] = useState(false);
  const [dueDays, setDueDays] = useState(14);
  const [submitting, setSubmitting] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await listReviews());
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Load failed');
    } finally {
      setLoading(false);
    }
  }, []);

  useEffect(() => { load(); }, [load]);

  const submitCreate = async () => {
    setSubmitting(true);
    try {
      const r = await createReview({ scope: 'all', due_in_days: dueDays });
      toast.success(`Review #${r.id} created with ${r.item_count} items`);
      setCreateOpen(false);
      router.push(`/access/access-reviews/${r.id}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Create failed');
    } finally {
      setSubmitting(false);
    }
  };

  if (!canWrite) {
    return (
      <MainLayout>
        <Head><title>Access Reviews | Praxis</title></Head>
        <EmptyState
          title="Operator-only"
          description="Access reviews are reviewed by admins and maintainers."
          icon={<ClipboardList size={28} />}
        />
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head><title>Access Reviews | Praxis</title></Head>

      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-content flex items-center gap-2">
            <ClipboardList size={18} /> Access Reviews
          </h1>
          <p className="text-sm text-content-muted mt-1">
            Periodic attestation of access bindings. Decide each row: attest, extend, or revoke. Required for SOC 2 / ISO access reviews.
          </p>
        </div>
        {isAdmin && (
          <Button variant="primary" size="sm" onClick={() => setCreateOpen(true)}>
            <Plus size={14} className="mr-1" /> New review
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>{rows.length} {rows.length === 1 ? 'review' : 'reviews'}</CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-content-subtle text-sm">Loading…</div>
          ) : rows.length === 0 ? (
            <EmptyState
              title="No reviews"
              description="Trigger one manually or wait for the scheduled cadence (configurable in Settings)."
              icon={<ClipboardList size={28} />}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-content-subtle border-b border-border">
                    <th className="py-2 pr-4">ID</th>
                    <th className="py-2 pr-4">Scope</th>
                    <th className="py-2 pr-4">Items</th>
                    <th className="py-2 pr-4">State</th>
                    <th className="py-2 pr-4">Due</th>
                    <th className="py-2 pr-4">Completed</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map((r) => (
                    <tr key={r.id} className="border-b border-border hover:bg-white/5 cursor-pointer" onClick={() => router.push(`/access/access-reviews/${r.id}`)}>
                      <td className="py-3 pr-4 font-mono text-xs text-content">#{r.id}</td>
                      <td className="py-3 pr-4 text-xs"><Badge variant="neutral">{r.scope}</Badge></td>
                      <td className="py-3 pr-4 text-xs text-content tabular-nums">{r.item_count}</td>
                      <td className="py-3 pr-4 text-xs"><Badge variant={stateVariant(r.state)}>{humanizeStatus(r.state)}</Badge></td>
                      <td className="py-3 pr-4 text-xs text-content-subtle">{formatTimestamp(r.due_at, { dateOnly: true })}</td>
                      <td className="py-3 pr-4 text-xs text-content-subtle">{r.completed_at ? formatTimestamp(r.completed_at) : '-'}</td>
                      <td className="py-3 pr-4 text-right">
                        <Button variant="ghost" size="sm">Open</Button>
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </CardBody>
      </Card>

      <Modal open={createOpen} onClose={() => setCreateOpen(false)} title="New access review (all enabled bindings)" maxWidth="max-w-md">
        <div className="space-y-4">
          <p className="text-sm text-content-muted">
            Snapshots every currently-enabled binding into a fresh review. The default scheduled cadence comes from Settings; this is for ad-hoc reviews.
          </p>
          <div>
            <label className="block text-xs text-content-muted mb-1">Due in (days)</label>
            <input
              type="number"
              min={1}
              max={365}
              value={dueDays}
              onChange={(e) => setDueDays(parseInt(e.target.value, 10) || 14)}
              className="w-full bg-surface-sunken border border-border rounded-md px-2 py-2 text-sm text-content"
            />
          </div>
          <div className="flex justify-end gap-2 pt-1">
            <Button variant="ghost" size="sm" onClick={() => setCreateOpen(false)} disabled={submitting}>Cancel</Button>
            <Button variant="primary" size="sm" loading={submitting} onClick={submitCreate}>Create</Button>
          </div>
        </div>
      </Modal>
    </MainLayout>
  );
};

export default AccessReviewsPage;
