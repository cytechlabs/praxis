import { useCallback, useEffect, useState } from 'react';
import { useRouter } from 'next/router';
import Head from 'next/head';
import { toast } from 'sonner';
import { Clock, Play, Trash2, Video } from 'lucide-react';
import MainLayout from '../../components/MainLayout';
import { useAuth } from '../../context/AuthContext';
import { Badge, Button, Card, CardBody, CardHeader, EmptyState } from '@/components/ui';
import { Recording, deleteRecording, listRecordings } from '../../services/recordingService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const statusVariant = (s: Recording['status']) => {
  switch (s) {
    case 'active': return 'info';
    case 'finalized': return 'success';
    case 'pruned': return 'neutral';
    case 'errored': return 'danger';
    default: return 'neutral';
  }
};

const fmtBytes = (n: number) => {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
};

const RecordingsPage = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { isAdmin } = useAuth();
  const [rows, setRows] = useState<Recording[]>([]);
  const [loading, setLoading] = useState(true);
  const [viewAll, setViewAll] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      setRows(await listRecordings({ mine_only: !viewAll }));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  }, [viewAll]);

  useEffect(() => { load(); }, [load]);

  const handleDelete = async (id: number) => {
    try {
      await deleteRecording(id);
      toast.success('Recording pruned');
      await load();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Delete failed');
    }
  };

  return (
    <MainLayout>
      <Head><title>Session Recordings | Praxis</title></Head>
      <div className="flex items-center justify-between mb-6">
        <div>
          <h1 className="text-xl font-semibold text-gray-100 flex items-center gap-2">
            <Video size={18} /> Session Recordings
          </h1>
          <p className="text-sm text-gray-400 mt-1">
            Every interactive session is recorded. Output only - keystrokes are never captured.
          </p>
        </div>
        {isAdmin && (
          <Button variant={viewAll ? 'primary' : 'outline'} size="sm" onClick={() => setViewAll(v => !v)}>
            {viewAll ? 'Showing all' : 'My recordings only'}
          </Button>
        )}
      </div>

      <Card>
        <CardHeader>Captures</CardHeader>
        <CardBody>
          {loading ? (
            <div className="text-gray-500 text-sm">Loading…</div>
          ) : rows.length === 0 ? (
            <EmptyState title="No recordings" description="Open an interactive session to start recording." icon={<Clock size={28} />} />
          ) : (
            <div className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="text-left text-xs uppercase tracking-wide text-gray-500 border-b border-gray-800">
                    <th className="py-2 pr-4">Session</th>
                    <th className="py-2 pr-4">Started</th>
                    <th className="py-2 pr-4">Frames</th>
                    <th className="py-2 pr-4">Size</th>
                    <th className="py-2 pr-4">Retention</th>
                    <th className="py-2 pr-4">Status</th>
                    <th className="py-2 pr-4" />
                  </tr>
                </thead>
                <tbody>
                  {rows.map(r => (
                    <tr key={r.id} className="border-b border-gray-900 hover:bg-white/5">
                      <td className="py-3 pr-4 font-mono text-xs text-gray-300">#{r.session_id}</td>
                      <td className="py-3 pr-4 text-xs text-gray-400">{formatTimestamp(r.started_at)}</td>
                      <td className="py-3 pr-4 text-xs text-gray-400 tabular-nums">{r.frame_count}</td>
                      <td className="py-3 pr-4 text-xs text-gray-400 tabular-nums">{fmtBytes(r.size_bytes)}</td>
                      <td className="py-3 pr-4 text-xs text-gray-500">{formatTimestamp(r.retention_expires_at, { dateOnly: true })}</td>
                      <td className="py-3 pr-4"><Badge variant={statusVariant(r.status)}>{humanizeStatus(r.status)}</Badge></td>
                      <td className="py-3 pr-4 text-right">
                        <div className="flex gap-1 justify-end">
                          <button
                            onClick={() => router.push(`/recordings/${r.id}`)}
                            disabled={r.status === 'pruned'}
                            aria-label="Play"
                            className="p-1.5 rounded-md text-gray-500 hover:text-emerald-400 hover:bg-emerald-500/10 disabled:opacity-30 disabled:cursor-not-allowed"
                          >
                            <Play size={14} />
                          </button>
                          {isAdmin && r.status !== 'pruned' && (
                            <button
                              onClick={() => handleDelete(r.id)}
                              aria-label="Delete"
                              className="p-1.5 rounded-md text-gray-500 hover:text-red-400 hover:bg-red-500/10"
                            >
                              <Trash2 size={14} />
                            </button>
                          )}
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
    </MainLayout>
  );
};

export default RecordingsPage;
