import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Eye, Plus, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Badge, Button, ErrorState, LoadingState, PageHeader } from '@/components/ui';
import MirrorForm from '@/components/mirror/MirrorForm';
import { useAuth } from '@/context/AuthContext';
import {
  listMirrors,
  signingStatusLabel,
  signingStatusVariant,
  syncStatusVariant,
  triggerMirrorSync,
  type MirrorRepo,
} from '@/services/mirrorService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

function formatBytes(bytes: number | null | undefined): string {
  if (!bytes || bytes <= 0) return '-';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let n = bytes;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

const MirrorsListPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [mirrors, setMirrors] = useState<MirrorRepo[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [syncingId, setSyncingId] = useState<number | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const { canWrite } = useAuth();

  const refresh = useCallback(async () => {
    try {
      const data = await listMirrors();
      setMirrors(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleSyncNow = async (mirror: MirrorRepo) => {
    setSyncingId(mirror.id);
    try {
      await triggerMirrorSync(mirror.id);
      toast.success(`Sync queued for "${mirror.slug}". Polling /runs to observe.`);
      // Brief delay before refresh - the BackgroundTask runs after the
      // response, so an immediate refresh might race the running flip.
      setTimeout(() => refresh(), 750);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue sync');
    } finally {
      setSyncingId(null);
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Mirrors · Praxis</title>
      </Head>
      <div className="p-6">
        <PageHeader
          title="Mirrors"
          subtitle="Local apt and yum/dnf mirrors. Praxis pulls upstream content on schedule and serves it to managed hosts."
          actions={
            canWrite && (
              <Button variant="primary" onClick={() => setShowCreate(true)}>
                <Plus size={14} /> New mirror
              </Button>
            )
          }
        />

        {canWrite && (
          <MirrorForm
            open={showCreate}
            onClose={() => setShowCreate(false)}
            onSaved={() => refresh()}
          />
        )}

        {error && (
          <ErrorState title="Couldn’t load mirrors" onRetry={refresh} />
        )}

        {mirrors === null && !error && <LoadingState label="Loading mirrors" />}

        {mirrors !== null && mirrors.length === 0 && !error && (
          <div className="rounded border border-border bg-surface-raised p-8 text-center">
            <p className="text-sm text-content">No mirrors yet.</p>
            <p className="mt-1 text-sm text-content-subtle">
              A mirror is the first step of the content workflow (Mirror → Channel →
              Profile → Host). Create one to pull upstream apt/yum content and serve
              it to your fleet.
            </p>
            {canWrite ? (
              <div className="mt-4">
                <Button variant="primary" onClick={() => setShowCreate(true)}>
                  <Plus size={14} /> Create your first mirror
                </Button>
              </div>
            ) : (
              <p className="mt-4 text-xs text-content-subtle">
                Ask an admin or maintainer to create the first mirror.
              </p>
            )}
          </div>
        )}

        {mirrors && mirrors.length > 0 && (
          <div className="overflow-x-auto rounded border border-border bg-surface-raised">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-content-muted">
                <tr>
                  <th className="px-4 py-2">Slug</th>
                  <th className="px-4 py-2">Family</th>
                  <th className="px-4 py-2">Distribution</th>
                  <th className="px-4 py-2">Status</th>
                  <th className="px-4 py-2">Trust</th>
                  <th className="px-4 py-2">Last sync</th>
                  <th className="px-4 py-2">Disk</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {mirrors.map((m) => (
                  <tr key={m.id} className="hover:bg-surface-overlay/40">
                    <td className="px-4 py-2 font-mono text-content">
                      <Link
                        href={`/mirrors/${m.id}`}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        {m.slug}
                      </Link>
                      {!m.enabled && (
                        <Badge variant="neutral" className="ml-2">
                          disabled
                        </Badge>
                      )}
                      {m.source_mode === 'imported_offline' && (
                        <Badge variant="orange" className="ml-2">
                          imported
                        </Badge>
                      )}
                    </td>
                    <td className="px-4 py-2 text-content">{m.package_family}</td>
                    <td className="px-4 py-2 text-content">{m.distribution}</td>
                    <td className="px-4 py-2">
                      <Badge
                        variant={syncStatusVariant(m.last_sync_status)}
                        pulse={m.last_sync_status === 'running'}
                      >
                        {m.last_sync_status}
                      </Badge>
                    </td>
                    <td className="px-4 py-2">
                      <Badge variant={signingStatusVariant(m.signing_status)}>
                        {signingStatusLabel(m.signing_status)}
                      </Badge>
                    </td>
                    <td className="px-4 py-2 text-content-muted">
                      {formatTimestamp(m.last_sync_finished_at) || '-'}
                    </td>
                    <td className="px-4 py-2 text-content-muted">
                      {formatBytes(m.current_disk_bytes)}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <button
                        onClick={() => handleSyncNow(m)}
                        disabled={
                          syncingId === m.id ||
                          m.source_mode === 'imported_offline' ||
                          !m.enabled ||
                          m.last_sync_status === 'running'
                        }
                        className="inline-flex items-center gap-1 rounded p-1 text-content-muted hover:text-green-400 disabled:opacity-30 disabled:hover:text-content-muted"
                        title={
                          m.source_mode === 'imported_offline'
                            ? 'Imported-offline mirrors do not sync upstream'
                            : !m.enabled
                            ? 'Mirror is disabled'
                            : m.last_sync_status === 'running'
                            ? 'Sync already in progress'
                            : 'Sync now'
                        }
                      >
                        <RefreshCw
                          size={16}
                          className={syncingId === m.id ? 'animate-spin' : ''}
                        />
                      </button>
                      <Link
                        href={`/mirrors/${m.id}`}
                        className="ml-1 inline-flex items-center gap-1 rounded p-1 text-content-muted hover:text-blue-400"
                        title="View detail"
                      >
                        <Eye size={16} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </MainLayout>
  );
};

export default MirrorsListPage;
