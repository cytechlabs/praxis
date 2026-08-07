import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, Folder, Pencil, RefreshCw, Trash2, AlertTriangle } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import SigningKeyPanel from '@/components/mirror/SigningKeyPanel';
import MirrorForm from '@/components/mirror/MirrorForm';
import { Badge, Button, ConfirmModal, ErrorState, LoadingState, PageHeader } from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  deleteMirror,
  getMirror,
  listMirrorRuns,
  signingStatusLabel,
  signingStatusVariant,
  syncStatusVariant,
  triggerMirrorSync,
  type MirrorRepo,
  type MirrorSyncRun,
} from '@/services/mirrorService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

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

const MirrorDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const idParam = router.query.id;
  const id = typeof idParam === 'string' ? Number(idParam) : NaN;
  const { user, canWrite } = useAuth();
  const [showEdit, setShowEdit] = useState(false);
  const [showDelete, setShowDelete] = useState(false);
  const [deleting, setDeleting] = useState(false);
  // Force-cutover authorization in the backend is
  // require_role("admin", "maintainer") - match that here so a
  // maintainer can use the override they're already authorized for.
  const userRoles = user?.roles ?? [];
  const canForceCutover =
    userRoles.includes('admin') || userRoles.includes('maintainer');

  const [mirror, setMirror] = useState<MirrorRepo | null>(null);
  const [runs, setRuns] = useState<MirrorSyncRun[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [syncing, setSyncing] = useState(false);
  const [expandedRun, setExpandedRun] = useState<number | null>(null);

  const refresh = useCallback(async () => {
    if (!Number.isFinite(id)) return;
    try {
      const [m, r] = await Promise.all([getMirror(id), listMirrorRuns(id, { limit: 50 })]);
      setMirror(m);
      setRuns(r);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleSyncNow = async () => {
    if (!mirror) return;
    setSyncing(true);
    try {
      await triggerMirrorSync(mirror.id);
      toast.success(`Sync queued for "${mirror.slug}".`);
      setTimeout(() => refresh(), 750);
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to queue sync');
    } finally {
      setSyncing(false);
    }
  };

  const handleDelete = async () => {
    if (!mirror) return;
    setDeleting(true);
    try {
      await deleteMirror(mirror.id);
      toast.success(`Mirror "${mirror.slug}" deleted`);
      router.push('/mirrors/all');
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to delete mirror');
      setDeleting(false);
    }
  };

  if (error) {
    return (
      <MainLayout>
        <div className="p-6">
          <Link
            href="/mirrors/all"
            className="mb-4 inline-flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200"
          >
            <ArrowLeft size={14} /> Back to mirrors
          </Link>
          <ErrorState title="Couldn’t load mirror" onRetry={refresh} />
        </div>
      </MainLayout>
    );
  }

  if (!mirror) {
    return (
      <MainLayout>
        <LoadingState label="Loading mirror" />
      </MainLayout>
    );
  }

  const syncDisabled =
    syncing ||
    mirror.source_mode === 'imported_offline' ||
    !mirror.enabled ||
    mirror.last_sync_status === 'running';

  const syncDisabledReason =
    mirror.source_mode === 'imported_offline'
      ? 'Imported-offline mirrors do not sync upstream'
      : !mirror.enabled
      ? 'Mirror is disabled'
      : mirror.last_sync_status === 'running'
      ? 'Sync already in progress'
      : '';

  return (
    <MainLayout>
      <Head>
        <title>{mirror.slug} · Mirrors · Praxis</title>
      </Head>
      <div className="p-6">
        <Link
          href="/mirrors/all"
          className="mb-4 inline-flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200"
        >
          <ArrowLeft size={14} /> Back to mirrors
        </Link>

        <PageHeader
          title={mirror.display_name}
          subtitle={mirror.slug}
          actions={
            <div className="flex items-center gap-2">
              <Link href={`/mirrors/${mirror.id}/browse`}>
                <Button variant="outline" size="sm">
                  <Folder size={14} /> Browse
                </Button>
              </Link>
              {canWrite && (
                <Button variant="outline" size="sm" onClick={() => setShowEdit(true)}>
                  <Pencil size={14} /> Edit
                </Button>
              )}
              {canWrite && (
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => setShowDelete(true)}
                  title="Delete this mirror"
                >
                  <Trash2 size={14} /> Delete
                </Button>
              )}
              <Button
                variant="primary"
                size="sm"
                onClick={handleSyncNow}
                disabled={syncDisabled}
                title={syncDisabledReason}
              >
                <RefreshCw size={14} className={syncing ? 'animate-spin' : ''} />
                Sync now
              </Button>
            </div>
          }
        />

        {canWrite && (
          <>
            <MirrorForm
              open={showEdit}
              onClose={() => setShowEdit(false)}
              onSaved={() => refresh()}
              existing={mirror}
            />
            <ConfirmModal
              open={showDelete}
              onClose={() => setShowDelete(false)}
              onConfirm={handleDelete}
              title="Delete mirror"
              message={`Delete mirror "${mirror.slug}"? Its channels lose this repo. This is a soft delete; served content stops.`}
              confirmLabel="Delete"
              variant="danger"
              loading={deleting}
            />
          </>
        )}

        {/* Definition card */}
        <section className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2">
          <DefField label="Package family" value={humanizeStatus(mirror.package_family)} />
          <DefField label="Distribution" value={mirror.distribution} />
          <DefField label="Upstream URL" value={mirror.upstream_url} mono />
          <DefField
            label="Components"
            value={mirror.components.length ? mirror.components.join(', ') : '(none)'}
          />
          <DefField label="Architectures" value={mirror.architectures.join(', ')} />
          <DefField label="Schedule" value={mirror.sync_schedule_cron} mono />
          <DefField label="Source mode" value={humanizeStatus(mirror.source_mode)} />
          <DefField
            label="Verify upstream signature"
            value={mirror.verify_upstream_signature ? 'yes' : 'no'}
          />
          <DefField
            label="Retention"
            value={`keep ${mirror.retention_keep_count} runs / ${mirror.retention_keep_within_days} days`}
          />
          <DefField
            label="Disk usage"
            value={`${formatBytes(mirror.current_disk_bytes)}${
              mirror.disk_budget_bytes
                ? ` / ${formatBytes(mirror.disk_budget_bytes)} budget`
                : ''
            }`}
          />
          <DefField
            label="Last sync started"
            value={formatTimestamp(mirror.last_sync_started_at) || '-'}
          />
          <DefField
            label="Last sync finished"
            value={formatTimestamp(mirror.last_sync_finished_at) || '-'}
          />
        </section>

        {/* PRA-198: make the bounded historical-byte policy visible where
            operators read retention / disk state. */}
        <p className="mb-6 rounded border border-zinc-800 bg-[#111115] p-3 text-xs leading-relaxed text-gray-500">
          Retention keeps run <span className="text-gray-300">metadata and manifests</span>, not
          historical bytes. In 1.0, mirror bytes are <span className="text-gray-300">live-only</span> -
          only the last-promoted sync exists on disk. A channel run pin is a tracking pin, not a byte
          freeze: an airgap export reproduces a pinned state byte-exact only while that run is still
          live. A pin that no longer matches live is <span className="text-gray-300">refused</span>{' '}
          (<code className="text-gray-300">historical_bytes_unavailable</code>) rather than exporting
          the wrong bytes - export the latest snapshot, re-pin to the current run, or keep the earlier
          bundle tar as a byte-exact archive.
        </p>

        {/* Status summary */}
        <section className="mb-6 flex flex-wrap items-center gap-3 rounded border border-zinc-800 bg-[#111115] p-4 text-sm">
          <span className="text-gray-400">Sync:</span>
          <Badge
            variant={syncStatusVariant(mirror.last_sync_status)}
            pulse={mirror.last_sync_status === 'running'}
          >
            {mirror.last_sync_status}
          </Badge>
          <span className="ml-3 text-gray-400">Trust:</span>
          <Badge variant={signingStatusVariant(mirror.signing_status)}>
            {signingStatusLabel(mirror.signing_status)}
          </Badge>
          {mirror.last_sync_error && (
            <span className="ml-2 inline-flex items-center gap-1 text-red-400">
              <AlertTriangle size={14} />
              {mirror.last_sync_error.slice(0, 200)}
              {mirror.last_sync_error.length > 200 && '…'}
            </span>
          )}
        </section>

        {/* Signing keys (PRA-158 #5c) */}
        <section className="mb-6">
          <SigningKeyPanel
            mirror={mirror}
            canForceCutover={canForceCutover}
            onChange={refresh}
          />
        </section>

        {/* Sync history */}
        <section>
          <h2 className="mb-2 text-sm font-medium uppercase text-gray-400">
            Sync history
          </h2>
          {runs.length === 0 ? (
            <div className="rounded border border-zinc-800 bg-[#111115] p-4 text-sm text-gray-400">
              No sync runs yet.
            </div>
          ) : (
            <div className="overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
              <table className="w-full text-sm">
                <thead className="border-b border-zinc-800 text-left text-gray-400">
                  <tr>
                    <th className="px-4 py-2">Run</th>
                    <th className="px-4 py-2">Status</th>
                    <th className="px-4 py-2">Started</th>
                    <th className="px-4 py-2">Finished</th>
                    <th className="px-4 py-2">Bytes</th>
                    <th className="px-4 py-2">Pkgs</th>
                    <th className="px-4 py-2 text-right">Manifest</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {runs.map((r) => (
                    <React.Fragment key={r.id}>
                      <tr className="hover:bg-zinc-900/40">
                        <td className="px-4 py-2 font-mono text-gray-300">#{r.id}</td>
                        <td className="px-4 py-2">
                          <Badge
                            variant={syncStatusVariant(r.status)}
                            pulse={r.status === 'running'}
                          >
                            {humanizeStatus(r.status)}
                          </Badge>
                          {r.estimate_unavailable && (
                            <Badge variant="warning" className="ml-1">
                              no estimate
                            </Badge>
                          )}
                        </td>
                        <td className="px-4 py-2 text-gray-400">
                          {formatTimestamp(r.started_at)}
                        </td>
                        <td className="px-4 py-2 text-gray-400">
                          {formatTimestamp(r.finished_at) || '-'}
                        </td>
                        <td className="px-4 py-2 text-gray-400">
                          {formatBytes(r.byte_count)}
                        </td>
                        <td className="px-4 py-2 text-gray-400">
                          {r.package_count ?? '-'}
                        </td>
                        <td className="px-4 py-2 text-right">
                          {r.status === 'ok' && r.manifest_sha256 ? (
                            <Link
                              href={`/mirrors/${mirror.id}/runs/${r.id}`}
                              className="text-blue-400 hover:text-blue-300"
                            >
                              view
                            </Link>
                          ) : r.error_text ? (
                            <button
                              onClick={() =>
                                setExpandedRun(expandedRun === r.id ? null : r.id)
                              }
                              className="text-gray-400 hover:text-gray-200"
                            >
                              {expandedRun === r.id ? 'hide error' : 'show error'}
                            </button>
                          ) : (
                            '-'
                          )}
                        </td>
                      </tr>
                      {expandedRun === r.id && r.error_text && (
                        <tr>
                          <td
                            colSpan={7}
                            className="border-t border-zinc-800 bg-black/40 px-4 py-2 font-mono text-xs text-red-300"
                          >
                            {r.error_text}
                          </td>
                        </tr>
                      )}
                    </React.Fragment>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </MainLayout>
  );
};

const DefField: React.FC<{ label: string; value: React.ReactNode; mono?: boolean }> = ({
  label,
  value,
  mono,
}) => (
  <div className="rounded border border-zinc-800 bg-[#111115] p-3">
    <div className="text-xs uppercase text-gray-500">{label}</div>
    <div className={`mt-1 text-sm text-gray-200 ${mono ? 'font-mono' : ''}`}>
      {value}
    </div>
  </div>
);

export default MirrorDetailPage;
