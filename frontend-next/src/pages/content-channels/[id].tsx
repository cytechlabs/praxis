import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Badge, ErrorState, LoadingState, PageHeader } from '@/components/ui';
import {
  addChannelRepo,
  getChannel,
  removeChannelRepo,
  type ContentChannel,
} from '@/services/contentChannelService';
import { listMirrors, type MirrorRepo } from '@/services/mirrorService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const ContentChannelDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const idParam = router.query.id;
  const id = typeof idParam === 'string' ? Number(idParam) : null;

  const [channel, setChannel] = useState<ContentChannel | null>(null);
  const [mirrors, setMirrors] = useState<MirrorRepo[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showAdd, setShowAdd] = useState(false);
  const [adding, setAdding] = useState(false);
  const [form, setForm] = useState<{
    mirror_id: number | null;
    suite_override: string;
  }>({ mirror_id: null, suite_override: '' });

  const refresh = useCallback(async () => {
    if (id == null || Number.isNaN(id)) return;
    try {
      const [c, m] = await Promise.all([
        getChannel(id, { include_deleted: true }),
        listMirrors(),
      ]);
      setChannel(c);
      setMirrors(m);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (id == null || Number.isNaN(id)) {
    return (
      <MainLayout>
        <div className="p-6 text-gray-400">Invalid channel id.</div>
      </MainLayout>
    );
  }

  const eligibleMirrors = mirrors.filter(
    (m) => channel && m.package_family === channel.package_family && !m.deleted_at,
  );

  const handleAddRepo = async () => {
    if (!channel || !form.mirror_id) return;
    setAdding(true);
    try {
      await addChannelRepo(channel.id, {
        mirror_id: form.mirror_id,
        suite_override: form.suite_override.trim() || null,
      });
      toast.success('Repo added to channel');
      setShowAdd(false);
      setForm({ mirror_id: null, suite_override: '' });
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Add repo failed');
    } finally {
      setAdding(false);
    }
  };

  const handleRemoveRepo = async (repoId: number) => {
    if (!channel) return;
    if (!window.confirm('Remove this mirror from the channel?')) return;
    try {
      await removeChannelRepo(channel.id, repoId);
      toast.success('Repo removed');
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Remove failed');
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>{channel ? `${channel.slug} · Content channels` : 'Content channel'} · Praxis</title>
      </Head>
      <div className="p-6">
        <Link
          href="/content-channels/all"
          className="mb-3 inline-flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200"
        >
          <ArrowLeft size={14} /> All content channels
        </Link>

        {error && (
          <ErrorState title="Couldn’t load content channel" onRetry={refresh} />
        )}

        {channel === null && !error && <LoadingState label="Loading channel" />}

        {channel && (
          <>
            <PageHeader title={channel.display_name} subtitle={channel.slug} />

            {channel.deleted_at && (
              <div className="mb-4 rounded border border-yellow-900/40 bg-yellow-900/10 p-3 text-xs text-yellow-300">
                This channel is soft-deleted ({formatTimestamp(channel.deleted_at)}). Resolver and apply paths skip it.
              </div>
            )}

            <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300">
                <div className="text-xs text-gray-500">Family</div>
                <Badge variant="neutral">{channel.package_family?.toUpperCase()}</Badge>
              </div>
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300">
                <div className="text-xs text-gray-500">Repos</div>
                {channel.repos.length}
              </div>
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300">
                <div className="text-xs text-gray-500">Created</div>
                {formatTimestamp(channel.created_at)}
              </div>
            </div>

            {channel.description && (
              <div className="mb-4 rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300 whitespace-pre-wrap">
                {channel.description}
              </div>
            )}

            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-200">Repos</h3>
              <button
                onClick={() => setShowAdd((v) => !v)}
                disabled={!!channel.deleted_at}
                className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
              >
                <Plus size={14} /> Add repo
              </button>
            </div>

            {showAdd && (
              <div className="mb-3 rounded border border-zinc-800 bg-[#111115] p-3">
                <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
                  <label className="text-xs text-gray-400">
                    Mirror ({channel.package_family} only)
                    <select
                      className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-gray-100"
                      value={form.mirror_id ?? ''}
                      onChange={(e) =>
                        setForm({
                          ...form,
                          mirror_id: e.target.value ? Number(e.target.value) : null,
                        })
                      }
                    >
                      <option value="">Select...</option>
                      {eligibleMirrors.map((m) => (
                        <option key={m.id} value={m.id}>
                          {m.slug} ({m.distribution})
                        </option>
                      ))}
                    </select>
                  </label>
                  <label className="text-xs text-gray-400">
                    Suite override (optional, e.g. <code>jammy-security</code>)
                    <input
                      className="mt-1 w-full rounded bg-black/40 px-2 py-1 font-mono text-sm text-gray-100"
                      value={form.suite_override}
                      onChange={(e) =>
                        setForm({ ...form, suite_override: e.target.value })
                      }
                    />
                  </label>
                </div>
                <div className="mt-3 flex gap-2">
                  <button
                    onClick={handleAddRepo}
                    disabled={adding || !form.mirror_id}
                    className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
                  >
                    {adding ? 'Adding…' : 'Add'}
                  </button>
                  <button
                    onClick={() => setShowAdd(false)}
                    className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-zinc-800"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {channel.repos.length === 0 ? (
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-500">
                No repos yet. Add one to start composing this channel.
              </div>
            ) : (
              <div className="overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
                <table className="w-full text-sm">
                  <thead className="border-b border-zinc-800 text-left text-gray-400">
                    <tr>
                      <th className="px-4 py-2">Mirror</th>
                      <th className="px-4 py-2">Suite</th>
                      <th className="px-4 py-2">Pin</th>
                      <th className="px-4 py-2 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {channel.repos.map((r) => (
                      <tr key={r.id} className="hover:bg-zinc-900/40">
                        <td className="px-4 py-2 font-mono text-gray-200">
                          {r.mirror_slug}
                        </td>
                        <td className="px-4 py-2 text-gray-300">
                          {r.effective_suite}
                          {r.suite_override && (
                            <Badge variant="neutral" className="ml-2">
                              override
                            </Badge>
                          )}
                        </td>
                        <td className="px-4 py-2 text-gray-400">
                          {r.pinned_run_id ? (
                            <span title={r.pinned_manifest_sha256 || undefined}>
                              run #{r.pinned_run_id}
                            </span>
                          ) : (
                            'live'
                          )}
                        </td>
                        <td className="px-4 py-2 text-right">
                          <button
                            onClick={() => handleRemoveRepo(r.id)}
                            disabled={!!channel.deleted_at}
                            className="inline-flex items-center gap-1 rounded p-1 text-gray-400 hover:text-red-400 disabled:opacity-30"
                          >
                            <Trash2 size={16} />
                          </button>
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </>
        )}
      </div>
    </MainLayout>
  );
};

export default ContentChannelDetailPage;
