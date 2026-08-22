import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Eye, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Badge, ErrorState, LoadingState, nativeSelectClass, PageHeader } from '@/components/ui';
import {
  createProfile,
  deleteProfile,
  listProfiles,
  type ContentProfile,
} from '@/services/contentProfileService';
import type { PackageFamily } from '@/services/contentChannelService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const ContentProfilesListPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [profiles, setProfiles] = useState<ContentProfile[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showCreate, setShowCreate] = useState(false);
  const [creating, setCreating] = useState(false);
  const [form, setForm] = useState<{
    slug: string;
    display_name: string;
    package_family: PackageFamily;
    description: string;
  }>({ slug: '', display_name: '', package_family: 'deb', description: '' });

  const refresh = useCallback(async () => {
    try {
      const data = await listProfiles();
      setProfiles(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleCreate = async () => {
    setCreating(true);
    try {
      await createProfile({
        slug: form.slug,
        display_name: form.display_name,
        package_family: form.package_family,
        description: form.description || null,
      });
      toast.success(`Created profile "${form.slug}"`);
      setShowCreate(false);
      setForm({ slug: '', display_name: '', package_family: 'deb', description: '' });
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to create profile');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (profile: ContentProfile) => {
    if (!window.confirm(`Soft-delete profile "${profile.slug}"?`)) return;
    try {
      await deleteProfile(profile.id);
      toast.success(`Deleted profile "${profile.slug}"`);
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to delete profile');
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Content profiles · Praxis</title>
      </Head>
      <div className="p-6">
        <PageHeader
          title="Content profiles"
          subtitle="Profiles are the host-facing object. Hosts (or groups, or smart groups) subscribe to a profile, and Praxis writes one source-list file per host based on the resolved profile."
          actions={
            <button
              onClick={() => setShowCreate(true)}
              className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500"
            >
              <Plus size={16} /> New profile
            </button>
          }
        />

        {error && (
          <ErrorState
            title="Couldn’t load content profiles"
            onRetry={refresh}
          />
        )}

        {showCreate && (
          <div className="mb-4 rounded border border-border bg-surface-raised p-4">
            <h3 className="mb-3 text-sm font-medium text-content">New content profile</h3>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <label className="text-xs text-content-muted">
                Slug
                <input
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 font-mono text-sm text-content"
                  value={form.slug}
                  onChange={(e) => setForm({ ...form, slug: e.target.value })}
                  placeholder="prod-deb"
                />
              </label>
              <label className="text-xs text-content-muted">
                Display name
                <input
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-content"
                  value={form.display_name}
                  onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                />
              </label>
              <label className="text-xs text-content-muted">
                Package family
                <select
                  className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                  value={form.package_family}
                  onChange={(e) =>
                    setForm({
                      ...form,
                      package_family: e.target.value as PackageFamily,
                    })
                  }
                >
                  <option value="deb">deb</option>
                  <option value="rpm">rpm</option>
                </select>
              </label>
              <label className="text-xs text-content-muted md:col-span-2">
                Description (optional)
                <textarea
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-content"
                  rows={2}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </label>
            </div>
            <div className="mt-3 flex gap-2">
              <button
                onClick={handleCreate}
                disabled={creating || !form.slug || !form.display_name}
                className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
              >
                {creating ? 'Creating…' : 'Create'}
              </button>
              <button
                onClick={() => setShowCreate(false)}
                className="rounded border border-border-strong px-3 py-1.5 text-sm text-content hover:bg-surface-overlay"
              >
                Cancel
              </button>
            </div>
          </div>
        )}

        {profiles === null && !error && <LoadingState label="Loading profiles" />}

        {profiles !== null && profiles.length === 0 && (
          <div className="rounded border border-border bg-surface-raised p-6 text-sm text-content-muted">
            No content profiles yet. Click <span className="text-content">New profile</span> to create one.
          </div>
        )}

        {profiles && profiles.length > 0 && (
          <div className="overflow-x-auto rounded border border-border bg-surface-raised">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-content-muted">
                <tr>
                  <th className="px-4 py-2">Slug</th>
                  <th className="px-4 py-2">Family</th>
                  <th className="px-4 py-2">Channels</th>
                  <th className="px-4 py-2">Created</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {profiles.map((p) => (
                  <tr key={p.id} className="hover:bg-surface-overlay/40">
                    <td className="px-4 py-2 font-mono text-content">
                      <Link
                        href={`/content-profiles/${p.id}`}
                        className="text-blue-400 hover:text-blue-300"
                      >
                        {p.slug}
                      </Link>
                      <div className="text-xs text-content-subtle">{p.display_name}</div>
                    </td>
                    <td className="px-4 py-2">
                      <Badge variant="neutral">{p.package_family?.toUpperCase()}</Badge>
                    </td>
                    <td className="px-4 py-2 text-content">{p.channels.length}</td>
                    <td className="px-4 py-2 text-content-muted">
                      {formatTimestamp(p.created_at)}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <Link
                        href={`/content-profiles/${p.id}`}
                        className="inline-flex items-center gap-1 rounded p-1 text-content-muted hover:text-blue-400"
                        title="View detail"
                      >
                        <Eye size={16} />
                      </Link>
                      <button
                        onClick={() => handleDelete(p)}
                        className="ml-1 inline-flex items-center gap-1 rounded p-1 text-content-muted hover:text-red-400"
                        title="Soft-delete"
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
      </div>
    </MainLayout>
  );
};

export default ContentProfilesListPage;
