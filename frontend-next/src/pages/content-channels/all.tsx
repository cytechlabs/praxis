import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { Eye, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import {
  Badge,
  PageHeader,
  DataTable,
  EmptyState,
  ErrorState,
  Button,
  FormActions,
  FormField,
  Input,
  Select,
} from '@/components/ui';
import {
  createChannel,
  deleteChannel,
  listChannels,
  type ContentChannel,
  type PackageFamily,
} from '@/services/contentChannelService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const ContentChannelsListPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [channels, setChannels] = useState<ContentChannel[] | null>(null);
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
      const data = await listChannels();
      setChannels(data);
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
      await createChannel({
        slug: form.slug,
        display_name: form.display_name,
        package_family: form.package_family,
        description: form.description || null,
      });
      toast.success(`Created channel "${form.slug}"`);
      setShowCreate(false);
      setForm({ slug: '', display_name: '', package_family: 'deb', description: '' });
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to create channel');
    } finally {
      setCreating(false);
    }
  };

  const handleDelete = async (channel: ContentChannel) => {
    if (!window.confirm(`Soft-delete channel "${channel.slug}"?`)) return;
    try {
      await deleteChannel(channel.id);
      toast.success(`Deleted channel "${channel.slug}"`);
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to delete channel');
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Content channels · Praxis</title>
      </Head>
      <div className="p-6">
        <PageHeader
          title="Content channels"
          subtitle="Channels bundle one or more mirrors of the same package family. Profiles compose channels and are the host-facing object - see Content profiles."
          actions={
            <Button
              variant="primary"
              size="sm"
              icon={<Plus size={16} />}
              onClick={() => setShowCreate(true)}
            >
              New channel
            </Button>
          }
        />

        {showCreate && (
          <div className="mb-4 rounded-lg border border-border bg-surface-raised p-4">
            <h3 className="mb-3 text-sm font-medium text-content">New content channel</h3>
            <div className="grid grid-cols-1 gap-3 md:grid-cols-2">
              <FormField label="Slug" htmlFor="content-channel-slug" required>
                <Input
                  id="content-channel-slug"
                  className="font-mono"
                  value={form.slug}
                  onChange={(e) => setForm({ ...form, slug: e.target.value })}
                  placeholder="prod-ubuntu-22-04"
                />
              </FormField>
              <FormField label="Display name" htmlFor="content-channel-display-name" required>
                <Input
                  id="content-channel-display-name"
                  value={form.display_name}
                  onChange={(e) => setForm({ ...form, display_name: e.target.value })}
                />
              </FormField>
              <FormField label="Package family" htmlFor="content-channel-package-family">
                <Select
                  id="content-channel-package-family"
                  value={form.package_family}
                  onChange={(e) =>
                    setForm({ ...form, package_family: e.target.value as PackageFamily })
                  }
                >
                  <option value="deb">deb</option>
                  <option value="rpm">rpm</option>
                </Select>
              </FormField>
              <FormField
                label="Description"
                htmlFor="content-channel-description"
                helper="Optional"
                className="md:col-span-2"
              >
                <textarea
                  id="content-channel-description"
                  className="w-full rounded-md border border-border bg-surface-sunken px-3 py-2 text-sm text-content transition-colors duration-150 placeholder:text-content-subtle focus:outline-none focus-visible:border-border-strong focus-visible:ring-2 focus-visible:ring-focusring"
                  rows={2}
                  value={form.description}
                  onChange={(e) => setForm({ ...form, description: e.target.value })}
                />
              </FormField>
            </div>
            <FormActions>
              <Button
                variant="primary"
                size="sm"
                loading={creating}
                onClick={handleCreate}
                disabled={creating || !form.slug || !form.display_name}
              >
                Create
              </Button>
              <Button variant="secondary" size="sm" onClick={() => setShowCreate(false)}>
                Cancel
              </Button>
            </FormActions>
          </div>
        )}

        {/* PRA-269: migrated to the shared DataTable primitive (proof migration). */}
        {error ? (
          <ErrorState title="Couldn’t load content channels" onRetry={refresh} />
        ) : (
          <DataTable
            loading={channels === null}
            rows={channels ?? []}
            rowKey={(c) => c.id}
            minWidth="min-w-[640px]"
            columns={[
              {
                key: 'slug',
                header: 'Slug',
                render: (c) => (
                  <div>
                    <Link
                      href={`/content-channels/${c.id}`}
                      className="font-mono text-link hover:text-link-hover underline underline-offset-2"
                    >
                      {c.slug}
                    </Link>
                    <div className="text-xs text-content-subtle">{c.display_name}</div>
                  </div>
                ),
              },
              {
                key: 'family',
                header: 'Family',
                render: (c) => <Badge variant="neutral">{c.package_family?.toUpperCase()}</Badge>,
              },
              { key: 'repos', header: 'Repos', render: (c) => c.repos.length },
              { key: 'created', header: 'Created', render: (c) => formatTimestamp(c.created_at) },
            ]}
            rowActions={(c) => (
              <div className="inline-flex items-center gap-1">
                <Link
                  href={`/content-channels/${c.id}`}
                  title="View detail"
                  className="inline-flex p-1 rounded text-content-subtle hover:text-content"
                >
                  <Eye size={16} />
                </Link>
                <Button
                  variant="ghost"
                  size="sm"
                  iconOnly
                  aria-label="Soft-delete"
                  title="Soft-delete"
                  icon={<Trash2 size={16} />}
                  onClick={() => handleDelete(c)}
                />
              </div>
            )}
            empty={
              <EmptyState
                variant="no-activity"
                title="No content channels yet"
                description="Create one to start tracking repositories."
              />
            }
          />
        )}
      </div>
    </MainLayout>
  );
};

export default ContentChannelsListPage;
