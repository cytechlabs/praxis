import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, Plus, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Badge, ErrorState, LoadingState, PageHeader } from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  addGroupSubscription,
  addHostSubscription,
  addProfileChannel,
  addSmartGroupSubscription,
  getProfile,
  listProfileSubscribers,
  listProfileSubscriptions,
  removeGroupSubscription,
  removeHostSubscription,
  removeProfileChannel,
  removeSmartGroupSubscription,
  type ContentProfile,
  type ProfileSubscriber,
  type ScopeKind,
  type SubscriptionRow,
} from '@/services/contentProfileService';
import { listChannels, type ContentChannel } from '@/services/contentChannelService';
import {
  fetchAllSystems,
  fetchGroups,
  type GroupResponse,
  type SystemListItem,
} from '@/services/systemService';
import {
  listSmartGroups,
  type SmartGroupListItem,
} from '@/services/smartGroupService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const ContentProfileDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const idParam = router.query.id;
  const id = typeof idParam === 'string' ? Number(idParam) : null;

  const [profile, setProfile] = useState<ContentProfile | null>(null);
  const [allChannels, setAllChannels] = useState<ContentChannel[]>([]);
  const [subscriptions, setSubscriptions] = useState<SubscriptionRow[]>([]);
  const [subscribers, setSubscribers] = useState<ProfileSubscriber[]>([]);
  const [error, setError] = useState<string | null>(null);
  const [showAddChannel, setShowAddChannel] = useState(false);
  const [linkChannelId, setLinkChannelId] = useState<number | null>(null);
  const [linking, setLinking] = useState(false);
  const [showAddSub, setShowAddSub] = useState(false);
  const [subScope, setSubScope] = useState<ScopeKind>('host');
  const [subTargetId, setSubTargetId] = useState<number | null>(null);
  const [addingSub, setAddingSub] = useState(false);
  const [allSystems, setAllSystems] = useState<SystemListItem[]>([]);
  const [allGroups, setAllGroups] = useState<GroupResponse[]>([]);
  const [allSmartGroups, setAllSmartGroups] = useState<SmartGroupListItem[]>([]);
  const { canWrite } = useAuth();

  const refresh = useCallback(async () => {
    if (id == null || Number.isNaN(id)) return;
    try {
      const [p, c, subs, subers, systems, groups, smartGroups] = await Promise.all([
        getProfile(id, { include_deleted: true }),
        listChannels(),
        listProfileSubscriptions(id),
        listProfileSubscribers(id),
        fetchAllSystems().catch(() => [] as SystemListItem[]),
        fetchGroups().catch(() => [] as GroupResponse[]),
        listSmartGroups().catch(() => [] as SmartGroupListItem[]),
      ]);
      setProfile(p);
      setAllChannels(c);
      setSubscriptions(subs);
      setSubscribers(subers);
      setAllSystems(systems);
      setAllGroups(groups);
      setAllSmartGroups(smartGroups);
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
        <div className="p-6 text-gray-400">Invalid profile id.</div>
      </MainLayout>
    );
  }

  const linkedChannelIds = new Set(profile?.channels.map((l) => l.channel_id) ?? []);
  const eligibleChannels = profile
    ? allChannels.filter(
        (c) =>
          c.package_family === profile.package_family &&
          !c.deleted_at &&
          !linkedChannelIds.has(c.id),
      )
    : [];

  const handleLink = async () => {
    if (!profile || !linkChannelId) return;
    setLinking(true);
    try {
      await addProfileChannel(profile.id, linkChannelId);
      toast.success('Channel linked');
      setShowAddChannel(false);
      setLinkChannelId(null);
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Link failed');
    } finally {
      setLinking(false);
    }
  };

  const handleUnlink = async (channelId: number) => {
    if (!profile) return;
    if (!window.confirm('Unlink this channel from the profile?')) return;
    try {
      await removeProfileChannel(profile.id, channelId);
      toast.success('Channel unlinked');
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Unlink failed');
    }
  };

  // Subscribed target ids per scope, so each picker filters out what's already bound.
  const subscribedIds = (kind: ScopeKind) =>
    new Set(subscriptions.filter((s) => s.scope_kind === kind).map((s) => s.scope_id));
  const eligibleHosts = allSystems.filter((s) => !subscribedIds('host').has(s.id));
  const eligibleGroups = allGroups.filter((g) => !subscribedIds('group').has(g.id));
  const eligibleSmartGroups = allSmartGroups.filter(
    (g) => !subscribedIds('smart_group').has(g.id),
  );
  const eligibleForScope =
    subScope === 'host'
      ? eligibleHosts.map((h) => ({ id: h.id, label: h.hostname }))
      : subScope === 'group'
        ? eligibleGroups.map((g) => ({ id: g.id, label: g.name }))
        : eligibleSmartGroups.map((g) => ({
            id: g.id,
            label: `${g.name} (${g.member_count})`,
          }));

  const setScope = (kind: ScopeKind) => {
    setSubScope(kind);
    setSubTargetId(null); // reset the picker when the scope type changes
  };

  const handleAddSubscription = async () => {
    if (!profile || !subTargetId) return;
    setAddingSub(true);
    try {
      if (subScope === 'host') {
        await addHostSubscription(profile.id, subTargetId);
      } else if (subScope === 'group') {
        await addGroupSubscription(profile.id, subTargetId);
      } else {
        await addSmartGroupSubscription(profile.id, subTargetId);
      }
      toast.success('Subscription added');
      setShowAddSub(false);
      setSubTargetId(null);
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Subscribe failed');
    } finally {
      setAddingSub(false);
    }
  };

  const handleRemoveSubscription = async (s: SubscriptionRow) => {
    if (!profile) return;
    if (!window.confirm(`Remove the ${s.scope_kind} subscription "${s.scope_label}"?`))
      return;
    try {
      if (s.scope_kind === 'host') {
        await removeHostSubscription(profile.id, s.scope_id);
      } else if (s.scope_kind === 'group') {
        await removeGroupSubscription(profile.id, s.scope_id);
      } else {
        await removeSmartGroupSubscription(profile.id, s.scope_id);
      }
      toast.success('Subscription removed');
      refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Remove failed');
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>{profile ? `${profile.slug} · Content profiles` : 'Content profile'} · Praxis</title>
      </Head>
      <div className="p-6">
        <Link
          href="/content-profiles/all"
          className="mb-3 inline-flex items-center gap-1 text-sm text-gray-400 hover:text-gray-200"
        >
          <ArrowLeft size={14} /> All content profiles
        </Link>

        {error && (
          <ErrorState title="Couldn’t load content profile" onRetry={refresh} />
        )}

        {profile === null && !error && <LoadingState label="Loading profile" />}

        {profile && (
          <>
            <PageHeader title={profile.display_name} subtitle={profile.slug} />

            {profile.deleted_at && (
              <div className="mb-4 rounded border border-yellow-900/40 bg-yellow-900/10 p-3 text-xs text-yellow-300">
                This profile is soft-deleted ({formatTimestamp(profile.deleted_at)}). Resolver and apply paths skip it.
              </div>
            )}

            <div className="mb-4 grid grid-cols-1 gap-3 md:grid-cols-3">
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300">
                <div className="text-xs text-gray-500">Family</div>
                <Badge variant="neutral">{profile.package_family?.toUpperCase()}</Badge>
              </div>
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300">
                <div className="text-xs text-gray-500">Channels</div>
                {profile.channels.length}
              </div>
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300">
                <div className="text-xs text-gray-500">Effective subscribers</div>
                {subscribers.length}
              </div>
            </div>

            {profile.description && (
              <div className="mb-4 rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-300 whitespace-pre-wrap">
                {profile.description}
              </div>
            )}

            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-200">Channels</h3>
              <button
                onClick={() => setShowAddChannel((v) => !v)}
                disabled={!!profile.deleted_at || eligibleChannels.length === 0}
                className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
              >
                <Plus size={14} /> Link channel
              </button>
            </div>

            {showAddChannel && (
              <div className="mb-3 rounded border border-zinc-800 bg-[#111115] p-3">
                <label className="text-xs text-gray-400">
                  Channel ({profile.package_family} only)
                  <select
                    className="mt-1 w-full rounded bg-black/40 px-2 py-1 text-sm text-gray-100"
                    value={linkChannelId ?? ''}
                    onChange={(e) =>
                      setLinkChannelId(e.target.value ? Number(e.target.value) : null)
                    }
                  >
                    <option value="">Select...</option>
                    {eligibleChannels.map((c) => (
                      <option key={c.id} value={c.id}>
                        {c.slug} ({c.repos.length} repo{c.repos.length === 1 ? '' : 's'})
                      </option>
                    ))}
                  </select>
                </label>
                <div className="mt-3 flex gap-2">
                  <button
                    onClick={handleLink}
                    disabled={linking || !linkChannelId}
                    className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
                  >
                    {linking ? 'Linking…' : 'Link'}
                  </button>
                  <button
                    onClick={() => setShowAddChannel(false)}
                    className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-zinc-800"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {profile.channels.length === 0 ? (
              <div className="mb-6 rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-500">
                No channels linked yet.
              </div>
            ) : (
              <div className="mb-6 overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
                <table className="w-full text-sm">
                  <thead className="border-b border-zinc-800 text-left text-gray-400">
                    <tr>
                      <th className="px-4 py-2">Channel</th>
                      <th className="px-4 py-2 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {profile.channels.map((link) => (
                      <tr key={link.id} className="hover:bg-zinc-900/40">
                        <td className="px-4 py-2">
                          <Link
                            href={`/content-channels/${link.channel_id}`}
                            className="font-mono text-blue-400 hover:text-blue-300"
                          >
                            {link.channel_slug}
                          </Link>
                          <div className="text-xs text-gray-500">
                            {link.channel_display_name}
                          </div>
                        </td>
                        <td className="px-4 py-2 text-right">
                          <button
                            onClick={() => handleUnlink(link.channel_id)}
                            disabled={!!profile.deleted_at}
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

            <div className="mb-2 flex items-center justify-between">
              <h3 className="text-sm font-medium text-gray-200">
                Subscriptions ({subscriptions.length})
              </h3>
              {canWrite && (
                <button
                  onClick={() => setShowAddSub((v) => !v)}
                  disabled={!!profile.deleted_at}
                  className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1 text-xs font-medium text-white hover:bg-blue-500 disabled:opacity-40"
                  title="Subscribe a host, group, or smart group to this profile"
                >
                  <Plus size={14} /> Add subscription
                </button>
              )}
            </div>

            {showAddSub && (
              <div className="mb-3 rounded border border-zinc-800 bg-[#111115] p-3">
                <div className="flex flex-wrap items-end gap-3">
                  <label className="text-xs text-gray-400">
                    Scope
                    <select
                      className="mt-1 block rounded bg-black/40 px-2 py-1 text-sm text-gray-100"
                      value={subScope}
                      onChange={(e) => setScope(e.target.value as ScopeKind)}
                    >
                      <option value="host">Host</option>
                      <option value="group">Group</option>
                      <option value="smart_group">Smart group</option>
                    </select>
                  </label>
                  <label className="flex-1 text-xs text-gray-400">
                    Target
                    <select
                      className="mt-1 block w-full rounded bg-black/40 px-2 py-1 text-sm text-gray-100"
                      value={subTargetId ?? ''}
                      onChange={(e) =>
                        setSubTargetId(e.target.value ? Number(e.target.value) : null)
                      }
                    >
                      <option value="">
                        {eligibleForScope.length === 0
                          ? `All ${subScope.replace('_', ' ')}s already subscribed`
                          : 'Select...'}
                      </option>
                      {eligibleForScope.map((t) => (
                        <option key={t.id} value={t.id}>
                          {t.label}
                        </option>
                      ))}
                    </select>
                  </label>
                </div>
                <div className="mt-3 flex gap-2">
                  <button
                    onClick={handleAddSubscription}
                    disabled={addingSub || !subTargetId}
                    className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-40"
                  >
                    {addingSub ? 'Subscribing…' : 'Subscribe'}
                  </button>
                  <button
                    onClick={() => setShowAddSub(false)}
                    className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-zinc-800"
                  >
                    Cancel
                  </button>
                </div>
              </div>
            )}

            {subscriptions.length === 0 ? (
              <div className="mb-6 rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-500">
                No subscriptions yet. Use{' '}
                <span className="text-gray-300">Add subscription</span> above to bind a
                host, group, or smart group - or assign this profile from a host&apos;s
                detail page.
              </div>
            ) : (
              <div className="mb-6 overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
                <table className="w-full text-sm">
                  <thead className="border-b border-zinc-800 text-left text-gray-400">
                    <tr>
                      <th className="px-4 py-2">Scope</th>
                      <th className="px-4 py-2">Label</th>
                      <th className="px-4 py-2">Created</th>
                      <th className="px-4 py-2 text-right">Actions</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {subscriptions.map((s) => (
                      <tr key={s.id} className="hover:bg-zinc-900/40">
                        <td className="px-4 py-2">
                          <Badge variant="neutral">{s.scope_kind}</Badge>
                        </td>
                        <td className="px-4 py-2 text-gray-200">{s.scope_label}</td>
                        <td className="px-4 py-2 text-gray-400">
                          {formatTimestamp(s.created_at)}
                        </td>
                        <td className="px-4 py-2 text-right">
                          {canWrite && (
                            <button
                              onClick={() => handleRemoveSubscription(s)}
                              disabled={!!profile.deleted_at}
                              className="inline-flex items-center gap-1 rounded p-1 text-gray-400 hover:text-red-400 disabled:opacity-30"
                              title="Remove subscription"
                            >
                              <Trash2 size={16} />
                            </button>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}

            <h3 className="mb-2 text-sm font-medium text-gray-200">
              Effective subscribers ({subscribers.length})
            </h3>
            <p className="mb-2 text-xs text-gray-500">
              Hosts whose effective resolution lands on this profile. Distinct
              from Subscriptions: hosts in conflict at the direct tier do not
              appear here.
            </p>
            {subscribers.length === 0 ? (
              <div className="rounded border border-zinc-800 bg-[#111115] p-3 text-sm text-gray-500">
                No effective subscribers yet.
              </div>
            ) : (
              <div className="overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
                <table className="w-full text-sm">
                  <thead className="border-b border-zinc-800 text-left text-gray-400">
                    <tr>
                      <th className="px-4 py-2">Host</th>
                      <th className="px-4 py-2">Via</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-zinc-800">
                    {subscribers.map((s) => (
                      <tr key={s.host_id} className="hover:bg-zinc-900/40">
                        <td className="px-4 py-2">
                          <Link
                            href={`/system-management/system/${s.host_id}`}
                            className="text-blue-400 hover:text-blue-300"
                          >
                            {s.hostname}
                          </Link>
                        </td>
                        <td className="px-4 py-2">
                          <Badge variant="neutral">{s.via_kind}</Badge>
                          {s.via_label && (
                            <span className="ml-2 text-xs text-gray-500">
                              {s.via_label}
                            </span>
                          )}
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

export default ContentProfileDetailPage;
