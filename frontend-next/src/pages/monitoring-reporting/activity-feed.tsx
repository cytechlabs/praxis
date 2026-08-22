import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody, nativeSelectClass } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { RefreshCw, Filter, Activity, Server, Layers, Briefcase, Package, Bell } from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import {
  eventVariant,
  eventTextClass,
  eventCardClass,
} from '@/utils/eventPresentation';

interface FeedItem {
  id: string;
  source: string;
  event_type: string;
  description: string;
  user_id: number | null;
  username: string | null;
  system_id: number | null;
  system_hostname: string | null;
  timestamp: string | null;
  details: Record<string, unknown>;
}

interface SourceOption {
  value: string;
  label: string;
}

// PRA-350: source picks the icon SHAPE (category identity). Color and card wash
// come from the shared event-presentation helper (severity), never from the
// source - so a `notification` is no longer red just for being a notification.
const sourceIcon: Record<string, LucideIcon> = {
  audit: Server,
  fleet_op: Layers,
  job: Briefcase,
  package: Package,
  notification: Bell,
};

const relativeTime = (ts: string | null) => {
  if (!ts) return '-';
  const diff = Date.now() - new Date(ts).getTime();
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m ago`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h ago`;
  const days = Math.floor(hours / 24);
  return `${days}d ago`;
};

const ActivityFeed: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [items, setItems] = useState<FeedItem[]>([]);
  const [total, setTotal] = useState(0);
  const [page, setPage] = useState(1);
  const pageSize = 25;
  const [loading, setLoading] = useState(false);

  const [sources, setSources] = useState<SourceOption[]>([]);
  const [sourceFilter, setSourceFilter] = useState('');
  const [fromDate, setFromDate] = useState('');
  const [toDate, setToDate] = useState('');

  const loadSources = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/activity/feed/sources');
      if (!res.ok) throw new Error('Failed to load sources');
      const data = await res.json();
      setSources(data.sources);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load sources');
    }
  }, []);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('page', String(page));
      params.set('page_size', String(pageSize));
      if (sourceFilter) params.set('source', sourceFilter);
      if (fromDate) params.set('from_date', new Date(fromDate).toISOString());
      if (toDate) params.set('to_date', new Date(toDate).toISOString());
      const res = await apiFetch(`/api/backend/activity/feed?${params.toString()}`);
      if (!res.ok) throw new Error('Failed to load activity feed');
      const data = await res.json();
      setItems(data.items);
      setTotal(data.total);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load activity feed');
    } finally {
      setLoading(false);
    }
  }, [page, sourceFilter, fromDate, toDate]);

  useEffect(() => { loadSources(); }, [loadSources]);
  useEffect(() => { load(); }, [load]);

  const resetFilters = () => {
    setSourceFilter('');
    setFromDate('');
    setToDate('');
    setPage(1);
  };

  const totalPages = Math.max(1, Math.ceil(total / pageSize));

  return (
    <MainLayout>
        <Head>
          <title>Activity Feed | Praxis</title>
        </Head>
        <PageHeader
          title="Activity Feed"
          actions={
            <div className="flex items-center gap-2">
              <Button
                variant="outline"
                size="sm"
                onClick={() => load()}
                icon={<RefreshCw className="w-4 h-4" />}
              >
                Refresh
              </Button>
              <HelpLink slug="monitoring-and-alerts" />
            </div>
          }
        />

        <Card>
          <CardBody>
            {/* Filters */}
            <div className="flex flex-wrap items-end gap-4 mb-6">
              <div className="flex items-center gap-2">
                <Filter className="w-4 h-4 text-content-muted" />
                <span className="text-sm text-content-muted">Filters:</span>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">Source</label>
                <select
                  value={sourceFilter}
                  onChange={(e) => { setSourceFilter(e.target.value); setPage(1); }}
                  className={`border border-border rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                >
                  <option value="">All</option>
                  {sources.map((s) => (
                    <option key={s.value} value={s.value}>{s.label}</option>
                  ))}
                </select>
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">From</label>
                <input
                  type="date"
                  value={fromDate}
                  onChange={(e) => { setFromDate(e.target.value); setPage(1); }}
                  className="bg-surface-sunken border border-border rounded px-2 py-1 text-content text-sm"
                />
              </div>
              <div>
                <label className="block text-xs text-content-muted mb-1">To</label>
                <input
                  type="date"
                  value={toDate}
                  onChange={(e) => { setToDate(e.target.value); setPage(1); }}
                  className="bg-surface-sunken border border-border rounded px-2 py-1 text-content text-sm"
                />
              </div>
              <Button variant="outline" size="sm" onClick={resetFilters}>
                Reset
              </Button>
            </div>

            {/* Source pills */}
            <div className="flex flex-wrap gap-2 mb-4">
              <button
                onClick={() => { setSourceFilter(''); setPage(1); }}
                className={`px-3 py-1 rounded-full text-xs border ${!sourceFilter ? 'bg-border text-content border-border-strong' : 'bg-surface-overlay text-content-muted border-border hover:border-border-strong'}`}
              >
                All
              </button>
              {sources.map((s) => (
                <button
                  key={s.value}
                  onClick={() => { setSourceFilter(s.value); setPage(1); }}
                  className={`px-3 py-1 rounded-full text-xs border ${sourceFilter === s.value ? 'bg-border text-content border-border-strong' : 'bg-surface-overlay text-content-muted border-border hover:border-border-strong'}`}
                >
                  {s.label}
                </button>
              ))}
            </div>

            {/* Feed items */}
            {loading && <div className="p-4 text-content-muted">Loading...</div>}
            {!loading && items.length === 0 && (
              <div className="p-8 text-center text-content-muted">No activity found.</div>
            )}

            <div className="space-y-2">
              {!loading && items.map((item) => {
                const variant = eventVariant({
                  type: item.event_type,
                  severity: item.details?.severity as string | undefined,
                  source: item.source,
                });
                const Icon = sourceIcon[item.source] || Activity;
                return (
                <div
                  key={item.id}
                  className={`border rounded-lg p-4 ${eventCardClass(variant)}`}
                >
                  <div className="flex items-start gap-3">
                    <div className="mt-0.5">
                      <Icon className={`w-4 h-4 ${eventTextClass(variant)}`} />
                    </div>
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2 mb-1">
                        <span className="inline-block px-2 py-0.5 rounded text-xs border bg-surface-overlay text-content-muted border-border-strong capitalize">
                          {item.source.replace('_', ' ')}
                        </span>
                        <span className="text-xs text-content-subtle">{relativeTime(item.timestamp)}</span>
                        {item.timestamp && (
                          <span className="text-xs text-content-subtle">{formatTimestamp(item.timestamp)}</span>
                        )}
                      </div>
                      <p className="text-sm text-content">{item.description}</p>
                      <div className="flex flex-wrap gap-3 mt-1 text-xs text-content-muted">
                        {item.username && <span>User: {item.username}</span>}
                        {item.system_hostname && <span>System: {item.system_hostname}</span>}
                        {item.event_type && <span>Type: {item.event_type}</span>}
                      </div>
                    </div>
                  </div>
                </div>
                );
              })}
            </div>

            {/* Pagination */}
            <div className="flex items-center justify-between pt-4 mt-4">
              <span className="text-sm text-content-muted">
                {total > 0
                  ? `Showing ${(page - 1) * pageSize + 1}-${Math.min(page * pageSize, total)} of ${total}`
                  : 'No results'}
              </span>
              <div className="flex gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page <= 1}
                  onClick={() => setPage((p) => p - 1)}
                >
                  Previous
                </Button>
                <span className="text-sm text-content-muted self-center">Page {page} of {totalPages}</span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={page >= totalPages}
                  onClick={() => setPage((p) => p + 1)}
                >
                  Next
                </Button>
              </div>
            </div>
          </CardBody>
        </Card>
    </MainLayout>
  );
};

export default ActivityFeed;
