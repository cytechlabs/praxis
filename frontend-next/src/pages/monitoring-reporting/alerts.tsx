import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import { toast } from 'sonner';
import { RefreshCw, CheckCheck, Check, Bell } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import {
  Notification,
  fetchNotifications,
  fetchUnreadCount,
  markNotificationRead,
  markAllNotificationsRead,
} from '@/services/notificationService';
import {
  emitNotificationsChanged,
  onNotificationsChanged,
} from '@/utils/notificationsEvents';
import { eventVariant, eventTextClass, eventDotClass } from '@/utils/eventPresentation';

const PAGE_SIZE = 100;

type FilterMode = 'all' | 'unread';

const AlertsPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [total, setTotal] = useState(0);
  const [unreadCount, setUnreadCount] = useState(0);
  const [loading, setLoading] = useState(true);
  const [filter, setFilter] = useState<FilterMode>('all');
  const [busyIds, setBusyIds] = useState<Set<number>>(new Set());
  const [markingAll, setMarkingAll] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    try {
      const isRead = filter === 'unread' ? false : undefined;
      const [listRes, countRes] = await Promise.all([
        fetchNotifications(isRead, PAGE_SIZE, 0),
        fetchUnreadCount(),
      ]);
      setNotifications(listRes.notifications);
      setTotal(listRes.total);
      setUnreadCount(countRes.unread_count);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load alerts');
    } finally {
      setLoading(false);
    }
  }, [filter]);

  useEffect(() => {
    load();
  }, [load]);

  // PRA-267 fix pass: also LISTEN for read-state changes (e.g. the top-bar bell
  // popover marking alerts read while this page is open) and reload from the
  // backend so the list can't go stale. The page's own mutations also emit this
  // event, which yields one authoritative reload - acceptable and keeps the list
  // consistent with the counts. load() does not emit, so there is no loop.
  useEffect(() => onNotificationsChanged(() => load()), [load]);

  // After a successful mutation, resync the authoritative unread count for this
  // page and notify the top-bar bell + status ribbon so their badges update now.
  const syncUnread = useCallback(async () => {
    try {
      const { unread_count } = await fetchUnreadCount();
      setUnreadCount(unread_count);
    } catch {
      // best-effort; the count refresh should not surface a second error toast
    }
    emitNotificationsChanged();
  }, []);

  const handleMarkOne = async (n: Notification) => {
    if (n.is_read || busyIds.has(n.id)) return;
    setBusyIds((prev) => new Set(prev).add(n.id));
    try {
      await markNotificationRead(n.id);
      // Only mutate the row after the API confirms the change.
      setNotifications((prev) =>
        filter === 'unread'
          ? prev.filter((x) => x.id !== n.id)
          : prev.map((x) => (x.id === n.id ? { ...x, is_read: true } : x))
      );
      await syncUnread();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to mark alert as read');
    } finally {
      setBusyIds((prev) => {
        const next = new Set(prev);
        next.delete(n.id);
        return next;
      });
    }
  };

  const handleMarkAll = async () => {
    if (markingAll || unreadCount === 0) return;
    setMarkingAll(true);
    try {
      const res = await markAllNotificationsRead();
      toast.success(
        res.updated_count === 1
          ? 'Marked 1 alert as read'
          : `Marked ${res.updated_count} alerts as read`
      );
      // Reload the list from the backend so read state is authoritative, then
      // resync counts + notify the other surfaces.
      await load();
      await syncUnread();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to mark all as read');
    } finally {
      setMarkingAll(false);
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Alerts | Praxis</title>
      </Head>
      <PageHeader
        title="Alerts"
        actions={
          <div className="flex items-center gap-2">
            {unreadCount > 0 && (
              <Button
                variant="primary"
                size="sm"
                onClick={handleMarkAll}
                loading={markingAll}
                icon={<CheckCheck className="w-4 h-4" />}
              >
                Mark all as read
              </Button>
            )}
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
          {/* Filter + summary */}
          <div className="flex flex-wrap items-center justify-between gap-3 mb-5">
            <div className="inline-flex rounded-md border border-gray-800 overflow-hidden text-sm">
              {(['all', 'unread'] as FilterMode[]).map((mode) => (
                <button
                  key={mode}
                  type="button"
                  onClick={() => setFilter(mode)}
                  aria-pressed={filter === mode}
                  className={`px-3 py-1 capitalize transition-colors ${
                    filter === mode
                      ? 'bg-red-500/15 text-red-300'
                      : 'text-gray-400 hover:text-gray-200 hover:bg-white/5'
                  }`}
                >
                  {mode}
                </button>
              ))}
            </div>
            <span className="text-xs text-gray-500 tabular-nums">
              {unreadCount} unread
            </span>
          </div>

          {loading ? (
            <div className="py-12 text-center text-sm text-gray-500">Loading alerts…</div>
          ) : notifications.length === 0 ? (
            <div className="py-12 text-center text-sm text-gray-600">
              <Bell className="w-6 h-6 mx-auto mb-2 text-gray-700" />
              {filter === 'unread' ? 'No unread alerts' : 'No alerts'}
            </div>
          ) : (
            <ul className="divide-y divide-gray-800/60">
              {notifications.map((n) => {
                const unread = !n.is_read;
                const variant = eventVariant({ type: n.type, severity: n.severity });
                return (
                  <li
                    key={n.id}
                    className={`flex items-start gap-3 px-2 py-3 ${
                      unread ? 'bg-white/[0.02]' : 'opacity-70'
                    }`}
                  >
                    <span
                      aria-hidden="true"
                      className={`mt-1.5 w-2 h-2 rounded-full flex-shrink-0 ${
                        unread ? eventDotClass(variant) : 'bg-transparent border border-gray-700'
                      }`}
                    />
                    <div className="flex-1 min-w-0">
                      <div className="flex items-center gap-2">
                        <span
                          className={`text-sm font-medium ${eventTextClass(variant)}`}
                        >
                          {n.title}
                        </span>
                        {unread ? (
                          <span className="text-[10px] uppercase tracking-wide font-semibold text-red-300 bg-red-500/10 px-1.5 py-0.5 rounded">
                            Unread
                          </span>
                        ) : (
                          <span className="inline-flex items-center gap-0.5 text-[10px] uppercase tracking-wide text-gray-600">
                            <Check className="w-3 h-3" /> Read
                          </span>
                        )}
                      </div>
                      {n.message && (
                        <p className="text-xs text-gray-500 mt-0.5 break-words">{n.message}</p>
                      )}
                      <p className="text-xs text-gray-700 mt-1">{formatTimestamp(n.created_at)}</p>
                    </div>
                    {unread && (
                      <Button
                        variant="outline"
                        size="sm"
                        onClick={() => handleMarkOne(n)}
                        loading={busyIds.has(n.id)}
                        icon={<Check className="w-4 h-4" />}
                        aria-label={`Mark "${n.title}" as read`}
                      >
                        Mark read
                      </Button>
                    )}
                  </li>
                );
              })}
            </ul>
          )}

          {!loading && total > notifications.length && (
            <p className="mt-4 text-center text-xs text-gray-600">
              Showing {notifications.length} of {total}. Mark alerts read to clear the
              list, or refine with the filter above.
            </p>
          )}
        </CardBody>
      </Card>
    </MainLayout>
  );
};

export default AlertsPage;
