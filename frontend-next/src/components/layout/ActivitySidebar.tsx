import React, { useCallback, useEffect, useRef, useState } from 'react';
import Link from 'next/link';
import { motion, AnimatePresence } from 'framer-motion';
import {
  Activity,
  Server,
  Layers,
  Briefcase,
  Package,
  Bell,
  ChevronRight,
  ChevronLeft,
  RefreshCw,
} from 'lucide-react';
import type { LucideIcon } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import { useAuth } from '@/context/AuthContext';
import { eventVariant, eventTextClass } from '@/utils/eventPresentation';

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
  details?: Record<string, unknown>;
}

// PRA-350: source selects the icon SHAPE (category); its COLOR comes from the
// shared severity helper, so a notification is no longer a red bell by default.
const sourceIcon: Record<string, LucideIcon> = {
  audit: Server,
  fleet_op: Layers,
  job: Briefcase,
  package: Package,
  notification: Bell,
};

// PRA-350: `notification` was labeled "Alert" for every item - misleading for
// routine/success events. It now reads as the neutral category "Notification";
// severity is conveyed by the icon color.
const sourceLabel: Record<string, string> = {
  audit: 'Audit',
  fleet_op: 'Fleet Op',
  job: 'Job',
  package: 'Package',
  notification: 'Notification',
};

const itemHref = (item: FeedItem): string => {
  if (item.source === 'audit' && item.system_id) return `/system-management/system/${item.system_id}`;
  if (item.source === 'fleet_op') return '/monitoring-reporting/fleet-operations-history';
  if (item.source === 'job') return '/job-scheduling/job-history';
  if (item.source === 'package' && item.system_id) return `/system-management/system/${item.system_id}`;
  if (item.source === 'notification') return '/monitoring-reporting/alerts';
  return '/monitoring-reporting/activity-feed';
};

const relTime = (ts: string | null) => {
  if (!ts) return '-';
  const diff = Date.now() - new Date(ts).getTime();
  if (diff < 0) return 'just now';
  const mins = Math.floor(diff / 60000);
  if (mins < 1) return 'just now';
  if (mins < 60) return `${mins}m`;
  const hours = Math.floor(mins / 60);
  if (hours < 24) return `${hours}h`;
  const days = Math.floor(hours / 24);
  return `${days}d`;
};

const STORAGE_KEY = 'praxis-activity-sidebar-open';
const POLL_INTERVAL_MS = 15_000;
const PAGE_SIZE = 15;

const ActivitySidebar: React.FC = () => {
  const { user } = useAuth();
  const [open, setOpen] = useState(false);
  const [items, setItems] = useState<FeedItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [unseenCount, setUnseenCount] = useState(0);
  const lastSeenIdRef = useRef<string | null>(null);

  // Restore open state
  useEffect(() => {
    if (typeof window === 'undefined') return;
    setOpen(localStorage.getItem(STORAGE_KEY) === '1');
  }, []);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    localStorage.setItem(STORAGE_KEY, open ? '1' : '0');
  }, [open]);

  const load = useCallback(async () => {
    if (!user) return;
    setLoading(true);
    try {
      const res = await apiFetch(`/api/backend/activity/feed?page=1&page_size=${PAGE_SIZE}`);
      if (!res.ok) return;
      const data = await res.json();
      const next: FeedItem[] = data.items || [];
      setItems(next);

      // Count items newer than last-seen marker (only if sidebar is closed)
      if (!open && next.length > 0) {
        const lastSeen = lastSeenIdRef.current;
        if (lastSeen === null) {
          // First load - set marker, no count
          lastSeenIdRef.current = next[0].id;
        } else {
          const idx = next.findIndex((i) => i.id === lastSeen);
          setUnseenCount(idx === -1 ? next.length : idx);
        }
      }
    } catch {
      // silent - sidebar is best-effort
    } finally {
      setLoading(false);
    }
  }, [user, open]);

  // Initial load + polling
  useEffect(() => {
    if (!user) return;
    load();
    const t = setInterval(load, POLL_INTERVAL_MS);
    return () => clearInterval(t);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  // Mark all as seen when opening
  useEffect(() => {
    if (open && items.length > 0) {
      lastSeenIdRef.current = items[0].id;
      setUnseenCount(0);
    }
  }, [open, items]);

  if (!user) return null;

  return (
    <>
      {/* Collapsed handle - always visible on right edge */}
      <button
        onClick={() => setOpen((o) => !o)}
        aria-label={open ? 'Close activity sidebar' : 'Open activity sidebar'}
        className={`fixed right-0 top-1/2 -translate-y-1/2 z-[80] flex items-center gap-1.5 px-2 py-3 bg-surface border border-r-0 border-border/60 rounded-l-md text-xs text-content-muted hover:text-content hover:bg-white/5 transition-colors ${open ? 'right-[340px]' : 'right-0'}`}
      >
        {open ? <ChevronRight size={14} /> : <ChevronLeft size={14} />}
        <Activity size={13} className="text-content-muted" />
        {!open && unseenCount > 0 && (
          <span className="ml-1 inline-flex items-center justify-center min-w-[16px] h-4 px-1 rounded-full bg-danger text-danger-fg text-[10px] font-semibold tabular-nums">
            {unseenCount > 9 ? '9+' : unseenCount}
          </span>
        )}
      </button>

      <AnimatePresence>
        {open && (
          <motion.aside
            initial={{ x: '100%' }}
            animate={{ x: 0 }}
            exit={{ x: '100%' }}
            transition={{ duration: 0.2, ease: [0.32, 0.72, 0, 1] }}
            className="fixed top-0 right-0 h-full w-[340px] z-[75] bg-surface border-l border-border/60 shadow-2xl flex flex-col"
          >
            <div className="flex items-center justify-between px-4 py-3 border-b border-border">
              <div className="flex items-center gap-2">
                <Activity size={14} className="text-content-muted" />
                <span className="text-sm font-semibold text-content tracking-tight">Activity</span>
              </div>
              <button
                onClick={load}
                aria-label="Refresh activity"
                className="p-1 text-content-subtle hover:text-content rounded transition-colors"
                title="Refresh"
              >
                <RefreshCw size={13} className={loading ? 'animate-spin' : ''} />
              </button>
            </div>

            <div className="flex-1 overflow-y-auto px-1.5 py-2">
              {items.length === 0 && !loading ? (
                <div className="text-center text-xs text-content-subtle py-8 px-4">
                  No recent activity. Events will appear here as they happen.
                </div>
              ) : (
                <div className="space-y-1">
                  {items.map((item) => {
                    const variant = eventVariant({
                      type: item.event_type,
                      severity: item.details?.severity as string | undefined,
                      source: item.source,
                    });
                    const Icon = sourceIcon[item.source] || Activity;
                    return (
                    <Link
                      key={item.id}
                      href={itemHref(item)}
                      className="block px-2.5 py-2 rounded-md hover:bg-white/[0.04] transition-colors group"
                    >
                      <div className="flex items-start gap-2">
                        <div className="mt-0.5 shrink-0">
                          <Icon size={13} className={eventTextClass(variant)} />
                        </div>
                        <div className="flex-1 min-w-0">
                          <div className="flex items-center gap-1.5 mb-0.5">
                            <span className="text-[10px] uppercase tracking-wider text-content-subtle font-medium">
                              {sourceLabel[item.source] || item.source}
                            </span>
                            <span className="text-[10px] text-content-subtle tabular-nums">{relTime(item.timestamp)}</span>
                          </div>
                          <div className="text-xs text-content-muted leading-snug group-hover:text-content transition-colors line-clamp-2">
                            {item.description}
                          </div>
                          {(item.system_hostname || item.username) && (
                            <div className="text-[10px] text-content-subtle mt-0.5 truncate">
                              {item.system_hostname && <span>{item.system_hostname}</span>}
                              {item.system_hostname && item.username && <span className="mx-1">·</span>}
                              {item.username && <span>{item.username}</span>}
                            </div>
                          )}
                        </div>
                      </div>
                    </Link>
                    );
                  })}
                </div>
              )}
            </div>

            <Link
              href="/monitoring-reporting/activity-feed"
              className="px-4 py-3 border-t border-border text-xs text-center text-content-muted hover:text-link-hover hover:bg-white/[0.02] transition-colors"
            >
              View full activity feed →
            </Link>
          </motion.aside>
        )}
      </AnimatePresence>
    </>
  );
};

export default ActivitySidebar;
