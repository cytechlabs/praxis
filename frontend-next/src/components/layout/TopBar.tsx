import React, { useState, useEffect, useRef, useCallback } from 'react';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Bell, HelpCircle, LogOut, User, CheckCheck, Search } from 'lucide-react';
import { motion, AnimatePresence } from 'framer-motion';
import { toast } from 'sonner';
import { useAuth } from '@/context/AuthContext';
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
import ExceptionBadges from './ExceptionBadges';
import { BrandWordmark } from '@/components/ui/BrandLogo';
import WorkspaceTabs from './WorkspaceTabs';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { eventVariant, eventTextClass, eventDotClass } from '@/utils/eventPresentation';

interface TopBarProps {
  onOpenPalette: () => void;
}

const TopBar: React.FC<TopBarProps> = ({ onOpenPalette }) => {
  const formatTimestamp = useFormatTimestamp();
  const [showNotifications, setShowNotifications] = useState(false);
  const [notifications, setNotifications] = useState<Notification[]>([]);
  const [unreadCount, setUnreadCount] = useState(0);
  const notifRef = useRef<HTMLDivElement>(null);
  const router = useRouter();
  const { logout } = useAuth();

  const loadUnreadCount = useCallback(async () => {
    try {
      const data = await fetchUnreadCount();
      setUnreadCount(data.unread_count);
    } catch {
      // silent
    }
  }, []);

  const loadNotifications = useCallback(async () => {
    try {
      const data = await fetchNotifications(undefined, 20, 0);
      setNotifications(data.notifications);
    } catch {
      // silent
    }
  }, []);

  useEffect(() => {
    loadUnreadCount();
    const interval = setInterval(loadUnreadCount, 30000);
    return () => clearInterval(interval);
  }, [loadUnreadCount]);

  useEffect(() => {
    if (showNotifications) loadNotifications();
  }, [showNotifications, loadNotifications]);

  // PRA-267: when the Alerts page (or this popover) reports a read-state change,
  // refetch the authoritative unread count immediately - and the open popover
  // list - rather than waiting for the 30s poll.
  useEffect(
    () =>
      onNotificationsChanged(() => {
        loadUnreadCount();
        if (showNotifications) loadNotifications();
      }),
    [loadUnreadCount, loadNotifications, showNotifications]
  );

  useEffect(() => {
    const handleClickOutside = (e: MouseEvent) => {
      if (notifRef.current && !notifRef.current.contains(e.target as Node)) {
        setShowNotifications(false);
      }
    };
    document.addEventListener('mousedown', handleClickOutside);
    return () => document.removeEventListener('mousedown', handleClickOutside);
  }, []);

  const handleMarkRead = async (id: number) => {
    try {
      await markNotificationRead(id);
      setNotifications((prev) => prev.map((n) => (n.id === id ? { ...n, is_read: true } : n)));
      // Refresh the authoritative count (and the ribbon) via the shared event
      // instead of decrementing locally - keeps every surface honest.
      emitNotificationsChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to mark as read');
    }
  };

  const handleMarkAllRead = async () => {
    try {
      await markAllNotificationsRead();
      setNotifications((prev) => prev.map((n) => ({ ...n, is_read: true })));
      emitNotificationsChanged();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to mark all as read');
    }
  };

  const handleLogout = async () => {
    await logout();
    router.push('/login');
  };

  return (
    <header className="border-b border-border/60 bg-surface/90 backdrop-blur-md sticky top-0 z-50">
      {/* PRA-273: single-row console shell - brand + workspace tabs on the left;
          search, exception/all-clear status, and user controls on the right. The
          workspace drawer floats under the tabs. */}
      <div className="flex items-center gap-4 px-4 h-12">
        <Link
          href="/fleet-dashboard"
          aria-label="Praxis - dashboard"
          className="flex shrink-0 items-center rounded focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
        >
          <BrandWordmark height={30} />
        </Link>

        <WorkspaceTabs />

        <div className="flex-1" />

        <div className="flex shrink-0 items-center gap-2">
          {/* Exception / all-clear status sits to the LEFT of search. */}
          <ExceptionBadges />

          {/* Command Palette trigger */}
          <button
            onClick={onOpenPalette}
            className="hidden sm:flex items-center gap-2 px-2.5 py-1 text-xs text-content-subtle bg-surface-sunken/50 border border-border rounded-md hover:border-border-strong hover:text-content-muted transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
          >
            <Search size={13} />
            <span>Search</span>
            <kbd className="text-[10px] text-content-subtle bg-surface-overlay px-1 py-0.5 rounded">Ctrl+K</kbd>
          </button>

          <div className="flex items-center gap-1">
          {/* Notifications */}
          <div className="relative" ref={notifRef}>
            <button
              onClick={() => setShowNotifications(!showNotifications)}
              className="p-2 text-content-subtle hover:text-content transition-colors relative"
            >
              <Bell size={16} />
              {unreadCount > 0 && (
                <span className="absolute top-1 right-1 w-3.5 h-3.5 text-[9px] font-bold text-danger-fg bg-danger rounded-full flex items-center justify-center">
                  {unreadCount > 9 ? '9+' : unreadCount}
                </span>
              )}
            </button>

            <AnimatePresence>
              {showNotifications && (
                <motion.div
                  initial={{ opacity: 0, y: -4 }}
                  animate={{ opacity: 1, y: 0 }}
                  exit={{ opacity: 0, y: -4 }}
                  transition={{ duration: 0.12 }}
                  className="absolute right-0 mt-1 w-96 max-h-[28rem] rounded-lg shadow-2xl bg-surface border border-border/60 overflow-hidden flex flex-col z-50"
                >
                  <div className="flex items-center justify-between px-4 py-2.5 border-b border-border">
                    <span className="text-sm font-semibold text-content">Notifications</span>
                    {unreadCount > 0 && (
                      <button onClick={handleMarkAllRead} className="flex items-center text-xs text-content-subtle hover:text-content transition-colors">
                        <CheckCheck size={14} className="mr-1" />
                        Mark all read
                      </button>
                    )}
                  </div>
                  <div className="overflow-y-auto flex-1">
                    {notifications.length === 0 ? (
                      <div className="px-4 py-8 text-center text-sm text-content-subtle">No notifications</div>
                    ) : (
                      notifications.map((notif) => {
                        const variant = eventVariant({ type: notif.type, severity: notif.severity });
                        return (
                        <button
                          key={notif.id}
                          onClick={() => !notif.is_read && handleMarkRead(notif.id)}
                          className={`w-full text-left px-4 py-3 border-b border-border/50 hover:bg-white/[0.02] transition-colors ${
                            !notif.is_read ? 'bg-white/[0.02]' : ''
                          }`}
                        >
                          <div className="flex items-start gap-2">
                            <span className={`mt-1.5 w-1.5 h-1.5 rounded-full flex-shrink-0 ${
                              !notif.is_read ? eventDotClass(variant) : 'bg-transparent'
                            }`} />
                            <div className="flex-1 min-w-0">
                              <div className={`text-sm font-medium ${eventTextClass(variant)}`}>
                                {notif.title}
                              </div>
                              {notif.message && (
                                <div className="text-xs text-content-subtle mt-0.5 truncate">{notif.message}</div>
                              )}
                              <div className="text-xs text-content-subtle mt-1">{formatTimestamp(notif.created_at)}</div>
                            </div>
                          </div>
                        </button>
                        );
                      })
                    )}
                  </div>
                </motion.div>
              )}
            </AnimatePresence>
          </div>

          {/* Help */}
          <Link
            href="/help"
            target="_blank"
            rel="noopener noreferrer"
            title="Help"
            aria-label="Help"
            className="p-2 text-content-subtle hover:text-content transition-colors"
          >
            <HelpCircle size={16} />
          </Link>

          {/* User */}
          <Link href="/preferences" className="p-2 text-content-subtle hover:text-content transition-colors">
            <User size={16} />
          </Link>
          <button
            onClick={handleLogout}
            title="Log out"
            aria-label="Log out"
            className="p-2 text-content-subtle hover:text-content transition-colors"
          >
            <LogOut size={16} />
          </button>
          </div>
        </div>
      </div>
    </header>
  );
};

export default TopBar;
