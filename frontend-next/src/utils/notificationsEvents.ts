// PRA-267: lightweight cross-component invalidation for notification read-state.
//
// There is no shared notification context, and the top-bar bell + status ribbon
// each own their own unread-count state with a 30s poll. When the Alerts page (or
// the bell popover) successfully marks notifications read, it dispatches this
// plain DOM event; TopBar and StatusRibbon listen and immediately refetch the
// authoritative unread-count endpoint, so every badge/count updates without a
// full reload or waiting for the next poll. A DOM event keeps this dependency-free.

export const NOTIFICATIONS_CHANGED_EVENT = 'praxis:notifications-changed';

/** Signal that notification read-state changed. Safe to call during SSR (no-op). */
export function emitNotificationsChanged(): void {
  if (typeof window === 'undefined') return;
  window.dispatchEvent(new Event(NOTIFICATIONS_CHANGED_EVENT));
}

/** Subscribe to notification read-state changes. Returns an unsubscribe fn. */
export function onNotificationsChanged(handler: () => void): () => void {
  if (typeof window === 'undefined') return () => {};
  window.addEventListener(NOTIFICATIONS_CHANGED_EVENT, handler);
  return () => window.removeEventListener(NOTIFICATIONS_CHANGED_EVENT, handler);
}
