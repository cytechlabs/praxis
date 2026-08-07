/**
 * PRA-258: React-owned timestamp preferences.
 *
 * Replaces the old mutable module globals in `utils/formatTimestamp` (which
 * fetched at import time and never notified React). Preferences now live in
 * React state under this provider:
 *   - SSR-safe: no fetch at import or during SSR — the effect runs client-side
 *     only, and initial render uses stable defaults, then updates on the client.
 *   - Reactive: `useFormatTimestamp()` / `<FormattedTimestamp />` subscribe to
 *     the context, so every rendered timestamp re-renders when preferences load
 *     or change (e.g. after saving in General settings).
 *   - No poisoned cache: a failed fetch sets a local error and keeps the current
 *     (default or last-good) config; a `refresh()` retries.
 */
import {
  createContext,
  useCallback,
  useContext,
  useEffect,
  useMemo,
  useState,
  type ReactNode,
} from 'react';
import {
  DEFAULT_TIMESTAMP_CONFIG,
  formatTimestamp,
  parseTimestampConfig,
  type FormatTimestampOptions,
  type TimestampConfig,
} from '../utils/formatTimestamp';
import { useAuth } from './AuthContext';

interface TimestampPreferencesContextValue {
  config: TimestampConfig;
  loading: boolean;
  error: string | null;
  refresh: () => Promise<void>;
}

/**
 * Load timestamp preferences from the public app-settings endpoint.
 *
 * SSR-safe: returns defaults without any network call when there is no window
 * (import/SSR). Uses plain `fetch` (not `apiFetch`) so an unauthenticated
 * login page can't trigger a 401 redirect loop. Throws on a non-OK response so
 * the provider can surface an error while keeping the current config.
 */
export async function fetchTimestampConfig(): Promise<TimestampConfig> {
  if (typeof window === 'undefined') {
    return DEFAULT_TIMESTAMP_CONFIG;
  }
  const res = await fetch('/api/backend/app-settings');
  if (!res.ok) {
    throw new Error(`app-settings request failed: ${res.status}`);
  }
  return parseTimestampConfig(await res.json());
}

// A default value so consumers rendered outside the provider (edge cases,
// isolated tests) still format with defaults instead of crashing.
const DEFAULT_CONTEXT: TimestampPreferencesContextValue = {
  config: DEFAULT_TIMESTAMP_CONFIG,
  loading: false,
  error: null,
  refresh: async () => {},
};

const TimestampPreferencesContext =
  createContext<TimestampPreferencesContextValue>(DEFAULT_CONTEXT);

export function TimestampPreferencesProvider({ children }: { children: ReactNode }) {
  const { user, loading: authLoading } = useAuth();
  const userId = user?.id ?? null;
  const [config, setConfig] = useState<TimestampConfig>(DEFAULT_TIMESTAMP_CONFIG);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const next = await fetchTimestampConfig();
      setConfig(next);
      setError(null);
    } catch (e) {
      // Keep the current (default or last-good) config — never poison it.
      setError(e instanceof Error ? e.message : 'Failed to load timestamp preferences');
    } finally {
      setLoading(false);
    }
  }, []);

  // Client-only: effects don't run during SSR, so this never fetches on the
  // server or at import time. Also wait for auth: the settings endpoint is
  // authenticated, and password login is a client-side transition, so a
  // pre-login 401 must not become a stale default config after login.
  useEffect(() => {
    if (authLoading) return;
    if (userId === null) {
      setConfig(DEFAULT_TIMESTAMP_CONFIG);
      setError(null);
      setLoading(false);
      return;
    }
    void refresh();
  }, [authLoading, userId, refresh]);

  const value = useMemo(
    () => ({ config, loading, error, refresh }),
    [config, loading, error, refresh],
  );

  return (
    <TimestampPreferencesContext.Provider value={value}>
      {children}
    </TimestampPreferencesContext.Provider>
  );
}

export function useTimestampPreferences(): TimestampPreferencesContextValue {
  return useContext(TimestampPreferencesContext);
}

/**
 * Returns a `formatTimestamp`-compatible function bound to the current
 * preferences. Components that call this re-render when preferences change,
 * which is what makes existing `formatTimestamp(value, options)` call sites
 * reactive after a simple import swap.
 */
export function useFormatTimestamp() {
  const { config } = useTimestampPreferences();
  return useMemo(
    () =>
      (value: string | Date | null | undefined, options?: FormatTimestampOptions) =>
        formatTimestamp(value, options, config),
    [config],
  );
}

/** Subscribed rendering component for the common JSX case. */
export function FormattedTimestamp({
  value,
  dateOnly,
  timeOnly,
}: {
  value: string | Date | null | undefined;
} & FormatTimestampOptions) {
  const format = useFormatTimestamp();
  return <>{format(value, { dateOnly, timeOnly })}</>;
}
