/**
 * PRA-257: Settings → Auth Logs.
 *
 * Reads the real, admin/auditor-gated audit stream through the shared
 * `/api/backend` proxy (apiFetch, via auditService) and shows the auth-relevant
 * subset - access sessions, approvals, MFA step-up, access requests/reviews/
 * revocations, SSH cert issuance, and enrollment tokens. Praxis does not record
 * discrete login/logout events today, so the copy says so instead of implying a
 * login feed.
 *
 * Resilience: auto-refresh stops after a few consecutive failures (no more
 * endless 10s polling against a broken endpoint) and a Refresh button both
 * reloads and resumes polling. Failures stay local to this tab - Settings
 * remains usable, and a transient poll error never wipes already-loaded rows.
 */
import { useCallback, useEffect, useRef, useState } from 'react';
import { RefreshCw } from 'lucide-react';
import { Badge, Button } from '@/components/ui';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import {
  POLL_INTERVAL_MS,
  fetchAuthLogRows,
  outcomeVariant,
  shouldKeepPolling,
  type AuthLogRow,
} from './authLogs';

const AuthLogsTab = () => {
  const formatTimestamp = useFormatTimestamp();
  const [rows, setRows] = useState<AuthLogRow[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);
  const [pollingStopped, setPollingStopped] = useState(false);
  const [selectedDetails, setSelectedDetails] = useState<string | null>(null);

  const failuresRef = useRef(0);
  const intervalRef = useRef<ReturnType<typeof setInterval> | null>(null);

  const stopPolling = useCallback(() => {
    if (intervalRef.current !== null) {
      clearInterval(intervalRef.current);
      intervalRef.current = null;
    }
  }, []);

  const load = useCallback(
    async (manual: boolean) => {
      if (manual) setLoading(true);
      try {
        const next = await fetchAuthLogRows();
        setRows(next);
        setError(null);
        failuresRef.current = 0;
        setPollingStopped(false);
      } catch (err) {
        // Keep previously-loaded rows; just surface the error locally.
        failuresRef.current += 1;
        setError(err instanceof Error ? err.message : 'Failed to load auth logs');
        if (!shouldKeepPolling(failuresRef.current)) {
          stopPolling();
          setPollingStopped(true);
        }
      } finally {
        if (manual) setLoading(false);
      }
    },
    [stopPolling],
  );

  const startPolling = useCallback(() => {
    stopPolling();
    intervalRef.current = setInterval(() => {
      void load(false);
    }, POLL_INTERVAL_MS);
  }, [load, stopPolling]);

  useEffect(() => {
    void (async () => {
      setLoading(true);
      await load(false);
      setLoading(false);
    })();
    startPolling();
    return stopPolling;
    // load/startPolling/stopPolling are stable (useCallback); run once on mount.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const handleRefresh = () => {
    void (async () => {
      await load(true);
      // Resume auto-refresh if it had stopped and we just recovered.
      if (intervalRef.current === null && failuresRef.current === 0) {
        startPolling();
      }
    })();
  };

  return (
    <div className="space-y-4">
      <div className="flex items-start justify-between gap-3">
        <div>
          <h2 className="text-xl mb-1">Auth Logs</h2>
          <p className="text-sm text-content-muted max-w-3xl">
            Access &amp; identity audit events - access sessions, approvals, MFA
            step-up, access requests, reviews, revocations, SSH certificate
            issuance, and enrollment tokens. Login and logout are not recorded as
            discrete events in this release.
          </p>
        </div>
        <Button variant="ghost" size="sm" onClick={handleRefresh} disabled={loading}>
          <RefreshCw size={14} className="mr-1" />
          Refresh
        </Button>
      </div>

      {error && (
        <div
          className="p-3 rounded border bg-red-900/30 border-red-800 text-red-200 text-sm flex items-center justify-between gap-3"
          role="alert"
        >
          <span>
            {error}
            {pollingStopped && ' - auto-refresh paused. Use Refresh to retry.'}
          </span>
        </div>
      )}

      {loading && rows.length === 0 ? (
        <div className="text-content-muted text-sm">Loading auth logs…</div>
      ) : (
        <div className="bg-surface-raised border border-border/60 rounded overflow-hidden">
          <div className="overflow-x-auto max-h-[600px] overflow-y-auto">
            <table className="min-w-full">
              <thead className="sticky top-0 bg-surface-raised">
                <tr className="border-b border-border/60">
                  <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-content-muted">Timestamp</th>
                  <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-content-muted">Action</th>
                  <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-content-muted">Actor</th>
                  <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-content-muted">Outcome</th>
                  <th scope="col" className="px-6 py-3 text-left text-sm font-medium text-content-muted">Details</th>
                </tr>
              </thead>
              <tbody>
                {rows.map((row) => (
                  <tr key={row.key} className="border-b border-border/60 hover:bg-red-900/10">
                    <td className="px-6 py-4 text-sm text-content whitespace-nowrap">
                      {formatTimestamp(row.timestamp)}
                    </td>
                    <td className="px-6 py-4 text-sm text-content whitespace-nowrap font-mono">
                      {row.action}
                    </td>
                    <td className="px-6 py-4 text-sm text-content whitespace-nowrap">
                      {row.actor}
                    </td>
                    <td className="px-6 py-4 text-sm whitespace-nowrap">
                      <Badge variant={outcomeVariant(row.outcome)}>{row.outcome}</Badge>
                    </td>
                    <td className="px-6 py-4 text-sm text-content whitespace-nowrap">
                      <button
                        onClick={() => setSelectedDetails(row.details)}
                        className="bg-red-800 hover:bg-red-700 text-white px-3 py-1 rounded text-sm"
                      >
                        More Details
                      </button>
                    </td>
                  </tr>
                ))}
                {rows.length === 0 && (
                  <tr>
                    <td colSpan={5} className="px-6 py-4 text-sm text-content-muted text-center">
                      No access &amp; identity audit events found
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>
      )}

      {selectedDetails && (
        <div className="fixed inset-0 bg-surface/50 flex items-center justify-center p-4">
          <div className="bg-surface-overlay border border-border/60 rounded-lg p-6 max-w-2xl w-full max-h-[80vh] overflow-y-auto">
            <div className="flex justify-between items-start mb-4">
              <h3 className="text-lg font-medium text-content">Event Details</h3>
              <button
                onClick={() => setSelectedDetails(null)}
                className="text-content-muted hover:text-content"
              >
                ✕
              </button>
            </div>
            <pre className="font-mono text-sm text-content whitespace-pre-wrap">
              {selectedDetails}
            </pre>
          </div>
        </div>
      )}
    </div>
  );
};

export default AuthLogsTab;
