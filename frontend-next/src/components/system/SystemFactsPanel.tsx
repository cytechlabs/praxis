/**
 * PRA-155 #2c: host detail Facts tab.
 *
 * Reads from `GET /systems/{id}/facts` and renders the inventory in a
 * transport-neutral way - the panel never implies the agent is
 * required. The Refresh button POSTs to the locked
 * `POST /systems/{id}/facts/refresh` endpoint (#2b-b); on a transport
 * failure (503 forced-agent / 504 timeout / 502 collector error) the
 * panel keeps showing the existing facts and surfaces an inline
 * failure message near the button rather than replacing the page.
 *
 * Auth model: GET is authenticated-readable (any user); the Refresh
 * button is rendered for admins only via the `canRefresh` prop.
 *
 * PRA-156 #3b: also fetches `GET /systems/{id}/lifecycle` and renders
 * a Lifecycle section. The lifecycle endpoint always returns 200 -
 * missing/stale facts surface as `status="unknown"` with the
 * unknown_reason discriminator. A failed lifecycle fetch never
 * replaces the facts panel; it just hides the section.
 */
import React, { useCallback, useEffect, useState } from 'react';
import { Badge, Button, EmptyState, SkeletonTable } from '@/components/ui';
import { apiFetch, formatApiError } from '@/utils/api';

// Server-driven freshness verdict; we never recompute client-side so
// every Praxis surface (UI here, future smart groups in #2d, audit
// rows) agrees on what "stale" means.
type Freshness = 'fresh' | 'stale' | 'missing';

// Mirrors broker capabilities + the FactsService source_transport enum.
type SourceTransport = 'agent' | 'ssh' | 'manual';

interface FactsResponse {
  system_id: number;
  schema_version: number | null;
  collected_at: string | null;
  source_transport: SourceTransport | null;
  freshness: Freshness;
  is_partial: boolean;
  facts: {
    cpu_model: string | null;
    cpu_cores: number | null;
    ram_total_bytes: number | null;
    kernel_version: string | null;
    distro_id: string | null;
    distro_release: string | null;
    uptime_seconds: number | null;
    reboot_required: boolean | null;
    package_manager: string | null;
    package_manager_version: string | null;
    virtualization: string | null;
    cloud_provider: string | null;
    cloud_instance_metadata: Record<string, string> | null;
    disks: Array<{
      mountpoint: string;
      filesystem: string;
      total_bytes: number;
      free_bytes: number;
    }>;
  } | null;
  partial_errors: Array<{ key: string; error: string }>;
  staleness_threshold_seconds: number;
}

// PRA-156 #3b: lifecycle verdict shape mirrors LifecycleService.compute.
// API stays raw (ISO date, integer days); the panel does the human
// formatting. unknown_reason is a free-form discriminator surfaced to
// help operators understand WHY a host is unknown, not to drive UI
// branching.
type LifecycleStatus = 'supported' | 'approaching-eol' | 'unsupported' | 'unknown';
type SupportKind = 'standard' | 'esm' | 'extended';

interface LifecycleResponse {
  system_id: number;
  freshness: Freshness;
  status: LifecycleStatus;
  days_to_eol: number | null;
  eol_date: string | null;
  support_kind: SupportKind | null;
  source: string | null;
  unknown_reason: string | null;
  staleness_threshold_seconds: number;
}

interface Props {
  systemId: number;
  canRefresh: boolean;
}

// --- formatting helpers -----------------------------------------------------
//
// API stays raw bytes / raw seconds; the panel presents formatted
// human-readable values with the raw form available on hover. The API
// is transport-neutral and lossless; UI does the squishing.

function formatBytes(bytes: number | null): string {
  if (bytes === null || bytes === undefined) return '-';
  if (bytes < 1024) return `${bytes} B`;
  const units = ['KiB', 'MiB', 'GiB', 'TiB', 'PiB'];
  let v = bytes / 1024;
  let i = 0;
  while (v >= 1024 && i < units.length - 1) {
    v /= 1024;
    i += 1;
  }
  return `${v.toFixed(v >= 100 ? 0 : 1)} ${units[i]}`;
}

function formatRelative(iso: string): string {
  // Scan-friendly age - "3h ago" / "12m ago" / "5d ago". The absolute
  // value lives in the title attribute on the rendering site so
  // operators can hover for the precise instant. We deliberately
  // don't pull a heavyweight i18n lib for this one line.
  const t = Date.parse(iso);
  if (Number.isNaN(t)) return iso;
  const diffSeconds = Math.max(0, Math.floor((Date.now() - t) / 1000));
  if (diffSeconds < 60) return 'just now';
  const m = Math.floor(diffSeconds / 60);
  if (m < 60) return `${m}m ago`;
  const h = Math.floor(m / 60);
  if (h < 24) return `${h}h ago`;
  const d = Math.floor(h / 24);
  if (d < 30) return `${d}d ago`;
  const mo = Math.floor(d / 30);
  if (mo < 12) return `${mo}mo ago`;
  return `${Math.floor(mo / 12)}y ago`;
}

function formatUptime(seconds: number | null): string {
  if (seconds === null || seconds === undefined) return '-';
  const d = Math.floor(seconds / 86400);
  const h = Math.floor((seconds % 86400) / 3600);
  const m = Math.floor((seconds % 3600) / 60);
  if (d > 0) return `${d}d ${h}h`;
  if (h > 0) return `${h}h ${m}m`;
  return `${m}m`;
}

function freshnessBadge(freshness: Freshness): { label: string; variant: 'success' | 'warning' | 'neutral' } {
  if (freshness === 'fresh') return { label: 'Fresh', variant: 'success' };
  if (freshness === 'stale') return { label: 'Stale', variant: 'warning' };
  return { label: 'Missing', variant: 'neutral' };
}

function transportLabel(t: SourceTransport | null): string {
  if (t === 'agent') return 'Agent';
  if (t === 'ssh') return 'SSH';
  if (t === 'manual') return 'Manual';
  return '-';
}

function lifecycleBadge(
  status: LifecycleStatus,
): { label: string; variant: 'success' | 'warning' | 'danger' | 'neutral' } {
  if (status === 'supported') return { label: 'Supported', variant: 'success' };
  if (status === 'approaching-eol')
    return { label: 'Approaching EOL', variant: 'warning' };
  if (status === 'unsupported') return { label: 'Unsupported', variant: 'danger' };
  return { label: 'Unknown', variant: 'neutral' };
}

function formatDaysToEol(days: number | null, status: LifecycleStatus): string {
  if (days === null) return '-';
  if (days < 0) return `EOL passed ${Math.abs(days)} day${Math.abs(days) === 1 ? '' : 's'} ago`;
  if (days === 0) return 'EOL today';
  // ``approaching-eol`` and ``supported`` both use the days-out form.
  void status;
  return `${days} day${days === 1 ? '' : 's'} until EOL`;
}

function supportKindLabel(kind: SupportKind | null): string {
  if (kind === 'standard') return 'Standard support';
  if (kind === 'esm') return 'Extended security maintenance (ESM)';
  if (kind === 'extended') return 'Extended support';
  return '-';
}

// Operator-facing translation of the unknown_reason discriminator.
// Kept terse - the section header carries the badge; this is the
// one-line "why" that helps an operator decide whether to refresh
// inventory, edit the EOL seed, or move on.
function unknownReasonLabel(reason: string | null): string | null {
  if (reason === 'freshness') return 'Inventory is stale or missing - refresh to update.';
  if (reason === 'missing_distro_facts')
    return 'Distro / release fields are missing from the latest collection.';
  if (reason === 'no_lifecycle_row')
    return 'No EOL data is seeded for this distro and release.';
  return null;
}

// --- panel ------------------------------------------------------------------

const SystemFactsPanel: React.FC<Props> = ({ systemId, canRefresh }) => {
  const [data, setData] = useState<FactsResponse | null>(null);
  const [lifecycle, setLifecycle] = useState<LifecycleResponse | null>(null);
  const [loading, setLoading] = useState(true);
  const [loadError, setLoadError] = useState<string | null>(null);
  const [refreshing, setRefreshing] = useState(false);
  const [refreshError, setRefreshError] = useState<string | null>(null);
  const [showPartials, setShowPartials] = useState(false);

  const fetchLifecycle = useCallback(async () => {
    // Lifecycle fetch failure must NOT replace the facts panel -
    // hide the section instead. The endpoint always returns 200 for
    // existing systems (missing/stale facts come through as
    // status="unknown"); a real 4xx/5xx here indicates an auth or
    // network problem we don't want to escalate over the facts UI.
    try {
      const res = await apiFetch(`/api/backend/systems/${systemId}/lifecycle`);
      if (!res.ok) {
        setLifecycle(null);
        return;
      }
      setLifecycle((await res.json()) as LifecycleResponse);
    } catch {
      setLifecycle(null);
    }
  }, [systemId]);

  const fetchFacts = useCallback(async () => {
    setLoading(true);
    setLoadError(null);
    try {
      const res = await apiFetch(`/api/backend/systems/${systemId}/facts`);
      if (!res.ok) {
        setLoadError(formatApiError(await res.json().catch(() => ({})), 'Failed to load facts'));
        return;
      }
      setData((await res.json()) as FactsResponse);
    } catch (e) {
      setLoadError(e instanceof Error ? e.message : 'Failed to load facts');
    } finally {
      setLoading(false);
    }
    // Lifecycle is computed from the same facts row; refetch in
    // parallel-ish so the section reflects the latest state.
    void fetchLifecycle();
  }, [systemId, fetchLifecycle]);

  useEffect(() => {
    void fetchFacts();
  }, [fetchFacts]);

  const handleRefresh = async () => {
    setRefreshing(true);
    setRefreshError(null);
    try {
      const res = await apiFetch(`/api/backend/systems/${systemId}/facts/refresh`, {
        method: 'POST',
      });
      if (!res.ok) {
        // Keep the panel populated; show inline failure
        // near the button. 503/504/502 must NOT replace the panel
        // with an error page.
        const body = await res.json().catch(() => ({}));
        setRefreshError(
          formatApiError(body, `Refresh failed (HTTP ${res.status})`)
        );
        return;
      }
      // Success - refetch the read endpoint to pick up the new row.
      await fetchFacts();
    } catch (e) {
      setRefreshError(e instanceof Error ? e.message : 'Refresh failed');
    } finally {
      setRefreshing(false);
    }
  };

  if (loading && data === null) {
    return <SkeletonTable rows={8} cols={2} />;
  }

  if (loadError && data === null) {
    return (
      <div className="rounded-lg border border-red-700 bg-red-900/30 p-4 text-red-200" role="alert">
        {loadError}
      </div>
    );
  }

  if (!data) {
    return null;
  }

  const fresh = freshnessBadge(data.freshness);
  const collectedRel = data.collected_at ? formatRelative(data.collected_at) : null;

  // Missing-row state - first-collect on a host that has no facts
  // yet. Empty state with the same Refresh button so operators can
  // trigger inventory immediately.
  if (data.freshness === 'missing') {
    return (
      <div className="space-y-4">
        <div className="flex items-center justify-between">
          <div className="flex items-center gap-2">
            <Badge variant={fresh.variant}>{fresh.label}</Badge>
          </div>
          {canRefresh && (
            <Button onClick={handleRefresh} loading={refreshing} variant="primary">
              Refresh
            </Button>
          )}
        </div>
        {refreshError && (
          <div className="rounded border border-amber-700 bg-amber-900/30 p-3 text-sm text-amber-200" role="alert">
            {refreshError}
          </div>
        )}
        <EmptyState
          title="Inventory hasn't been collected yet"
          description="Run a refresh to collect CPU, memory, OS, and storage details for this host."
        />
      </div>
    );
  }

  const facts = data.facts!;
  const cloudMd = facts.cloud_instance_metadata || {};

  return (
    <div className="space-y-6">
      {/* Header: badges + collected-at + refresh */}
      <div className="flex flex-wrap items-center justify-between gap-3">
        <div className="flex flex-wrap items-center gap-2">
          <Badge variant={fresh.variant}>{fresh.label}</Badge>
          <Badge variant="neutral">{transportLabel(data.source_transport)}</Badge>
          {data.is_partial && (
            <span title="Some collectors failed; details below.">
              <Badge variant="warning">Partial</Badge>
            </span>
          )}
          {collectedRel && (
            <span
              className="text-xs text-content-muted"
              title={data.collected_at || ''}
            >
              Collected {collectedRel}
            </span>
          )}
        </div>
        {canRefresh && (
          <Button onClick={handleRefresh} loading={refreshing} variant="primary">
            Refresh
          </Button>
        )}
      </div>

      {/* Inline refresh failure - keep panel populated. */}
      {refreshError && (
        <div className="rounded border border-amber-700 bg-amber-900/30 p-3 text-sm text-amber-200" role="alert">
          Refresh failed: {refreshError}
          <span className="ml-2 text-amber-300">Showing previously-collected facts.</span>
        </div>
      )}

      {/* CPU / Memory */}
      <FactSection title="CPU & Memory">
        <FactRow label="CPU model" value={facts.cpu_model} />
        <FactRow label="CPU cores" value={facts.cpu_cores?.toString() ?? null} />
        <FactRow
          label="RAM total"
          value={formatBytes(facts.ram_total_bytes)}
          rawTitle={facts.ram_total_bytes ? `${facts.ram_total_bytes} bytes` : undefined}
        />
      </FactSection>

      {/* OS */}
      <FactSection title="Operating System">
        <FactRow label="Distro" value={[facts.distro_id, facts.distro_release].filter(Boolean).join(' ') || null} />
        <FactRow label="Kernel" value={facts.kernel_version} />
        <FactRow
          label="Uptime"
          value={formatUptime(facts.uptime_seconds)}
          rawTitle={facts.uptime_seconds ? `${facts.uptime_seconds} seconds` : undefined}
        />
        <FactRow
          label="Reboot required"
          value={
            facts.reboot_required === null
              ? null
              : facts.reboot_required ? 'Yes' : 'No'
          }
        />
      </FactSection>

      {/* Lifecycle (PRA-156 #3b) - only render when the read
          succeeded. Section header carries the status badge so the
          verdict is visible at a glance even when facts are stale
          and the body shows '-'. */}
      {lifecycle && (
        <div>
          <div className="mb-2 flex items-center gap-2">
            <h3 className="text-sm font-semibold uppercase tracking-wide text-content-muted">
              Lifecycle
            </h3>
            <Badge variant={lifecycleBadge(lifecycle.status).variant}>
              {lifecycleBadge(lifecycle.status).label}
            </Badge>
          </div>
          <div className="rounded border border-border bg-surface-raised/30 p-3 text-sm">
            <FactRow
              label="Status"
              value={
                lifecycle.status === 'unknown'
                  ? unknownReasonLabel(lifecycle.unknown_reason) || 'Unknown'
                  : formatDaysToEol(lifecycle.days_to_eol, lifecycle.status)
              }
            />
            <FactRow label="EOL date" value={lifecycle.eol_date} />
            <FactRow
              label="Support window"
              value={lifecycle.support_kind ? supportKindLabel(lifecycle.support_kind) : null}
            />
            <FactRow label="Source" value={lifecycle.source} />
          </div>
        </div>
      )}

      {/* Package manager / virtualization */}
      <FactSection title="Platform">
        <FactRow
          label="Package manager"
          value={
            facts.package_manager
              ? `${facts.package_manager}${facts.package_manager_version ? ` (${facts.package_manager_version})` : ''}`
              : null
          }
        />
        <FactRow label="Virtualization" value={facts.virtualization} />
      </FactSection>

      {/* Cloud - only render if we know we're cloud-hosted. */}
      {(facts.cloud_provider || Object.keys(cloudMd).length > 0) && (
        <FactSection title="Cloud">
          <FactRow label="Provider" value={facts.cloud_provider} />
          <FactRow label="Instance ID" value={cloudMd.instance_id ?? null} />
          <FactRow label="Region" value={cloudMd.region ?? null} />
          <FactRow label="Zone" value={cloudMd.zone ?? null} />
        </FactSection>
      )}

      {/* Disks */}
      {facts.disks && facts.disks.length > 0 && (
        <FactSection title="Storage">
          <table className="w-full text-sm">
            <thead className="text-xs uppercase text-content-subtle">
              <tr>
                <th className="py-1 text-left">Mount</th>
                <th className="py-1 text-left">Filesystem</th>
                <th className="py-1 text-right">Total</th>
                <th className="py-1 text-right">Free</th>
              </tr>
            </thead>
            <tbody>
              {facts.disks.map((d, i) => (
                <tr key={`${d.mountpoint}-${i}`} className="border-t border-border">
                  <td className="py-1.5 font-mono text-content">{d.mountpoint}</td>
                  <td className="py-1.5 text-content-muted">{d.filesystem}</td>
                  <td className="py-1.5 text-right text-content" title={`${d.total_bytes} bytes`}>
                    {formatBytes(d.total_bytes)}
                  </td>
                  <td className="py-1.5 text-right text-content" title={`${d.free_bytes} bytes`}>
                    {formatBytes(d.free_bytes)}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        </FactSection>
      )}

      {/* Partial errors - collapsed disclosure. Many
          fleets will have ≥1 partial (cloud probe on bare-metal,
          missing systemd-detect-virt) so this should NOT feel like a
          page-level error. */}
      {data.partial_errors.length > 0 && (
        <details
          className="rounded border border-border bg-surface-raised/30 p-3 text-sm"
          open={showPartials}
          onToggle={(e) => setShowPartials((e.target as HTMLDetailsElement).open)}
        >
          <summary className="cursor-pointer text-content">
            {data.partial_errors.length} collection issue{data.partial_errors.length === 1 ? '' : 's'}
          </summary>
          <ul className="mt-2 space-y-1 text-xs text-content-muted">
            {data.partial_errors.map((e, i) => (
              <li key={`${e.key}-${i}`}>
                <span className="font-mono text-content">{e.key}</span>: {e.error}
              </li>
            ))}
          </ul>
        </details>
      )}
    </div>
  );
};

// --- small subcomponents ----------------------------------------------------

const FactSection: React.FC<{ title: string; children: React.ReactNode }> = ({
  title,
  children,
}) => (
  <div>
    <h3 className="mb-2 text-sm font-semibold uppercase tracking-wide text-content-muted">
      {title}
    </h3>
    <div className="rounded border border-border bg-surface-raised/30 p-3 text-sm">{children}</div>
  </div>
);

const FactRow: React.FC<{ label: string; value: string | null; rawTitle?: string }> = ({
  label,
  value,
  rawTitle,
}) => (
  <div className="flex justify-between gap-4 border-b border-border/60 py-1.5 last:border-b-0">
    <span className="text-content-subtle">{label}</span>
    <span
      className={value === null ? 'text-content-subtle italic' : 'text-content'}
      title={rawTitle}
    >
      {value === null ? '-' : value}
    </span>
  </div>
);

export default SystemFactsPanel;
