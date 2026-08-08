/**
 * PRA-163 #4: per-host applicable-advisories card.
 *
 * Renders the host's `patch_advisory_host_applicability` rows
 * (joined with their source advisories) plus a state-counts
 * summary, an explicit "host facts missing" callout when the
 * resolver couldn't compute applicability, and an operator-
 * triggered manual recompute that surfaces the row delta inline.
 *
 * Slice 4 design lock: the recompute trigger uses the existing
 * Slice 2 `compute_host_applicability` resolver and emits the
 * existing `patch_advisory.applicable_recomputed` audit. No new
 * audit event was added.
 */
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, RefreshCw } from 'lucide-react';
import { toast } from 'sonner';
import { Badge, Button, Card, CardBody, CardHeader } from '@/components/ui';
import {
  APPLICABILITY_STATE_LABELS,
  APPLICABILITY_STATE_VALUES,
  type ApplicabilityState,
  getHostAdvisoryCounts,
  type HostAdvisoryCounts,
  type HostAdvisoryRow,
  listHostAdvisories,
  recomputeHostAdvisories,
  SEVERITY_LABELS,
} from '@/services/patchAdvisoryService';

interface Props {
  systemId: number;
}

const HostAdvisoryCard = ({ systemId }: Props) => {
  const [counts, setCounts] = useState<HostAdvisoryCounts | null>(null);
  const [rows, setRows] = useState<HostAdvisoryRow[] | null>(null);
  const [stateFilter, setStateFilter] = useState<ApplicabilityState | ''>('');
  const [loading, setLoading] = useState(true);
  const [recomputing, setRecomputing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hostFactsMissing, setHostFactsMissing] = useState(false);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const [c, r] = await Promise.all([
        getHostAdvisoryCounts(systemId),
        listHostAdvisories(systemId, {
          state: stateFilter || undefined,
        }),
      ]);
      setCounts(c);
      setRows(r);
      // Slice 4-a: counts endpoint now surfaces host_facts_missing
      // directly so the callout renders on initial paint, not just
      // after operator-triggered recompute. Same predicate the Slice
      // 2 resolver uses to short-circuit applicability computation.
      setHostFactsMissing(c.host_facts_missing);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [systemId, stateFilter]);

  useEffect(() => {
    load();
  }, [load]);

  const handleRecompute = async () => {
    setRecomputing(true);
    try {
      const result = await recomputeHostAdvisories(systemId);
      const delta =
        result.rows_added + result.rows_updated + result.rows_removed;
      if (result.host_facts_missing) {
        toast.warning(
          `Host facts missing - applicability could not be recomputed (${result.rows_removed} stale rows pruned).`,
        );
      } else if (delta === 0) {
        toast.success('Already up to date - no rows changed.');
      } else {
        toast.success(
          `Recomputed: +${result.rows_added} added, ~${result.rows_updated} updated, −${result.rows_removed} removed.`,
        );
      }
      setHostFactsMissing(result.host_facts_missing);
      await load();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : String(e));
    } finally {
      setRecomputing(false);
    }
  };

  const renderBody = () => {
    if (loading && !counts) {
      return <div className="text-sm text-content-muted">Loading…</div>;
    }
    if (error) {
      return (
        <div className="rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-300">
          {error}
        </div>
      );
    }

    return (
      <div>
        {hostFactsMissing && (
          <div className="mb-3 rounded border border-yellow-900/40 bg-yellow-900/10 p-3 text-sm text-yellow-200">
            <div className="flex items-center gap-2 font-medium">
              <AlertTriangle size={14} /> Host facts unavailable
            </div>
            <p className="mt-1 text-xs text-yellow-300">
              The resolver couldn&apos;t determine applicability because the host
              has no usable distro facts. Once the host reports facts, recompute
              again to populate this card.
            </p>
          </div>
        )}

        <div className="mb-3 grid grid-cols-2 gap-3 md:grid-cols-4">
          {APPLICABILITY_STATE_VALUES.map((s) => (
            <button
              key={s}
              onClick={() => setStateFilter(stateFilter === s ? '' : s)}
              className={`rounded-lg border px-3 py-2 text-left text-sm transition-colors ${
                stateFilter === s
                  ? 'border-blue-500 bg-blue-900/20'
                  : 'border-border bg-surface-raised/30 hover:bg-white/[0.03]'
              }`}
            >
              <div className="text-xs uppercase tracking-wide text-content-subtle">
                {APPLICABILITY_STATE_LABELS[s]}
              </div>
              <div className="text-2xl font-bold text-content tabular-nums">
                {counts?.counts?.[s] ?? 0}
              </div>
            </button>
          ))}
        </div>

        {(rows?.length ?? 0) === 0 ? (
          <p className="text-sm text-content-muted">
            {stateFilter
              ? `No advisories in state "${APPLICABILITY_STATE_LABELS[stateFilter as ApplicabilityState]}".`
              : 'No advisory applicability rows have been computed for this host yet.'}
          </p>
        ) : (
          <div className="overflow-x-auto rounded border border-border">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-content-muted">
                <tr>
                  <th className="px-3 py-2">Advisory</th>
                  <th className="px-3 py-2">Severity</th>
                  <th className="px-3 py-2">Class</th>
                  <th className="px-3 py-2">Package</th>
                  <th className="px-3 py-2">Installed</th>
                  <th className="px-3 py-2">Required</th>
                  <th className="px-3 py-2">State</th>
                  <th className="px-3 py-2">Reason</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {rows!.map((r) => (
                  <tr key={r.id} className="hover:bg-surface-overlay/40">
                    <td className="px-3 py-1.5">
                      <Link
                        href={`/patch-advisories/${r.advisory_id}`}
                        className="font-mono text-blue-400 hover:text-blue-300"
                      >
                        {r.advisory.source_advisory_id}
                      </Link>
                    </td>
                    <td className="px-3 py-1.5 text-content">
                      {SEVERITY_LABELS[r.advisory.severity]}
                    </td>
                    <td className="px-3 py-1.5 text-content">
                      {r.advisory.advisory_class}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-content">
                      {r.package_name}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-content">
                      {r.installed_version ?? '-'}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-content">
                      {r.required_version ?? '-'}
                    </td>
                    <td className="px-3 py-1.5">
                      <Badge variant={stateBadgeVariant(r.state)}>
                        {APPLICABILITY_STATE_LABELS[r.state]}
                      </Badge>
                    </td>
                    <td className="px-3 py-1.5 text-xs text-content-subtle">
                      {r.reason ?? ''}
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}
      </div>
    );
  };

  return (
    <Card className="mt-4">
      <CardHeader
        action={
          <Button
            variant="ghost"
            size="sm"
            onClick={handleRecompute}
            disabled={recomputing}
            aria-label="Recompute host advisory applicability"
          >
            <RefreshCw size={14} className={recomputing ? 'animate-spin' : ''} />
          </Button>
        }
      >
        <div>
          <div>Patch advisories</div>
          <div className="mt-0.5 text-xs font-normal text-content-subtle">
            Joined applicability state from advisory data + host facts
            + installed packages. Recompute updates only this host.
          </div>
        </div>
      </CardHeader>
      <CardBody>{renderBody()}</CardBody>
    </Card>
  );
};

function stateBadgeVariant(
  state: ApplicabilityState,
): 'success' | 'warning' | 'danger' | 'neutral' {
  if (state === 'applicable') return 'danger';
  if (state === 'fixed') return 'success';
  if (state === 'unknown') return 'warning';
  return 'neutral';
}

export default HostAdvisoryCard;
