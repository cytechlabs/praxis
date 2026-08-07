/**
 * PRA-173 closeout fix: plan-scoped rollback summary
 * section.
 *
 * Renders ``GET /patch/update-plans/{plan_id}/rollback`` so plans
 * with no current execution, multiple execution attempts, or
 * pre-existing per-plan rollback evidence surface the same
 * per-execution feasibility view the backend already exposes. The
 * execution-scoped `RollbackPanel` is for the *current* execution
 * only; this component is the plan's running ledger.
 *
 * Refresh model: the plan detail page already polls plan + latest
 * execution. This section refreshes on `planRefresh()` so the two
 * stay aligned without a separate polling loop.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Badge from '@/components/ui/Badge';
import {
  getPlanRollback,
  PatchRollbackApiError,
  type PlanRollbackRead,
} from '@/services/patchRollbackService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

export interface PlanRollbackSummaryProps {
  planId: number;
  reportError: (label: string, e: unknown) => void;
  /** Increment to force a refetch from the parent page. */
  refreshKey?: number;
}

const PlanRollbackSummary: React.FC<PlanRollbackSummaryProps> = ({
  planId,
  reportError,
  refreshKey,
}) => {
  const formatTimestamp = useFormatTimestamp();
  const [data, setData] = useState<PlanRollbackRead | null>(null);
  const [loaded, setLoaded] = useState(false);

  const refresh = useCallback(async () => {
    try {
      const out = await getPlanRollback(planId);
      setData(out);
    } catch (e) {
      if (e instanceof PatchRollbackApiError && e.status === 404) {
        setData(null);
      } else {
        reportError('Load plan rollback summary', e);
      }
    } finally {
      setLoaded(true);
    }
  }, [planId, reportError]);

  useEffect(() => {
    refresh();
  }, [refresh, refreshKey]);

  if (!loaded) {
    return (
      <section
        data-testid="plan-rollback-summary"
        className="rounded-md border border-praxis-border bg-praxis-surface p-4"
      >
        <h2 className="text-sm font-semibold">Plan rollback summary</h2>
        <p className="mt-1 text-xs text-praxis-text-muted">Loading…</p>
      </section>
    );
  }
  if (!data) return null;

  const summary = data.summary;
  return (
    <section
      data-testid="plan-rollback-summary"
      className="rounded-md border border-praxis-border bg-praxis-surface p-4 space-y-3"
    >
      <div>
        <h2 className="text-sm font-semibold">Plan rollback summary</h2>
        <p className="text-xs text-praxis-text-muted">
          Aggregate rollback feasibility across every execution started for
          this plan. Independent from the live execution panel so prior /
          terminal executions still show up.
        </p>
      </div>

      <div className="flex flex-wrap gap-1.5 text-xs">
        <Badge variant="info">
          {summary.execution_count} execution{summary.execution_count === 1 ? '' : 's'}
        </Badge>
        <Badge variant="info">{summary.evaluated_count} evaluated</Badge>
        <Badge variant="success">
          {summary.host_counts_by_state.feasible ?? 0} feasible host
          {(summary.host_counts_by_state.feasible ?? 0) === 1 ? '' : 's'}
        </Badge>
        <Badge variant="warning">
          {summary.host_counts_by_state.partial_feasible ?? 0} partial
        </Badge>
        <Badge variant="neutral">
          {summary.host_counts_by_state.infeasible ?? 0} infeasible
        </Badge>
        <span className="text-praxis-text-muted">
          · {summary.package_count} package row(s) ·{' '}
          {summary.package_counts_by_state.feasible ?? 0} dispatch-ready
        </span>
      </div>

      {Object.keys(summary.refusal_counts || {}).length > 0 && (
        <p className="text-xs text-praxis-text-muted">
          Refusals:{' '}
          {Object.entries(summary.refusal_counts)
            .map(([k, v]) => `${k}=${v}`)
            .join(', ')}
        </p>
      )}

      {data.executions.length === 0 ? (
        <p className="text-xs text-praxis-text-muted">
          No executions have been started for this plan yet.
        </p>
      ) : (
        <div className="overflow-auto rounded-md border border-praxis-border">
          <table className="min-w-full text-xs">
            <thead className="bg-praxis-surface text-praxis-text-muted">
              <tr>
                <th className="px-3 py-2 text-left font-medium">Execution</th>
                <th className="px-3 py-2 text-left font-medium">Started</th>
                <th className="px-3 py-2 text-left font-medium">
                  Execution state
                </th>
                <th className="px-3 py-2 text-left font-medium">
                  Rollback state
                </th>
                <th className="px-3 py-2 text-left font-medium">Refusal</th>
              </tr>
            </thead>
            <tbody>
              {data.executions.map((ref) => {
                const rb = ref.rollback;
                return (
                  <tr
                    key={ref.execution_id}
                    data-testid={`plan-rollback-execution-${ref.execution_id}`}
                    className="border-t border-praxis-border"
                  >
                    <td className="px-3 py-1.5 font-mono">
                      #{ref.execution_id}
                    </td>
                    <td className="px-3 py-1.5 text-praxis-text-muted">
                      {formatTimestamp(ref.started_at)}
                    </td>
                    <td className="px-3 py-1.5">{humanizeStatus(ref.execution_state)}</td>
                    <td className="px-3 py-1.5">
                      {rb ? (
                        <Badge
                          variant={
                            rb.state === 'evaluated'
                              ? ('success' as never)
                              : ('warning' as never)
                          }
                        >
                          {humanizeStatus(rb.state)}
                        </Badge>
                      ) : (
                        <span className="text-praxis-text-muted">
                          not evaluated
                        </span>
                      )}
                    </td>
                    <td className="px-3 py-1.5 font-mono text-praxis-text-muted">
                      {rb?.refusal_reason ?? '-'}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        </div>
      )}
    </section>
  );
};

export default PlanRollbackSummary;
