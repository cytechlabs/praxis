/**
 * PRA-177 Slice 1: per-host remediation inventory (read-only).
 *
 * Backed by ``GET /compliance/systems/{system_id}/remediation``.
 * Renders the five paged sections returned by the backend:
 *
 *   - open_requests
 *   - approved_requests
 *   - current_plans
 *   - ready_plans
 *   - superseded_history
 *
 * Each section has its own offset cursor so paging through one
 * section does not reset the others. The shared limit is exposed to
 * the operator as a single page-size control.
 *
 * No mutation controls: this slice does not expose request open,
 * approve/reject, plan build/refresh, acknowledge, attempt create,
 * or dispatch flows.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, ExternalLink, RefreshCw } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import {
  Badge,
  Button,
  Card,
  CardBody,
  EmptyState,
  ErrorState,
  PageHeader,
  SkeletonTable,
} from '@/components/ui';
import {
  PLAN_KIND_LABELS,
  RemediationHostInventory,
  RemediationPlanPage,
  RemediationRequestPage,
  getSystemRemediationInventory,
  remediationPlanStateBadgeVariant,
  remediationRequestStateBadgeVariant,
  SEVERITY_LABELS,
  severityBadgeVariant,
} from '@/services/complianceService';
import { fetchSystemDetails } from '@/services/systemService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { humanizeStatus } from '@/utils/humanize';

const DEFAULT_LIMIT = 25;

interface Offsets {
  open: number;
  approved: number;
  current: number;
  ready: number;
  superseded: number;
}

const ZERO_OFFSETS: Offsets = {
  open: 0,
  approved: 0,
  current: 0,
  ready: 0,
  superseded: 0,
};

const ComplianceSystemRemediationPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const systemId = Number(router.query.id);

  const [inventory, setInventory] = useState<RemediationHostInventory | null>(null);
  const [offsets, setOffsets] = useState<Offsets>(ZERO_OFFSETS);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [hostname, setHostname] = useState<string | null>(null);

  useEffect(() => {
    if (!Number.isFinite(systemId)) return;
    fetchSystemDetails(systemId)
      .then((s) => setHostname(s.hostname))
      .catch(() => setHostname(null));
  }, [systemId]);

  const hostLabel = hostname ?? `System #${systemId}`;

  const refresh = useCallback(async () => {
    if (!Number.isFinite(systemId)) return;
    setLoading(true);
    try {
      const data = await getSystemRemediationInventory(systemId, {
        limit: DEFAULT_LIMIT,
        open_offset: offsets.open,
        approved_offset: offsets.approved,
        current_plans_offset: offsets.current,
        ready_plans_offset: offsets.ready,
        superseded_offset: offsets.superseded,
      });
      setInventory(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [systemId, offsets]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  if (!Number.isFinite(systemId)) {
    return (
      <MainLayout>
        <div className="p-6 text-content-muted">Invalid system id.</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>{hostLabel} Remediation · Praxis</title>
      </Head>

      <div className="p-6 space-y-6">
        <PageHeader
          title={`${hostLabel} Remediation`}
          subtitle="Per-host remediation inventory: open and approved requests, current and ready plan previews, and superseded plan history."
          actions={
            <div className="flex items-center gap-2">
              <Link
                href={`/compliance/systems/${systemId}`}
                className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
              >
                <ArrowLeft size={14} /> System compliance
              </Link>
              <Link
                href="/compliance/remediation"
                className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
              >
                Fleet remediation →
              </Link>
              <Button variant="outline" onClick={() => refresh()}>
                <RefreshCw size={14} /> Refresh
              </Button>
            </div>
          }
        />

        {error && (
          <ErrorState
            title="Couldn’t load remediation inventory"
            onRetry={refresh}
          />
        )}

        {!inventory && loading && (
          <Card>
            <CardBody>
              <SkeletonTable rows={5} cols={5} />
            </CardBody>
          </Card>
        )}

        {inventory && (
          <>
            <Card>
              <CardBody>
                <div className="flex flex-wrap items-center gap-6">
                  <Stat label="Open requests" value={inventory.open_requests.total} />
                  <Stat
                    label="Approved requests"
                    value={inventory.approved_requests.total}
                  />
                  <Stat
                    label="Current plans"
                    value={inventory.current_plans.total}
                  />
                  <Stat label="Ready plans" value={inventory.ready_plans.total} />
                  <Stat
                    label="Superseded history"
                    value={inventory.superseded_history.total}
                  />
                  <Stat
                    label="Generated"
                    value={
                      <span className="text-xs text-content">
                        {formatTimestamp(inventory.generated_at)}
                      </span>
                    }
                  />
                </div>
              </CardBody>
            </Card>

            <RequestSection
              title="Open requests"
              emptyDescription="No remediation requests in state requested for this host."
              page={inventory.open_requests}
              offset={offsets.open}
              onPage={(o) => setOffsets((s) => ({ ...s, open: o }))}
            />

            <RequestSection
              title="Approved requests"
              emptyDescription="No approved remediation requests for this host. Approved requests may or may not have a plan preview yet."
              page={inventory.approved_requests}
              offset={offsets.approved}
              onPage={(o) => setOffsets((s) => ({ ...s, approved: o }))}
            />

            <PlanSection
              title="Current plans"
              emptyDescription="No current (non-superseded) plan previews for this host."
              page={inventory.current_plans}
              offset={offsets.current}
              onPage={(o) => setOffsets((s) => ({ ...s, current: o }))}
            />

            <PlanSection
              title="Ready plans"
              emptyDescription="No current plans are ready for execution. Plans become ready only when acknowledged, fresh, in state planned, and of an executable package kind."
              page={inventory.ready_plans}
              offset={offsets.ready}
              onPage={(o) => setOffsets((s) => ({ ...s, ready: o }))}
            />

            <PlanSection
              title="Superseded history"
              emptyDescription="No superseded plan history yet."
              page={inventory.superseded_history}
              offset={offsets.superseded}
              onPage={(o) => setOffsets((s) => ({ ...s, superseded: o }))}
            />
          </>
        )}
      </div>
    </MainLayout>
  );
};

const RequestSection: React.FC<{
  title: string;
  emptyDescription: string;
  page: RemediationRequestPage;
  offset: number;
  onPage: (offset: number) => void;
}> = ({ title, emptyDescription, page, offset, onPage }) => {
  const formatTimestamp = useFormatTimestamp();
  return (
  <Card>
    <CardBody>
      <SectionHeader title={title} total={page.total} />
      {page.items.length === 0 ? (
        <EmptyState title={`No ${title.toLowerCase()}`} description={emptyDescription} />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-content-muted border-b border-border">
                <tr>
                  <th className="py-2 pr-3">Request</th>
                  <th className="py-2 pr-3">State</th>
                  <th className="py-2 pr-3">Policy</th>
                  <th className="py-2 pr-3">Check</th>
                  <th className="py-2 pr-3">Severity</th>
                  <th className="py-2 pr-3">Created</th>
                  <th className="py-2 pr-3"></th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((r) => (
                  <tr key={r.id} className="border-b border-border/50">
                    <td className="py-2 pr-3 font-mono">#{r.id}</td>
                    <td className="py-2 pr-3">
                      <Badge
                        variant={remediationRequestStateBadgeVariant(r.state)}
                      >
                        {humanizeStatus(r.state)}
                      </Badge>
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs">
                      <Link
                        href={`/compliance/policies/${r.policy_id}`}
                        className="text-blue-400 hover:underline"
                      >
                        {r.policy_slug}
                      </Link>
                    </td>
                    <td className="py-2 pr-3 font-mono text-xs text-content">
                      {r.check_slug}
                    </td>
                    <td className="py-2 pr-3">
                      <Badge variant={severityBadgeVariant(r.severity_snapshot)}>
                        {SEVERITY_LABELS[r.severity_snapshot]}
                      </Badge>
                    </td>
                    <td className="py-2 pr-3 text-xs text-content">
                      {formatTimestamp(r.created_at)}
                    </td>
                    <td className="py-2 pr-3 text-right">
                      <Link
                        href={`/compliance/remediation/requests/${r.id}`}
                        className="inline-flex items-center gap-1 text-xs text-content hover:text-content"
                      >
                        Open <ExternalLink size={12} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} offset={offset} onPage={onPage} />
        </>
      )}
    </CardBody>
  </Card>
  );
};

const PlanSection: React.FC<{
  title: string;
  emptyDescription: string;
  page: RemediationPlanPage;
  offset: number;
  onPage: (offset: number) => void;
}> = ({ title, emptyDescription, page, offset, onPage }) => {
  const formatTimestamp = useFormatTimestamp();
  return (
  <Card>
    <CardBody>
      <SectionHeader title={title} total={page.total} />
      {page.items.length === 0 ? (
        <EmptyState title={`No ${title.toLowerCase()}`} description={emptyDescription} />
      ) : (
        <>
          <div className="overflow-x-auto">
            <table className="w-full text-sm">
              <thead className="text-left text-content-muted border-b border-border">
                <tr>
                  <th className="py-2 pr-3">Plan</th>
                  <th className="py-2 pr-3">State</th>
                  <th className="py-2 pr-3">Kind</th>
                  <th className="py-2 pr-3">Acknowledged</th>
                  <th className="py-2 pr-3">Stale?</th>
                  <th className="py-2 pr-3">Ready?</th>
                  <th className="py-2 pr-3">Request</th>
                  <th className="py-2 pr-3"></th>
                </tr>
              </thead>
              <tbody>
                {page.items.map((p) => (
                  <tr key={p.id} className="border-b border-border/50">
                    <td className="py-2 pr-3 font-mono">#{p.id}</td>
                    <td className="py-2 pr-3">
                      <Badge variant={remediationPlanStateBadgeVariant(p.state)}>
                        {humanizeStatus(p.state)}
                      </Badge>
                    </td>
                    <td className="py-2 pr-3 text-xs text-content">
                      {PLAN_KIND_LABELS[p.plan_kind] ?? p.plan_kind}
                    </td>
                    <td className="py-2 pr-3 text-xs">
                      {p.acknowledged_at ? (
                        formatTimestamp(p.acknowledged_at)
                      ) : (
                        <Badge variant="warning">no</Badge>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      {p.is_stale ? (
                        <Badge variant="orange">stale</Badge>
                      ) : (
                        <Badge variant="success">fresh</Badge>
                      )}
                    </td>
                    <td className="py-2 pr-3">
                      {p.ready_for_execution ? (
                        <Badge variant="success">ready</Badge>
                      ) : (
                        <Badge variant="warning">not ready</Badge>
                      )}
                    </td>
                    <td className="py-2 pr-3 text-xs">
                      <Link
                        href={`/compliance/remediation/requests/${p.request_id}`}
                        className="text-blue-400 hover:underline"
                      >
                        Request #{p.request_id}
                      </Link>
                    </td>
                    <td className="py-2 pr-3 text-right">
                      <Link
                        href={`/compliance/remediation/plans/${p.id}`}
                        className="inline-flex items-center gap-1 text-xs text-content hover:text-content"
                      >
                        Open <ExternalLink size={12} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
          <Pager page={page} offset={offset} onPage={onPage} />
        </>
      )}
    </CardBody>
  </Card>
  );
};

const SectionHeader: React.FC<{ title: string; total: number }> = ({
  title,
  total,
}) => (
  <div className="flex items-center justify-between mb-3">
    <h2 className="text-lg font-semibold text-content">{title}</h2>
    <span className="text-xs text-content-muted">{total} total</span>
  </div>
);

const Pager: React.FC<{
  page: RemediationRequestPage | RemediationPlanPage;
  offset: number;
  onPage: (offset: number) => void;
}> = ({ page, offset, onPage }) => (
  <div className="mt-3 flex items-center justify-between text-xs text-content-muted">
    <span>
      Showing {page.items.length} of {page.total} (offset {page.offset})
    </span>
    <div className="flex gap-2">
      <Button
        variant="outline"
        size="sm"
        onClick={() => onPage(Math.max(0, offset - page.limit))}
        disabled={offset === 0}
      >
        Previous
      </Button>
      <Button
        variant="outline"
        size="sm"
        onClick={() =>
          page.next_offset !== null && onPage(page.next_offset)
        }
        disabled={page.next_offset === null}
      >
        Next
      </Button>
    </div>
  </div>
);

const Stat: React.FC<{ label: string; value: React.ReactNode }> = ({
  label,
  value,
}) => (
  <div className="min-w-[8rem]">
    <p className="text-xs uppercase tracking-wide text-content-subtle">{label}</p>
    <p className="text-2xl font-semibold text-content mt-0.5">{value}</p>
  </div>
);

export default ComplianceSystemRemediationPage;
