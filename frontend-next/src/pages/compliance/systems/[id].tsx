/**
 * PRA-165 Slice 4: per-host compliance evidence.
 *
 * Mounted at ``/compliance/systems/[id]`` so any compliance page can
 * link directly to a host's verdict timeline without forcing the
 * operator to first navigate to /system-management/system/[id].
 * Reads evidence from ``GET /compliance/systems/{id}/evidence``;
 * supports verdict filter + offset paging. Export buttons hang off
 * the page header for admin/maintainer.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import ExportEvidenceMenu from '@/components/compliance/ExportEvidenceMenu';
import OpenRemediationRequestButton from '@/components/compliance/OpenRemediationRequestButton';
import {
  Badge,
  Button,
  Card,
  CardBody,
  EmptyState,
  nativeSelectClass,
  PageHeader,
  SkeletonTable,
} from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  ComplianceEvidencePage,
  listSystemEvidence,
  statusBadgeVariant,
  Verdict,
  VERDICTS,
} from '@/services/complianceService';
import { fetchSystemDetails } from '@/services/systemService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const ComplianceSystemEvidencePage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const systemId = Number(router.query.id);
  const { canWrite } = useAuth();

  const [verdict, setVerdict] = useState<Verdict | ''>('');
  const [policyIdText, setPolicyIdText] = useState('');
  const [offset, setOffset] = useState(0);
  const [page, setPage] = useState<ComplianceEvidencePage | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  const [hostname, setHostname] = useState<string | null>(null);
  const limit = 50;

  // Resolve the hostname for the header; fall back to "System #<id>" on failure or
  // for a decommissioned host.
  useEffect(() => {
    if (!Number.isFinite(systemId)) return;
    fetchSystemDetails(systemId)
      .then((s) => setHostname(s.hostname))
      .catch(() => setHostname(null));
  }, [systemId]);

  const hostLabel = hostname ?? `System #${systemId}`;

  const policyIdFilter = (() => {
    const trimmed = policyIdText.trim();
    if (!trimmed) return undefined;
    const n = Number(trimmed);
    return Number.isFinite(n) && n > 0 ? n : undefined;
  })();

  const refresh = useCallback(async () => {
    if (!Number.isFinite(systemId)) return;
    setLoading(true);
    try {
      const data = await listSystemEvidence(systemId, {
        verdict: verdict || undefined,
        policy_id: policyIdFilter,
        offset,
        limit,
      });
      setPage(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [systemId, verdict, policyIdFilter, offset]);

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
        <title>{hostLabel} Compliance · Praxis</title>
      </Head>

      <div className="p-6 space-y-6">
        <PageHeader
          title={`${hostLabel} Compliance`}
          subtitle="Per-host evidence timeline pulled from the compliance evaluation runner."
          actions={
            <div className="flex items-center gap-2">
              <Link
                href="/compliance"
                className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
              >
                <ArrowLeft size={14} /> Compliance dashboard
              </Link>
              <Link
                href={`/compliance/systems/${systemId}/remediation`}
                className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
              >
                Remediation inventory →
              </Link>
              <Link
                href={`/system-management/system/${systemId}`}
                className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
              >
                System detail →
              </Link>
              {canWrite && (
                <ExportEvidenceMenu
                  baseOpts={{
                    system_id: systemId,
                    verdict: verdict || undefined,
                    policy_id: policyIdFilter,
                  }}
                />
              )}
            </div>
          }
        />

        <Card>
          <CardBody>
            <div className="flex items-center mb-4 gap-4 flex-wrap">
              <div className="flex items-center gap-2">
                <label className="text-xs text-content-muted uppercase tracking-wide">
                  Verdict
                </label>
                <select
                  className={`border border-border rounded px-3 py-1.5 text-sm ${nativeSelectClass}`}
                  value={verdict}
                  onChange={(e) => {
                    setVerdict(e.target.value as Verdict | '');
                    setOffset(0);
                  }}
                >
                  <option value="">All</option>
                  {VERDICTS.map((v) => (
                    <option key={v} value={v}>
                      {v}
                    </option>
                  ))}
                </select>
              </div>
              <div className="flex items-center gap-2">
                <label className="text-xs text-content-muted uppercase tracking-wide">
                  Policy ID
                </label>
                <input
                  type="number"
                  min={1}
                  placeholder="any"
                  className="w-24 bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
                  value={policyIdText}
                  onChange={(e) => {
                    setPolicyIdText(e.target.value);
                    setOffset(0);
                  }}
                />
              </div>
            </div>

            {error && (
              <p className="text-red-400 text-sm mb-2">
                Something went wrong. Please try again.
              </p>
            )}

            {loading && !page ? (
              <SkeletonTable rows={6} cols={6} />
            ) : page && page.items.length === 0 ? (
              <EmptyState
                title="No evidence rows match"
                description="This host has no compliance verdicts in the current filter. The evaluation runner stamps new rows on each due sweep."
              />
            ) : page ? (
              <>
                <div className="overflow-x-auto">
                  <table className="w-full text-sm">
                    <thead className="text-left text-content-muted border-b border-border">
                      <tr>
                        <th className="py-2 pr-3">Evaluated</th>
                        <th className="py-2 pr-3">Policy</th>
                        <th className="py-2 pr-3">Check</th>
                        <th className="py-2 pr-3">Status</th>
                        <th className="py-2 pr-3">Evaluator</th>
                        <th className="py-2 pr-3">Reason</th>
                        <th className="py-2 pr-3">Observed</th>
                        <th className="py-2 pr-3"></th>
                      </tr>
                    </thead>
                    <tbody>
                      {page.items.map((r) => (
                        <tr key={r.id} className="border-b border-border/50">
                          <td className="py-2 pr-3 text-xs text-content">
                            {formatTimestamp(r.evaluated_at)}
                          </td>
                          <td className="py-2 pr-3">
                            <Link
                              href={`/compliance/policies/${r.policy_id}`}
                              className="text-blue-400 hover:underline font-mono text-xs"
                            >
                              {r.policy_slug}
                            </Link>
                          </td>
                          <td className="py-2 pr-3 font-mono text-xs">
                            {r.check_slug}
                          </td>
                          <td className="py-2 pr-3">
                            <Badge variant={statusBadgeVariant(r.status)}>
                              {r.status_label}
                            </Badge>
                          </td>
                          <td className="py-2 pr-3 text-xs text-content">
                            {r.runner_label}
                          </td>
                          <td className="py-2 pr-3 text-xs text-content-muted">
                            {r.verdict_reason_label ?? '-'}
                          </td>
                          <td className="py-2 pr-3 text-xs text-content-muted font-mono">
                            {r.observed_value ?? '-'}
                          </td>
                          <td className="py-2 pr-3 text-right">
                            <OpenRemediationRequestButton
                              row={r}
                              onOpened={refresh}
                            />
                          </td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
                <div className="mt-3 flex items-center justify-between text-xs text-content-muted">
                  <span>
                    Showing {page.items.length} of {page.total} (offset {page.offset})
                  </span>
                  <div className="flex gap-2">
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => setOffset(Math.max(0, offset - limit))}
                      disabled={offset === 0}
                    >
                      Previous
                    </Button>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() =>
                        page.next_offset !== null && setOffset(page.next_offset)
                      }
                      disabled={page.next_offset === null}
                    >
                      Next
                    </Button>
                  </div>
                </div>
              </>
            ) : null}
          </CardBody>
        </Card>
      </div>
    </MainLayout>
  );
};

export default ComplianceSystemEvidencePage;
