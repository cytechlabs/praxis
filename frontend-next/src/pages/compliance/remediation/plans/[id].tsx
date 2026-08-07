/**
 * PRA-177 Slice 1 + 3: remediation plan preview detail.
 *
 * Slice 1 renders the existing PRA-167 plan envelope: state +
 * lifecycle, plan steps (structured intent, NOT executable shell),
 * staleness and acknowledgement metadata, and the derived
 * ready_for_execution gate with a human explanation for any
 * not-ready branch.
 *
 * Slice 3 adds an inline Acknowledge CTA that mirrors the
 * request-detail behavior. The button is admin-only, enabled only
 * when the source request is still `approved`, the plan is current,
 * `planned`, fresh, and not already acknowledged. Every other
 * branch renders a concise disabled-state explanation instead.
 * Acknowledgement is metadata-only - it never dispatches anything.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft } from 'lucide-react';
import { toast } from 'sonner';
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
import { useAuth } from '@/context/AuthContext';
import {
  ComplianceApiError,
  PLAN_KIND_LABELS,
  RemediationPlanRead,
  RemediationRequestRead,
  acknowledgeRemediationPlan,
  checkKindLabel,
  getRemediationPlan,
  getRemediationRequest,
  planNotReadyExplanation,
  remediationPlanStateBadgeVariant,
  remediationRequestStateBadgeVariant,
  SEVERITY_LABELS,
  severityBadgeVariant,
} from '@/services/complianceService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { fetchSystemDetails } from '@/services/systemService';

const ComplianceRemediationPlanDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const planId = Number(router.query.id);
  const { isAdmin } = useAuth();

  const [plan, setPlan] = useState<RemediationPlanRead | null>(null);
  const [request, setRequest] = useState<RemediationRequestRead | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Prefer a resolved hostname over a raw "system #id" in visible copy.
  const [hostname, setHostname] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!Number.isFinite(planId)) return;
    setLoading(true);
    try {
      const planRow = await getRemediationPlan(planId);
      setPlan(planRow);
      // Fetch the source request so the acknowledge gate can consult
      // the live request state; ignore a 404/error here so the plan
      // page still renders if the request lookup fails.
      try {
        setRequest(await getRemediationRequest(planRow.request_id));
      } catch {
        setRequest(null);
      }
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [planId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const systemId = plan?.system_id;
  useEffect(() => {
    if (systemId == null) return;
    let cancelled = false;
    setHostname(null);
    fetchSystemDetails(systemId)
      .then((s) => {
        if (!cancelled) setHostname(s.hostname);
      })
      .catch(() => {
        if (!cancelled) setHostname(null);
      });
    return () => {
      cancelled = true;
    };
  }, [systemId]);

  if (!Number.isFinite(planId)) {
    return (
      <MainLayout>
        <div className="p-6 text-gray-400">Invalid plan id.</div>
      </MainLayout>
    );
  }

  const notReady = plan ? planNotReadyExplanation(plan) : null;

  return (
    <MainLayout>
      <Head>
        <title>Remediation Plan #{planId} · Praxis</title>
      </Head>
      <div className="p-6 space-y-6">
        <PageHeader
          title={`Remediation Plan #${planId}`}
          subtitle={
            plan
              ? `${plan.policy_slug} / ${plan.check_slug} on ${hostname ?? `system #${plan.system_id}`}`
              : undefined
          }
          actions={
            <div className="flex items-center gap-2">
              {plan && (
                <Link
                  href={`/compliance/remediation/requests/${plan.request_id}`}
                  className="inline-flex items-center gap-1.5 text-sm text-gray-300 hover:text-gray-100"
                >
                  <ArrowLeft size={14} /> Request #{plan.request_id}
                </Link>
              )}
              <Link
                href="/compliance/remediation"
                className="inline-flex items-center gap-1.5 text-sm text-gray-300 hover:text-gray-100"
              >
                Fleet remediation →
              </Link>
            </div>
          }
        />

        {error && (
          <ErrorState title="Couldn’t load plan" onRetry={refresh} />
        )}

        {!plan && loading ? (
          <Card>
            <CardBody>
              <SkeletonTable rows={6} cols={2} />
            </CardBody>
          </Card>
        ) : plan ? (
          <>
            <Card>
              <CardBody>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-4">
                  <Row
                    label="State"
                    value={
                      <Badge variant={remediationPlanStateBadgeVariant(plan.state)}>
                        {plan.state}
                      </Badge>
                    }
                  />
                  <Row
                    label="Plan kind"
                    value={
                      <span className="text-sm text-gray-200">
                        {PLAN_KIND_LABELS[plan.plan_kind] ?? plan.plan_kind}
                      </span>
                    }
                  />
                  <Row
                    label="Severity"
                    value={
                      <Badge variant={severityBadgeVariant(plan.severity_snapshot)}>
                        {SEVERITY_LABELS[plan.severity_snapshot]}
                      </Badge>
                    }
                  />
                  <Row
                    label="Policy"
                    value={
                      <Link
                        href={`/compliance/policies/${plan.policy_id}`}
                        className="text-blue-400 hover:underline font-mono text-xs"
                      >
                        {plan.policy_slug} · v{plan.policy_version}
                      </Link>
                    }
                  />
                  <Row
                    label="Check"
                    value={
                      <span className="font-mono text-xs">
                        {plan.check_slug} ({checkKindLabel(plan.check_kind)})
                      </span>
                    }
                  />
                  <Row
                    label="System"
                    value={
                      <Link
                        href={`/compliance/systems/${plan.system_id}/remediation`}
                        className="text-blue-400 hover:underline"
                      >
                        {hostname ?? `#${plan.system_id}`}
                      </Link>
                    }
                  />
                  <Row
                    label="Current?"
                    value={
                      plan.is_current ? (
                        <Badge variant="success">current</Badge>
                      ) : (
                        <Badge variant="neutral">superseded</Badge>
                      )
                    }
                  />
                  <Row
                    label="Acknowledged"
                    value={
                      plan.acknowledged_at ? (
                        <span className="text-xs text-gray-300">
                          {formatTimestamp(plan.acknowledged_at)}
                          {plan.acknowledged_by !== null && (
                            <span className="text-gray-500">
                              {' '}
                              · user #{plan.acknowledged_by}
                            </span>
                          )}
                        </span>
                      ) : (
                        <Badge variant="warning">not acknowledged</Badge>
                      )
                    }
                  />
                  <Row
                    label="Stale?"
                    value={
                      plan.is_stale ? (
                        <Badge variant="orange">stale</Badge>
                      ) : (
                        <Badge variant="success">fresh</Badge>
                      )
                    }
                  />
                  <Row
                    label="Ready for execution"
                    value={
                      plan.ready_for_execution ? (
                        <Badge variant="success">ready</Badge>
                      ) : (
                        <Badge variant="warning">not ready</Badge>
                      )
                    }
                  />
                  {plan.superseded_by_plan_id !== null && (
                    <Row
                      label="Superseded by"
                      value={
                        <Link
                          href={`/compliance/remediation/plans/${plan.superseded_by_plan_id}`}
                          className="text-blue-400 hover:underline text-xs"
                        >
                          Plan #{plan.superseded_by_plan_id}
                        </Link>
                      }
                    />
                  )}
                  <Row
                    label="Fingerprint"
                    value={
                      <span className="font-mono text-[10px] text-gray-400 break-all">
                        {plan.check_definition_fingerprint ?? '-'}
                      </span>
                    }
                  />
                  <Row label="Built" value={formatTimestamp(plan.created_at)} />
                  <Row label="Updated" value={formatTimestamp(plan.updated_at)} />
                  <Row
                    label="Built by"
                    value={
                      <span className="font-mono text-xs">
                        user #{plan.created_by}
                      </span>
                    }
                  />
                </div>
                <AcknowledgeAction
                  plan={plan}
                  request={request}
                  isAdmin={isAdmin}
                  onChanged={refresh}
                />
              </CardBody>
            </Card>

            {notReady && (
              <Card>
                <CardBody>
                  <div className="border border-yellow-500/30 bg-yellow-500/5 rounded p-3 text-sm text-yellow-300">
                    <span className="font-semibold">
                      Not ready for execution:{' '}
                    </span>
                    {notReady}
                  </div>
                </CardBody>
              </Card>
            )}

            {plan.unsupported_reason && (
              <Card>
                <CardBody>
                  <div className="border border-orange-500/30 bg-orange-500/5 rounded p-3 text-sm text-orange-300">
                    <span className="font-semibold">Unsupported reason: </span>
                    {plan.unsupported_reason}
                  </div>
                </CardBody>
              </Card>
            )}

            {plan.error_message && (
              <Card>
                <CardBody>
                  <div className="border border-red-500/30 bg-red-500/5 rounded p-3 text-sm text-red-300">
                    <span className="font-semibold">Build error: </span>
                    {plan.error_message}
                  </div>
                </CardBody>
              </Card>
            )}

            <Card>
              <CardBody>
                <h2 className="text-lg font-semibold text-gray-200 mb-3">
                  Plan steps
                </h2>
                <p className="text-xs text-gray-500 mb-3">
                  Structured intent only - not executable shell. Dispatch
                  consumes these for ready package plans;
                  review-required and unsupported kinds always require manual
                  operator action.
                </p>
                {plan.plan_steps.length === 0 ? (
                  <EmptyState
                    title="No plan steps"
                    description="This plan has no structured steps. Check the state and unsupported reason above."
                  />
                ) : (
                  <ol className="space-y-3">
                    {plan.plan_steps.map((step, idx) => (
                      <li
                        key={idx}
                        className="border border-gray-800 rounded p-3 bg-gray-900/40"
                      >
                        <div className="flex items-center gap-2 mb-2">
                          <span className="text-xs text-gray-500 font-mono">
                            step {idx + 1}
                          </span>
                          {typeof step.action_intent === 'string' && (
                            <Badge variant="info">{step.action_intent}</Badge>
                          )}
                          {typeof step.safety_notes === 'string' && (
                            <span className="text-xs text-gray-400">
                              {step.safety_notes}
                            </span>
                          )}
                        </div>
                        <pre className="text-xs font-mono text-gray-300 whitespace-pre-wrap overflow-x-auto">
                          {JSON.stringify(step, null, 2)}
                        </pre>
                      </li>
                    ))}
                  </ol>
                )}
              </CardBody>
            </Card>
          </>
        ) : null}
      </div>
    </MainLayout>
  );
};

// ---------------------------------------------------------------------------
// PRA-177 Slice 3 - inline Acknowledge CTA mirrored from request detail.
// ---------------------------------------------------------------------------

function acknowledgeBlockedReason(
  request: RemediationRequestRead | null,
  plan: RemediationPlanRead,
): string | null {
  if (request && request.state !== 'approved') {
    return `Request state is ${request.state}; only approved requests can have a plan acknowledged.`;
  }
  if (!plan.is_current) {
    return 'Plan is superseded by a newer current plan.';
  }
  if (plan.state !== 'planned') {
    return `Plan state is ${plan.state}; only planned previews can be acknowledged.`;
  }
  if (plan.is_stale) {
    return 'Plan is stale; rebuild it from the request detail page before acknowledging.';
  }
  if (plan.acknowledged_at) {
    return 'Plan is already acknowledged.';
  }
  if (plan.plan_kind.endsWith('_review_required')) {
    return (
      'Plan kind requires manual operator review; no automated shape ' +
      'exists for this check kind, so acknowledgement is disabled.'
    );
  }
  if (plan.plan_kind === 'unsupported') {
    return (
      'Plan kind is unsupported; no automated remediation shape exists ' +
      'for this check kind.'
    );
  }
  return null;
}

interface AcknowledgeActionProps {
  plan: RemediationPlanRead;
  request: RemediationRequestRead | null;
  isAdmin: boolean;
  onChanged: () => Promise<void> | void;
}

const AcknowledgeAction: React.FC<AcknowledgeActionProps> = ({
  plan,
  request,
  isAdmin,
  onChanged,
}) => {
  const [submitting, setSubmitting] = useState(false);

  if (!isAdmin) {
    return (
      <div className="border-t border-gray-800 pt-4 mt-4 text-[11px] text-gray-500">
        Plan acknowledgement requires the admin role.
      </div>
    );
  }

  const blocked = acknowledgeBlockedReason(request, plan);

  const submit = async () => {
    setSubmitting(true);
    try {
      await acknowledgeRemediationPlan(plan.request_id);
      toast.success('Plan acknowledged');
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Acknowledge plan failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="border-t border-gray-800 pt-4 mt-4 space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        {request && (
          <span className="text-xs text-gray-400">
            Source request:{' '}
            <Link
              href={`/compliance/remediation/requests/${request.id}`}
              className="text-blue-400 hover:underline"
            >
              #{request.id}
            </Link>{' '}
            <Badge variant={remediationRequestStateBadgeVariant(request.state)}>
              {request.state}
            </Badge>
          </span>
        )}
        <Button
          variant="primary"
          onClick={submit}
          loading={submitting}
          disabled={blocked !== null}
          title={blocked ?? undefined}
          className="ml-auto"
        >
          Acknowledge plan
        </Button>
      </div>
      {blocked && (
        <div className="text-xs text-yellow-300 border border-yellow-500/30 bg-yellow-500/5 rounded p-2">
          <span className="font-semibold">Acknowledge unavailable: </span>
          {blocked}
        </div>
      )}
      <p className="text-[11px] text-gray-500">
        Acknowledgement flips operator-intent metadata only - it never
        runs commands, dispatches anything, or mutates a host.
      </p>
    </div>
  );
};

const Row: React.FC<{
  label: string;
  value: React.ReactNode;
  wide?: boolean;
}> = ({ label, value, wide }) => (
  <div className={wide ? 'md:col-span-3' : ''}>
    <p className="text-xs uppercase tracking-wide text-gray-500">{label}</p>
    <div className="text-sm text-gray-200 mt-0.5">{value}</div>
  </div>
);

export default ComplianceRemediationPlanDetailPage;
