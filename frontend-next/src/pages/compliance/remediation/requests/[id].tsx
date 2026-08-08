/**
 * PRA-177 Slices 1 + 2 + 3 + 4: remediation request detail.
 *
 * Slice 1 ships the read shapes:
 *
 *   - request envelope (snapshot, justification, decision, lineage)
 *   - linked plan preview (or "no plan built yet" not-ready state)
 *   - per-request execution rollup with paginated attempt history
 *
 * Slice 2 adds the request lifecycle mutation controls:
 *
 *   - Approve   (admin only; SoD blocks the requester)
 *   - Reject    (admin only; SoD blocks the requester)
 *   - Cancel    (admin OR the original requester)
 *
 * Slice 3 adds plan lifecycle controls: Build / Rebuild / Acknowledge.
 *
 * Slice 4 closes the chain with execution-attempt controls:
 *
 *   - Create execution attempt (admin; gated on a current acknowledged
 *     plan that reads `ready_for_execution`)
 *   - Dispatch all pending attempts for the request (admin; gated on
 *     at least one attempt in state `pending` in the rollup; bounded
 *     by the backend `MAX_BATCH_SIZE`)
 *
 * Confirm modals wrap dispatch actions because they invoke the
 * existing governed PRA-171 patch transport - they are the only
 * mutations in the chain that can reach a host. Create-attempt
 * persists a durable audit row and re-checks the readiness gate but
 * never dispatches.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, Check, ExternalLink, X } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import {
  Badge,
  Button,
  Card,
  CardBody,
  ConfirmModal,
  EmptyState,
  ErrorState,
  Modal,
  PageHeader,
  SkeletonTable,
} from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  ComplianceApiError,
  PLAN_KIND_LABELS,
  REMEDIATION_BATCH_DISPATCH_MAX,
  RemediationExecutionBatchResult,
  RemediationExecutionRequestRollup,
  RemediationPlanRead,
  RemediationRequestRead,
  acknowledgeRemediationPlan,
  approveRemediationRequest,
  buildRemediationPlan,
  cancelRemediationRequest,
  createRemediationExecutionAttempt,
  dispatchRemediationRequestExecutions,
  getRemediationPlanForRequest,
  getRemediationRequest,
  checkKindLabel,
  getRemediationRequestExecutions,
  planNotReadyExplanation,
  rejectRemediationRequest,
  remediationExecutionStateBadgeVariant,
  remediationPlanStateBadgeVariant,
  remediationRequestStateBadgeVariant,
  SEVERITY_LABELS,
  severityBadgeVariant,
} from '@/services/complianceService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { fetchSystemDetails } from '@/services/systemService';

const EXECUTION_PAGE_SIZE = 25;

type DecisionAction = 'approve' | 'reject' | 'cancel';

const ComplianceRemediationRequestDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const requestId = Number(router.query.id);
  const { user, isAdmin, canWrite } = useAuth();

  const [request, setRequest] = useState<RemediationRequestRead | null>(null);
  const [plan, setPlan] = useState<RemediationPlanRead | null>(null);
  const [rollup, setRollup] = useState<RemediationExecutionRequestRollup | null>(
    null,
  );
  const [executionsOffset, setExecutionsOffset] = useState(0);
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Prefer a resolved hostname over a raw "system #id" in visible copy; fall
  // back to the id only when the hostname can't be resolved.
  const [hostname, setHostname] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!Number.isFinite(requestId)) return;
    setLoading(true);
    try {
      const [req, planRow, exec] = await Promise.all([
        getRemediationRequest(requestId),
        getRemediationPlanForRequest(requestId),
        getRemediationRequestExecutions(requestId, {
          offset: executionsOffset,
          limit: EXECUTION_PAGE_SIZE,
        }),
      ]);
      setRequest(req);
      setPlan(planRow);
      setRollup(exec);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [requestId, executionsOffset]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const systemId = request?.system_id;
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

  if (!Number.isFinite(requestId)) {
    return (
      <MainLayout>
        <div className="p-6 text-content-muted">Invalid remediation request id.</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>Remediation Request #{requestId} · Praxis</title>
      </Head>
      <div className="p-6 space-y-6">
        <PageHeader
          title={`Remediation Request #${requestId}`}
          subtitle={
            request
              ? `${request.policy_slug} / ${request.check_slug} on ${hostname ?? `system #${request.system_id}`}`
              : undefined
          }
          actions={
            <div className="flex items-center gap-2">
              <Link
                href="/compliance/remediation"
                className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
              >
                <ArrowLeft size={14} /> Fleet remediation
              </Link>
              {request && (
                <Link
                  href={`/compliance/systems/${request.system_id}/remediation`}
                  className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
                >
                  System inventory →
                </Link>
              )}
            </div>
          }
        />

        {error && (
          <ErrorState title="Couldn’t load request" onRetry={refresh} />
        )}

        {!request && loading ? (
          <Card>
            <CardBody>
              <SkeletonTable rows={6} cols={2} />
            </CardBody>
          </Card>
        ) : request ? (
          <>
            <Card>
              <CardBody>
                <div className="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-4">
                  <Row
                    label="State"
                    value={
                      <Badge
                        variant={remediationRequestStateBadgeVariant(request.state)}
                      >
                        {request.state}
                      </Badge>
                    }
                  />
                  <Row
                    label="Severity"
                    value={
                      <Badge variant={severityBadgeVariant(request.severity_snapshot)}>
                        {SEVERITY_LABELS[request.severity_snapshot]}
                      </Badge>
                    }
                  />
                  <Row
                    label="Verdict snapshot"
                    value={<span className="text-xs">{request.verdict_label}</span>}
                  />
                  <Row
                    label="Policy"
                    value={
                      <Link
                        href={`/compliance/policies/${request.policy_id}`}
                        className="text-blue-400 hover:underline font-mono text-xs"
                      >
                        {request.policy_slug} · v{request.policy_version}
                      </Link>
                    }
                  />
                  <Row
                    label="Check"
                    value={
                      <span className="font-mono text-xs">
                        {request.check_slug} ({checkKindLabel(request.check_kind)})
                      </span>
                    }
                  />
                  <Row
                    label="System"
                    value={
                      <Link
                        href={`/compliance/systems/${request.system_id}/remediation`}
                        className="text-blue-400 hover:underline"
                      >
                        {hostname ?? `#${request.system_id}`}
                      </Link>
                    }
                  />
                  <Row
                    label="Evidence"
                    value={
                      request.evidence_id !== null ? (
                        <Link
                          href={`/compliance/systems/${request.system_id}`}
                          className="text-blue-400 hover:underline text-xs font-mono"
                        >
                          evidence #{request.evidence_id}
                        </Link>
                      ) : (
                        <span className="text-xs text-content-subtle">
                          (evidence row deleted)
                        </span>
                      )
                    }
                  />
                  <Row
                    label="Evaluation run"
                    value={
                      <span className="font-mono text-xs text-content-muted">
                        {request.evaluation_run_id ?? '-'}
                      </span>
                    }
                  />
                  <Row label="Created" value={formatTimestamp(request.created_at)} />
                  <Row
                    label="Requested by"
                    value={
                      <span className="font-mono text-xs">
                        user #{request.requested_by}
                      </span>
                    }
                  />
                  <Row
                    label="Decided by"
                    value={
                      request.decided_by !== null ? (
                        <span className="font-mono text-xs">
                          user #{request.decided_by}
                        </span>
                      ) : (
                        <span className="text-xs text-content-subtle">-</span>
                      )
                    }
                  />
                  <Row
                    label="Decided at"
                    value={
                      request.decided_at
                        ? formatTimestamp(request.decided_at)
                        : '-'
                    }
                  />
                  {request.verdict_reason_snapshot_label && (
                    <Row
                      label="Verdict reason"
                      wide
                      value={
                        <span className="text-xs text-content">
                          {request.verdict_reason_snapshot_label}
                        </span>
                      }
                    />
                  )}
                  {request.remediation_guidance_snapshot && (
                    <Row
                      label="Remediation guidance"
                      wide
                      value={
                        <pre className="whitespace-pre-wrap text-sm text-content">
                          {request.remediation_guidance_snapshot}
                        </pre>
                      }
                    />
                  )}
                  {request.justification && (
                    <Row
                      label="Justification"
                      wide
                      value={
                        <pre className="whitespace-pre-wrap text-sm text-content">
                          {request.justification}
                        </pre>
                      }
                    />
                  )}
                  {request.decided_reason && (
                    <Row
                      label="Decision reason"
                      wide
                      value={
                        <pre className="whitespace-pre-wrap text-sm text-content">
                          {request.decided_reason}
                        </pre>
                      }
                    />
                  )}
                </div>
              </CardBody>
            </Card>

            <DecisionControls
              request={request}
              currentUserId={user?.id ?? null}
              isAdmin={isAdmin}
              onChanged={refresh}
            />

            <Card>
              <CardBody>
                <h2 className="text-lg font-semibold text-content mb-3">
                  Plan preview
                </h2>
                {plan ? (
                  <PlanSummary
                    plan={plan}
                    request={request}
                    canWrite={canWrite}
                    isAdmin={isAdmin}
                    onChanged={refresh}
                  />
                ) : request.state !== 'approved' ? (
                  <EmptyState
                    title="No plan preview"
                    description={`Plan previews are built only after a request is approved. Current state: ${request.state}.`}
                  />
                ) : (
                  <BuildPlanEmptyState
                    requestId={request.id}
                    canWrite={canWrite}
                    onChanged={refresh}
                  />
                )}
              </CardBody>
            </Card>

            <Card>
              <CardBody>
                <div className="flex items-center justify-between mb-3 flex-wrap gap-2">
                  <h2 className="text-lg font-semibold text-content">
                    Execution attempts
                  </h2>
                  <div className="flex items-center gap-3">
                    {rollup && (
                      <span className="text-xs text-content-muted">
                        {rollup.total_attempts} total
                      </span>
                    )}
                    {rollup && (
                      <BatchDispatchAction
                        requestId={request.id}
                        rollup={rollup}
                        isAdmin={isAdmin}
                        onChanged={refresh}
                      />
                    )}
                  </div>
                </div>
                {rollup ? (
                  <RollupTable
                    rollup={rollup}
                    page={executionsOffset}
                    onPage={setExecutionsOffset}
                  />
                ) : (
                  <SkeletonTable rows={3} cols={5} />
                )}
              </CardBody>
            </Card>
          </>
        ) : null}
      </div>
    </MainLayout>
  );
};

interface PlanSummaryProps {
  plan: RemediationPlanRead;
  request: RemediationRequestRead;
  canWrite: boolean;
  isAdmin: boolean;
  onChanged: () => Promise<void> | void;
}

const PlanSummary: React.FC<PlanSummaryProps> = ({
  plan,
  request,
  canWrite,
  isAdmin,
  onChanged,
}) => {
  const formatTimestamp = useFormatTimestamp();
  const notReady = planNotReadyExplanation(plan);
  return (
    <div className="space-y-4">
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
            <span className="text-sm text-content">
              {PLAN_KIND_LABELS[plan.plan_kind] ?? plan.plan_kind}
            </span>
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
              <span className="text-xs text-content">
                {formatTimestamp(plan.acknowledged_at)}
                {plan.acknowledged_by !== null && (
                  <span className="text-content-subtle">
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
        <Row
          label="Plan link"
          value={
            <Link
              href={`/compliance/remediation/plans/${plan.id}`}
              className="inline-flex items-center gap-1 text-xs text-blue-400 hover:underline"
            >
              Plan #{plan.id} <ExternalLink size={12} />
            </Link>
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
        <Row label="Built" value={formatTimestamp(plan.created_at)} />
      </div>
      {notReady && (
        <div className="border border-yellow-500/30 bg-yellow-500/5 rounded p-3 text-sm text-yellow-300">
          <span className="font-semibold">Not ready for execution: </span>
          {notReady}
        </div>
      )}
      {plan.unsupported_reason && (
        <div className="border border-orange-500/30 bg-orange-500/5 rounded p-3 text-sm text-orange-300">
          <span className="font-semibold">Unsupported: </span>
          {plan.unsupported_reason}
        </div>
      )}
      {plan.error_message && (
        <div className="border border-red-500/30 bg-red-500/5 rounded p-3 text-sm text-red-300">
          <span className="font-semibold">Build error: </span>
          {plan.error_message}
        </div>
      )}
      <PlanActions
        request={request}
        plan={plan}
        canWrite={canWrite}
        isAdmin={isAdmin}
        onChanged={onChanged}
      />
    </div>
  );
};

// ---------------------------------------------------------------------------
// PRA-177 Slice 3 - plan build / refresh / acknowledge controls.
//
// Build is metadata-only - the backend POST is idempotent and never
// runs anything on a host. Rebuild reuses the same route and is
// surfaced only when the current plan is stale, failed, unsupported,
// or review-required. Acknowledge flips operator-intent metadata
// and feeds the read-only `ready_for_execution` gate.
//
// Acknowledgement requires a `planned` current fresh non-acknowledged
// plan whose source request is still `approved` AND whose plan_kind
// has an executable shape. Review-required and unsupported plan
// kinds are disabled-with-explanation here even though the backend
// would otherwise accept the call - acknowledging them would only
// ever feed an always-false `ready_for_execution` gate (see
// docs/remediation-workflow.md). The disabled-state copy mirrors
// the backend `acknowledge_plan` fail-closed branches plus the
// non-executable plan_kind tail branches.
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
    return 'Plan is stale; rebuild it to capture the current check definition before acknowledging.';
  }
  if (plan.acknowledged_at) {
    return 'Plan is already acknowledged.';
  }
  // Review-required and unsupported plan kinds need manual operator
  // action - there is no automatable shape for a future execution
  // slice to consume, so the Slice 3 acceptance disables Acknowledge
  // here even though the backend would otherwise accept the call.
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

function rebuildEligible(plan: RemediationPlanRead): boolean {
  return (
    plan.is_stale ||
    plan.state === 'failed' ||
    plan.state === 'unsupported' ||
    plan.plan_kind.endsWith('_review_required')
  );
}

interface PlanActionsProps {
  request: RemediationRequestRead;
  plan: RemediationPlanRead;
  canWrite: boolean;
  isAdmin: boolean;
  onChanged: () => Promise<void> | void;
}

const PlanActions: React.FC<PlanActionsProps> = ({
  request,
  plan,
  canWrite,
  isAdmin,
  onChanged,
}) => {
  const [busy, setBusy] = useState<
    'rebuild' | 'acknowledge' | 'create-attempt' | null
  >(null);
  const [confirmCreate, setConfirmCreate] = useState(false);

  const rebuild = async () => {
    setBusy('rebuild');
    try {
      await buildRemediationPlan(request.id);
      toast.success('Plan preview rebuilt');
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Rebuild plan failed: ${msg}`);
    } finally {
      setBusy(null);
    }
  };

  const ack = async () => {
    setBusy('acknowledge');
    try {
      await acknowledgeRemediationPlan(request.id);
      toast.success('Plan acknowledged');
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Acknowledge plan failed: ${msg}`);
    } finally {
      setBusy(null);
    }
  };

  const createAttempt = async () => {
    setBusy('create-attempt');
    try {
      const created = await createRemediationExecutionAttempt(plan.id);
      toast.success(`Execution attempt #${created.id} created`);
      setConfirmCreate(false);
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Create execution attempt failed: ${msg}`);
    } finally {
      setBusy(null);
    }
  };

  const ackBlocked = acknowledgeBlockedReason(request, plan);
  const showRebuild = rebuildEligible(plan);
  const createBlocked: string | null = !plan.ready_for_execution
    ? 'Plan must be current, acknowledged, fresh, and of an executable ' +
      'package kind before an execution attempt can be created.'
    : null;

  // Hide the action row entirely if there are no controls to show and
  // the user lacks any privilege; keeps auditor-friendly read-only.
  if (!canWrite && !isAdmin) return null;

  return (
    <>
      <div className="border-t border-border pt-4 space-y-2">
        <div className="flex flex-wrap items-center gap-2">
          {canWrite && showRebuild && (
            <Button
              variant="outline"
              onClick={rebuild}
              loading={busy === 'rebuild'}
              disabled={busy !== null}
            >
              Rebuild plan preview
            </Button>
          )}
          {isAdmin && (
            <Button
              variant="primary"
              onClick={ack}
              loading={busy === 'acknowledge'}
              disabled={busy !== null || ackBlocked !== null}
              title={ackBlocked ?? undefined}
            >
              Acknowledge plan
            </Button>
          )}
          {isAdmin && (
            <Button
              variant="outline"
              onClick={() => setConfirmCreate(true)}
              disabled={busy !== null || createBlocked !== null}
              title={createBlocked ?? undefined}
            >
              Create execution attempt
            </Button>
          )}
          {!isAdmin && canWrite && (
            <span
              className="text-[11px] text-content-subtle"
              title="Plan acknowledgement and attempt creation require the admin role."
            >
              Acknowledge / create attempt requires admin
            </span>
          )}
        </div>
        {isAdmin && ackBlocked && (
          <div className="text-xs text-yellow-300 border border-yellow-500/30 bg-yellow-500/5 rounded p-2">
            <span className="font-semibold">Acknowledge unavailable: </span>
            {ackBlocked}
          </div>
        )}
        {isAdmin && createBlocked && (
          <div className="text-xs text-yellow-300 border border-yellow-500/30 bg-yellow-500/5 rounded p-2">
            <span className="font-semibold">Create attempt unavailable: </span>
            {createBlocked}
          </div>
        )}
        <p className="text-[11px] text-content-subtle">
          Rebuild, acknowledge, and create-attempt all flip metadata only -
          they never run commands, dispatch attempts, mutate hosts, or
          refresh facts. Dispatch happens from the execution detail page or
          the request batch CTA below.
        </p>
      </div>
      <ConfirmModal
        open={confirmCreate}
        onClose={() => {
          if (busy === null) setConfirmCreate(false);
        }}
        onConfirm={createAttempt}
        title="Create execution attempt?"
        message={
          `Persist a durable execution-attempt audit row against current ` +
          `plan #${plan.id}. This re-checks the readiness gate but does NOT ` +
          `dispatch - the attempt enters state \`pending\` and an admin must ` +
          `explicitly dispatch it from the execution detail page or the ` +
          `request batch CTA.`
        }
        confirmLabel="Create attempt"
        variant="warning"
        loading={busy === 'create-attempt'}
      />
    </>
  );
};

interface BuildPlanEmptyStateProps {
  requestId: number;
  canWrite: boolean;
  onChanged: () => Promise<void> | void;
}

const BuildPlanEmptyState: React.FC<BuildPlanEmptyStateProps> = ({
  requestId,
  canWrite,
  onChanged,
}) => {
  const [submitting, setSubmitting] = useState(false);

  const build = async () => {
    setSubmitting(true);
    try {
      await buildRemediationPlan(requestId);
      toast.success('Plan preview built');
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Build plan failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="space-y-3">
      <EmptyState
        title="No plan preview built yet"
        description="Build a structured preview of what dispatch would do for this approved request. Building flips metadata only - it never runs anything on the host."
      />
      {canWrite ? (
        <div className="flex justify-end">
          <Button variant="primary" onClick={build} loading={submitting}>
            Build plan preview
          </Button>
        </div>
      ) : (
        <p className="text-[11px] text-content-subtle text-right">
          Build requires the admin or maintainer role.
        </p>
      )}
    </div>
  );
};

// ---------------------------------------------------------------------------
// PRA-177 Slice 4 - bounded request-scoped batch dispatch CTA.
//
// Visible next to the Execution attempts heading. Disabled with
// explanation when:
//   - the current user is not admin, or
//   - the rollup contains zero attempts in state `pending`.
//
// The confirm modal surfaces the bound (`MAX_BATCH_SIZE`) and the
// continue-on-error / per-attempt audit behavior so the operator
// knows what they are committing to. Result is summarized via toast
// once the backend returns the batch envelope.
// ---------------------------------------------------------------------------

interface BatchDispatchActionProps {
  requestId: number;
  rollup: RemediationExecutionRequestRollup;
  isAdmin: boolean;
  onChanged: () => Promise<void> | void;
}

const BatchDispatchAction: React.FC<BatchDispatchActionProps> = ({
  requestId,
  rollup,
  isAdmin,
  onChanged,
}) => {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const pendingCount = rollup.counts_by_state.pending ?? 0;
  const blocked: string | null = !isAdmin
    ? 'Batch dispatch requires the admin role.'
    : pendingCount === 0
      ? 'No attempts are in state `pending` for this request.'
      : null;

  const dispatch = async () => {
    setSubmitting(true);
    try {
      const result: RemediationExecutionBatchResult =
        await dispatchRemediationRequestExecutions(requestId, {
          limit: REMEDIATION_BATCH_DISPATCH_MAX,
        });
      toast.success(
        `Batch dispatch: ${result.dispatched_count} dispatched ` +
          `(${result.succeeded_count} ok, ${result.failed_count} fail, ` +
          `${result.refused_count} refused)`,
      );
      setConfirmOpen(false);
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Batch dispatch failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="flex flex-col items-end gap-1">
      <Button
        variant="outline"
        size="sm"
        onClick={() => setConfirmOpen(true)}
        disabled={blocked !== null}
        title={blocked ?? undefined}
      >
        Dispatch all pending ({pendingCount})
      </Button>
      {blocked && (
        <div
          className="text-[11px] text-yellow-300 border border-yellow-500/30 bg-yellow-500/5 rounded px-2 py-1 max-w-xs text-right"
          data-testid="batch-dispatch-blocked"
        >
          <span className="font-semibold">Batch dispatch unavailable: </span>
          {blocked}
        </div>
      )}
      <ConfirmModal
        open={confirmOpen}
        onClose={() => {
          if (!submitting) setConfirmOpen(false);
        }}
        onConfirm={dispatch}
        title="Dispatch all pending attempts?"
        message={
          `Dispatch every \`pending\` execution attempt for this request, ` +
          `bounded by the backend max of ${REMEDIATION_BATCH_DISPATCH_MAX}. ` +
          `Each attempt is dispatched through the approved patch execution ` +
          `transport and audited individually; failures and ` +
          `refusals do not stop the loop. This action CAN reach hosts.`
        }
        confirmLabel="Dispatch all"
        variant="danger"
        loading={submitting}
      />
    </div>
  );
};

const RollupTable: React.FC<{
  rollup: RemediationExecutionRequestRollup;
  page: number;
  onPage: (offset: number) => void;
}> = ({ rollup, page, onPage }) => {
  const formatTimestamp = useFormatTimestamp();
  if (rollup.total_attempts === 0) {
    return (
      <EmptyState
        title="No execution attempts"
        description="Execution attempts are persisted when an operator dispatches a ready, acknowledged plan. Dispatch is available from the execution attempt detail page."
      />
    );
  }
  return (
    <>
      <div className="flex flex-wrap gap-4 text-xs text-content mb-3">
        {Object.entries(rollup.counts_by_state).map(([state, count]) => (
          <span key={state}>
            <Badge variant={remediationExecutionStateBadgeVariant(state)}>
              {state}
            </Badge>{' '}
            <span className="font-mono">{count}</span>
          </span>
        ))}
        {Object.keys(rollup.counts_by_failure_reason).length > 0 && (
          <span className="text-content-muted">
            failure reasons:{' '}
            <span className="font-mono">
              {Object.entries(rollup.counts_by_failure_reason)
                .map(([reason, count]) => `${reason}=${count}`)
                .join(', ')}
            </span>
          </span>
        )}
      </div>
      <div className="overflow-x-auto">
        <table className="w-full text-sm">
          <thead className="text-left text-content-muted border-b border-border">
            <tr>
              <th className="py-2 pr-3">Attempt</th>
              <th className="py-2 pr-3">State</th>
              <th className="py-2 pr-3">Plan kind</th>
              <th className="py-2 pr-3">Package</th>
              <th className="py-2 pr-3">Dispatched</th>
              <th className="py-2 pr-3">Completed</th>
              <th className="py-2 pr-3">Failure reason</th>
              <th className="py-2 pr-3"></th>
            </tr>
          </thead>
          <tbody>
            {rollup.attempts.map((a) => (
              <tr key={a.id} className="border-b border-border/50">
                <td className="py-2 pr-3 font-mono">#{a.id}</td>
                <td className="py-2 pr-3">
                  <Badge variant={remediationExecutionStateBadgeVariant(a.state)}>
                    {a.state}
                  </Badge>
                </td>
                <td className="py-2 pr-3 text-xs text-content">
                  {PLAN_KIND_LABELS[
                    a.plan_kind_snapshot as keyof typeof PLAN_KIND_LABELS
                  ] ?? a.plan_kind_snapshot}
                </td>
                <td className="py-2 pr-3 font-mono text-xs">
                  {a.package_name ?? '-'}
                  {a.package_version_target ? ` @ ${a.package_version_target}` : ''}
                </td>
                <td className="py-2 pr-3 text-xs text-content">
                  {a.dispatched_at ? formatTimestamp(a.dispatched_at) : '-'}
                </td>
                <td className="py-2 pr-3 text-xs text-content">
                  {a.completed_at ? formatTimestamp(a.completed_at) : '-'}
                </td>
                <td className="py-2 pr-3 font-mono text-xs text-content-muted">
                  {a.failure_reason ?? '-'}
                </td>
                <td className="py-2 pr-3 text-right">
                  <Link
                    href={`/compliance/remediation/executions/${a.id}`}
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
      <div className="mt-3 flex items-center justify-between text-xs text-content-muted">
        <span>
          Showing {rollup.returned_count} of {rollup.total_attempts} (offset{' '}
          {rollup.offset})
        </span>
        <div className="flex gap-2">
          <Button
            variant="outline"
            size="sm"
            onClick={() => onPage(Math.max(0, page - rollup.limit))}
            disabled={page === 0}
          >
            Previous
          </Button>
          <Button
            variant="outline"
            size="sm"
            onClick={() =>
              rollup.next_offset !== null && onPage(rollup.next_offset)
            }
            disabled={!rollup.has_more}
          >
            Next
          </Button>
        </div>
      </div>
    </>
  );
};

const Row: React.FC<{
  label: string;
  value: React.ReactNode;
  wide?: boolean;
}> = ({ label, value, wide }) => (
  <div className={wide ? 'md:col-span-3' : ''}>
    <p className="text-xs uppercase tracking-wide text-content-subtle">{label}</p>
    <div className="text-sm text-content mt-0.5">{value}</div>
  </div>
);

// ---------------------------------------------------------------------------
// PRA-177 Slice 2 - request lifecycle decision controls.
//
// Visible only when the request is in state `requested`. Terminal
// states (`approved`/`rejected`/`cancelled`) render an explanatory
// banner instead so an auditor sees that the row is closed and why.
// ---------------------------------------------------------------------------

interface DecisionControlsProps {
  request: RemediationRequestRead;
  currentUserId: number | null;
  isAdmin: boolean;
  onChanged: () => Promise<void> | void;
}

const DecisionControls: React.FC<DecisionControlsProps> = ({
  request,
  currentUserId,
  isAdmin,
  onChanged,
}) => {
  const [pending, setPending] = useState<DecisionAction | null>(null);
  const [reason, setReason] = useState('');
  const [submitting, setSubmitting] = useState(false);

  if (request.state !== 'requested') {
    return (
      <Card>
        <CardBody>
          <div className="text-sm text-content-muted">
            This request is{' '}
            <span className="font-semibold text-content">{request.state}</span>
            . Lifecycle decisions are closed; open a new request from a
            failing evidence row if remediation is still needed.
          </div>
        </CardBody>
      </Card>
    );
  }

  const isRequester =
    currentUserId !== null && currentUserId === request.requested_by;
  const canApproveReject = isAdmin && !isRequester;
  const canCancel = isAdmin || isRequester;

  const open = (action: DecisionAction) => {
    setPending(action);
    setReason('');
  };
  const close = () => {
    if (submitting) return;
    setPending(null);
    setReason('');
  };

  const labelFor = (action: DecisionAction): string =>
    action === 'approve'
      ? 'Approve request'
      : action === 'reject'
        ? 'Reject request'
        : 'Cancel request';

  const submit = async () => {
    if (pending === null) return;
    setSubmitting(true);
    const trimmed = reason.trim();
    const decided_reason = trimmed ? trimmed : null;
    try {
      if (pending === 'approve') {
        await approveRemediationRequest(request.id, decided_reason);
        toast.success(`Request #${request.id} approved`);
      } else if (pending === 'reject') {
        await rejectRemediationRequest(request.id, decided_reason);
        toast.success(`Request #${request.id} rejected`);
      } else {
        await cancelRemediationRequest(request.id, decided_reason);
        toast.success(`Request #${request.id} cancelled`);
      }
      setPending(null);
      setReason('');
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`${labelFor(pending)} failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <>
      <Card>
        <CardBody>
          <div className="flex flex-wrap items-center justify-between gap-3">
            <div>
              <h2 className="text-lg font-semibold text-content">
                Lifecycle decision
              </h2>
              <p className="text-xs text-content-subtle mt-1 max-w-xl">
                Approval flips request state only - it never builds a plan,
                dispatches an attempt, mutates a host, refreshes facts,
                scans packages, or auto-installs/removes anything.
              </p>
            </div>
            <div className="flex flex-wrap items-center gap-2">
              <Button
                variant="primary"
                onClick={() => open('approve')}
                disabled={!canApproveReject}
                title={
                  canApproveReject
                    ? undefined
                    : isRequester
                      ? 'Separation of duties: the original requester cannot approve their own request.'
                      : 'Approve requires the admin role.'
                }
              >
                <Check size={14} /> Approve
              </Button>
              <Button
                variant="outline"
                onClick={() => open('reject')}
                disabled={!canApproveReject}
                title={
                  canApproveReject
                    ? undefined
                    : isRequester
                      ? 'Separation of duties: the original requester cannot reject their own request.'
                      : 'Reject requires the admin role.'
                }
              >
                <X size={14} /> Reject
              </Button>
              <Button
                variant="outline"
                onClick={() => open('cancel')}
                disabled={!canCancel}
                title={
                  canCancel
                    ? undefined
                    : 'Cancel requires the admin role or being the original requester.'
                }
              >
                Cancel
              </Button>
            </div>
          </div>
          {!canApproveReject && isRequester && (
            <div className="mt-3 text-xs text-yellow-300 border border-yellow-500/30 bg-yellow-500/5 rounded p-2">
              Separation of duties (SOC 2 CC6.3): the original requester
              cannot approve or reject their own request. An admin who did
              not open this request must decide.
            </div>
          )}
        </CardBody>
      </Card>

      <Modal
        open={pending !== null}
        onClose={close}
        title={pending ? labelFor(pending) : ''}
      >
        <div className="space-y-4">
          <p className="text-xs text-content-muted">
            Optional reason recorded in the audit row as{' '}
            <code className="font-mono">decided_reason</code>. Maximum 4096
            characters.
          </p>
          <textarea
            rows={4}
            maxLength={4096}
            className="w-full bg-surface-sunken border border-border rounded px-3 py-1.5 text-sm text-content"
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="Reason (optional)"
            aria-label="Decision reason"
          />
          <div className="flex justify-end gap-2">
            <Button variant="outline" onClick={close} disabled={submitting}>
              Back
            </Button>
            <Button
              variant={pending === 'approve' ? 'primary' : 'outline'}
              onClick={submit}
              loading={submitting}
            >
              Confirm {pending}
            </Button>
          </div>
        </div>
      </Modal>
    </>
  );
};

export default ComplianceRemediationRequestDetailPage;
