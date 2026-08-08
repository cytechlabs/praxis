/**
 * PRA-177 Slice 1 + 4: remediation execution attempt detail.
 *
 * Slice 1 ships the read envelope: state, transport, package
 * identifiers, approval lineage, dispatch / completion timing,
 * exit code, structured failure reason, and stdout / stderr
 * summaries.
 *
 * Slice 4 adds a single-attempt Dispatch CTA (admin only) when
 * the attempt state is `pending`. The CTA is wrapped in a
 * confirmation modal because dispatch invokes the existing
 * governed PRA-171 patch transport - it is the only mutation
 * here that can reach a host. The backend re-checks the
 * readiness gate at write time; failures surface via toast.
 * Terminal states render the button disabled with explanation.
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
  ConfirmModal,
  ErrorState,
  PageHeader,
  SkeletonTable,
} from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  ComplianceApiError,
  PLAN_KIND_LABELS,
  RemediationExecutionAttemptRead,
  checkKindLabel,
  dispatchRemediationExecution,
  getRemediationExecution,
  remediationExecutionStateBadgeVariant,
  SEVERITY_LABELS,
  severityBadgeVariant,
} from '@/services/complianceService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { fetchSystemDetails } from '@/services/systemService';

const ComplianceRemediationExecutionDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const attemptId = Number(router.query.id);

  const { isAdmin } = useAuth();
  const [attempt, setAttempt] = useState<RemediationExecutionAttemptRead | null>(
    null,
  );
  const [error, setError] = useState<string | null>(null);
  const [loading, setLoading] = useState(true);
  // Prefer a resolved hostname over a raw "system #id" in visible copy.
  const [hostname, setHostname] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    if (!Number.isFinite(attemptId)) return;
    setLoading(true);
    try {
      setAttempt(await getRemediationExecution(attemptId));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [attemptId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const systemId = attempt?.system_id;
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

  if (!Number.isFinite(attemptId)) {
    return (
      <MainLayout>
        <div className="p-6 text-content-muted">Invalid execution attempt id.</div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>Remediation Execution #{attemptId} · Praxis</title>
      </Head>
      <div className="p-6 space-y-6">
        <PageHeader
          title={`Remediation Execution #${attemptId}`}
          subtitle={
            attempt
              ? `${attempt.policy_slug} / ${attempt.check_slug} on ${hostname ?? `system #${attempt.system_id}`}`
              : undefined
          }
          actions={
            <div className="flex items-center gap-2">
              {attempt && (
                <Link
                  href={`/compliance/remediation/requests/${attempt.request_id}`}
                  className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
                >
                  <ArrowLeft size={14} /> Request #{attempt.request_id}
                </Link>
              )}
              <Link
                href="/compliance/remediation"
                className="inline-flex items-center gap-1.5 text-sm text-content hover:text-content"
              >
                Fleet remediation →
              </Link>
            </div>
          }
        />

        {error && (
          <ErrorState title="Couldn’t load execution" onRetry={refresh} />
        )}

        {!attempt && loading ? (
          <Card>
            <CardBody>
              <SkeletonTable rows={6} cols={2} />
            </CardBody>
          </Card>
        ) : attempt ? (
          <Card>
            <CardBody>
              <div className="grid grid-cols-1 md:grid-cols-3 gap-x-6 gap-y-4">
                <Row
                  label="State"
                  value={
                    <Badge
                      variant={remediationExecutionStateBadgeVariant(attempt.state)}
                    >
                      {attempt.state}
                    </Badge>
                  }
                />
                <Row
                  label="Plan kind snapshot"
                  value={
                    <span className="text-sm text-content">
                      {PLAN_KIND_LABELS[
                        attempt.plan_kind_snapshot as keyof typeof PLAN_KIND_LABELS
                      ] ?? attempt.plan_kind_snapshot}
                    </span>
                  }
                />
                <Row
                  label="Severity"
                  value={
                    <Badge variant={severityBadgeVariant(attempt.severity_snapshot)}>
                      {SEVERITY_LABELS[attempt.severity_snapshot]}
                    </Badge>
                  }
                />
                <Row
                  label="Plan"
                  value={
                    attempt.plan_id !== null ? (
                      <Link
                        href={`/compliance/remediation/plans/${attempt.plan_id}`}
                        className="text-blue-400 hover:underline text-xs"
                      >
                        Plan #{attempt.plan_id}
                      </Link>
                    ) : (
                      <span className="text-xs text-content-subtle">-</span>
                    )
                  }
                />
                <Row
                  label="Policy"
                  value={
                    <Link
                      href={`/compliance/policies/${attempt.policy_id}`}
                      className="text-blue-400 hover:underline font-mono text-xs"
                    >
                      {attempt.policy_slug} · v{attempt.policy_version}
                    </Link>
                  }
                />
                <Row
                  label="Check"
                  value={
                    <span className="font-mono text-xs">
                      {attempt.check_slug} ({checkKindLabel(attempt.check_kind)})
                    </span>
                  }
                />
                <Row
                  label="System"
                  value={
                    <Link
                      href={`/compliance/systems/${attempt.system_id}/remediation`}
                      className="text-blue-400 hover:underline"
                    >
                      {hostname ?? `#${attempt.system_id}`}
                    </Link>
                  }
                />
                <Row
                  label="Package"
                  value={
                    <span className="font-mono text-xs">
                      {attempt.package_name ?? '-'}
                      {attempt.package_version_target
                        ? ` @ ${attempt.package_version_target}`
                        : ''}
                    </span>
                  }
                />
                <Row
                  label="Transport"
                  value={
                    <span className="font-mono text-xs">
                      {attempt.transport ?? '-'}
                    </span>
                  }
                />
                <Row
                  label="Approval decided by"
                  value={
                    attempt.approval_decided_by !== null ? (
                      <span className="font-mono text-xs">
                        user #{attempt.approval_decided_by}
                      </span>
                    ) : (
                      <span className="text-xs text-content-subtle">-</span>
                    )
                  }
                />
                <Row
                  label="Approval decided at"
                  value={
                    attempt.approval_decided_at
                      ? formatTimestamp(attempt.approval_decided_at)
                      : '-'
                  }
                />
                <Row
                  label="Created"
                  value={formatTimestamp(attempt.created_at)}
                />
                <Row
                  label="Created by"
                  value={
                    <span className="font-mono text-xs">
                      user #{attempt.created_by}
                    </span>
                  }
                />
                <Row
                  label="Dispatched"
                  value={
                    attempt.dispatched_at
                      ? formatTimestamp(attempt.dispatched_at)
                      : '-'
                  }
                />
                <Row
                  label="Completed"
                  value={
                    attempt.completed_at
                      ? formatTimestamp(attempt.completed_at)
                      : '-'
                  }
                />
                <Row
                  label="Exit code"
                  value={
                    attempt.exit_code !== null ? (
                      <span className="font-mono">{attempt.exit_code}</span>
                    ) : (
                      <span className="text-xs text-content-subtle">-</span>
                    )
                  }
                />
                <Row
                  label="Duration"
                  value={
                    attempt.duration_ms !== null ? (
                      <span className="font-mono">
                        {attempt.duration_ms.toLocaleString()} ms
                      </span>
                    ) : (
                      <span className="text-xs text-content-subtle">-</span>
                    )
                  }
                />
                <Row
                  label="Failure reason"
                  value={
                    <span className="font-mono text-xs">
                      {attempt.failure_reason ?? '-'}
                    </span>
                  }
                />
                {attempt.error_message && (
                  <Row
                    label="Error message"
                    wide
                    value={
                      <pre className="whitespace-pre-wrap text-xs font-mono text-red-300">
                        {attempt.error_message}
                      </pre>
                    }
                  />
                )}
                {attempt.stdout_summary && (
                  <Row
                    label="stdout summary"
                    wide
                    value={
                      <pre className="whitespace-pre-wrap text-xs font-mono text-content">
                        {attempt.stdout_summary}
                      </pre>
                    }
                  />
                )}
                {attempt.stderr_summary && (
                  <Row
                    label="stderr summary"
                    wide
                    value={
                      <pre className="whitespace-pre-wrap text-xs font-mono text-content">
                        {attempt.stderr_summary}
                      </pre>
                    }
                  />
                )}
              </div>
              <DispatchAction
                attempt={attempt}
                isAdmin={isAdmin}
                onChanged={refresh}
              />
            </CardBody>
          </Card>
        ) : null}
      </div>
    </MainLayout>
  );
};

// ---------------------------------------------------------------------------
// PRA-177 Slice 4 - single-attempt dispatch CTA.
//
// Visible when `state === 'pending'`. Wrapped in a confirmation
// modal because dispatch invokes the existing governed PRA-171
// patch transport on the live backend - the only mutation on this
// page that can reach a host. Disabled with explanation when the
// attempt is in a terminal state or when the user is not admin.
// The backend re-checks the readiness gate at write time; the UI
// surface is a UX nicety, the backend remains authoritative.
// ---------------------------------------------------------------------------

interface DispatchActionProps {
  attempt: RemediationExecutionAttemptRead;
  isAdmin: boolean;
  onChanged: () => Promise<void> | void;
}

const DispatchAction: React.FC<DispatchActionProps> = ({
  attempt,
  isAdmin,
  onChanged,
}) => {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [submitting, setSubmitting] = useState(false);

  const blocked: string | null = !isAdmin
    ? 'Dispatch requires the admin role.'
    : attempt.state !== 'pending'
      ? `Attempt is in state \`${attempt.state}\`; only \`pending\` attempts can be dispatched.`
      : null;

  const dispatch = async () => {
    setSubmitting(true);
    try {
      await dispatchRemediationExecution(attempt.id);
      toast.success(`Attempt #${attempt.id} dispatched`);
      setConfirmOpen(false);
      await onChanged();
    } catch (e) {
      const msg = e instanceof ComplianceApiError ? e.message : String(e);
      toast.error(`Dispatch attempt failed: ${msg}`);
    } finally {
      setSubmitting(false);
    }
  };

  return (
    <div className="border-t border-border pt-4 mt-4 space-y-2">
      <div className="flex flex-wrap items-center gap-3">
        <Button
          variant="primary"
          onClick={() => setConfirmOpen(true)}
          disabled={blocked !== null}
          title={blocked ?? undefined}
          className="ml-auto"
        >
          Dispatch attempt
        </Button>
      </div>
      {blocked && (
        <div className="text-xs text-yellow-300 border border-yellow-500/30 bg-yellow-500/5 rounded p-2">
          <span className="font-semibold">Dispatch unavailable: </span>
          {blocked}
        </div>
      )}
      <p className="text-[11px] text-content-subtle">
        Dispatch invokes the approved patch execution transport on
        the backend. The backend re-checks the readiness gate at write
        time and walks the attempt through{' '}
        <code className="font-mono">pending → dispatched → succeeded | failed</code>{' '}
        on this same row.
      </p>
      <ConfirmModal
        open={confirmOpen}
        onClose={() => {
          if (!submitting) setConfirmOpen(false);
        }}
        onConfirm={dispatch}
        title="Dispatch attempt?"
        message={
          `Dispatch attempt #${attempt.id} through the approved patch ` +
          `execution transport. The backend re-checks the readiness gate; on ` +
          `success the attempt transitions to \`succeeded\`, otherwise to ` +
          `\`failed\` with a structured failure reason. This action CAN ` +
          `reach the host.`
        }
        confirmLabel="Dispatch"
        variant="danger"
        loading={submitting}
      />
    </div>
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

export default ComplianceRemediationExecutionDetailPage;
