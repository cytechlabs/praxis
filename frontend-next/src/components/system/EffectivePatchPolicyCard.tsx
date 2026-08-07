/**
 * PRA-161 #1f: effective patch-policy card for the host detail page.
 *
 * Calls ``GET /systems/{id}/patch-policy/effective`` and renders the
 * resolver result. Treats `no_policy` and `conflict` as first-class
 * states (per the slice 1f packet - DO NOT collapse a conflict into
 * "no policy"). The conflict path uses the structured 409 detail to
 * name the competing tier and policies so an operator can fix the
 * duplicate-binding state directly from the host page.
 */
import { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { AlertTriangle, RefreshCw, Star } from 'lucide-react';
import { Badge, Button, Card, CardBody, CardHeader } from '@/components/ui';
import {
  getEffectivePatchPolicy,
  RESOLUTION_KIND_LABELS,
  type EffectivePolicyResolution,
} from '@/services/patchPolicyService';

interface Props {
  systemId: number;
}

const EffectivePatchPolicyCard = ({ systemId }: Props) => {
  const [resolution, setResolution] = useState<EffectivePolicyResolution | null>(
    null,
  );
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState<string | null>(null);

  const load = useCallback(async () => {
    setLoading(true);
    setError(null);
    try {
      const r = await getEffectivePatchPolicy(systemId);
      setResolution(r);
    } catch (e) {
      setError(e instanceof Error ? e.message : 'Failed to fetch effective patch policy');
    } finally {
      setLoading(false);
    }
  }, [systemId]);

  useEffect(() => {
    load();
  }, [load]);

  const renderBody = () => {
    if (loading) {
      return <div className="text-sm text-gray-400">Loading…</div>;
    }
    if (error) {
      return (
        <div className="rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-300">
          {error}
        </div>
      );
    }
    if (!resolution) {
      return null;
    }

    if (resolution.state === 'conflict') {
      const detail = resolution.conflict;
      return (
        <div className="rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-200">
          <div className="mb-2 flex items-center gap-2 font-medium">
            <AlertTriangle size={14} />
            Effective patch-policy conflict
          </div>
          <div className="text-xs text-red-300">
            Multiple enabled policies are bound to this host at the same tier
            ({detail?.tier ?? 'unknown'}). The resolver will not silently pick
            one - fix the duplicate-binding state below before relying on the
            policy layer for this host.
          </div>
          {detail && detail.policies.length > 0 && (
            <ul className="mt-2 list-inside list-disc text-xs text-red-200">
              {detail.policies.map((p) => (
                <li key={p.id}>
                  <Link
                    href={`/patch-policies/${p.id}`}
                    className="font-mono text-red-200 underline hover:text-red-100"
                  >
                    {p.slug}
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      );
    }

    if (resolution.state === 'no_policy' || !resolution.effective?.policy) {
      return (
        <div className="text-sm text-gray-300">
          <Badge variant="neutral">No policy</Badge>
          <p className="mt-2 text-xs text-gray-500">
            No direct, static-group, smart-group, or fleet-default binding
            matches this host. Add one from the{' '}
            <Link
              href="/patch-policies/all"
              className="text-blue-400 hover:text-blue-300"
            >
              Patch policies
            </Link>{' '}
            page.
          </p>
        </div>
      );
    }

    const eff = resolution.effective;
    const policy = eff.policy!;
    const kindLabel = RESOLUTION_KIND_LABELS[eff.resolution_kind];
    return (
      <div className="text-sm">
        <div className="flex flex-wrap items-center gap-2">
          <Link
            href={`/patch-policies/${policy.id}`}
            className="font-mono text-base text-blue-400 hover:text-blue-300"
          >
            {policy.slug}
          </Link>
          <Badge variant="neutral">{kindLabel}</Badge>
          {policy.is_fleet_default && (
            <span
              className="inline-flex items-center gap-1 rounded border border-amber-700/40 bg-amber-900/20 px-1.5 py-0.5 text-xs text-amber-300"
              title="Resolved via the fleet-default fallback"
            >
              <Star size={11} className="fill-amber-300" />
              Fleet default
            </span>
          )}
        </div>
        <div className="mt-1 text-xs text-gray-400">{policy.name}</div>
        <dl className="mt-3 grid grid-cols-2 gap-x-6 gap-y-1 text-xs text-gray-300 md:grid-cols-3">
          <div>
            <dt className="text-gray-500">Scope</dt>
            <dd>{policy.scope_kind}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Reboot</dt>
            <dd>{policy.reboot_policy}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Cadence</dt>
            <dd>{policy.rollout_cadence}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Approval</dt>
            <dd>
              {policy.requires_approval
                ? `Required (${policy.required_approvals})`
                : '-'}
            </dd>
          </div>
          <div>
            <dt className="text-gray-500">Failure</dt>
            <dd>{policy.failure_policy}</dd>
          </div>
          <div>
            <dt className="text-gray-500">Enabled</dt>
            <dd>{policy.enabled ? 'yes' : 'no'}</dd>
          </div>
        </dl>
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
            onClick={load}
            disabled={loading}
            aria-label="Refresh effective patch policy"
          >
            <RefreshCw size={14} />
          </Button>
        }
      >
        <div>
          <div>Effective patch policy</div>
          <div className="mt-0.5 text-xs font-normal text-gray-500">
            Resolved via direct host &gt; static group &gt; smart group &gt; fleet default.
          </div>
        </div>
      </CardHeader>
      <CardBody>{renderBody()}</CardBody>
    </Card>
  );
};

export default EffectivePatchPolicyCard;
