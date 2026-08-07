/**
 * PRA-312 Slice 2: per-host content-profile section for the system detail page.
 *
 * Completes the operator workflow terminal step (Mirror → Channel → Profile → Host):
 * shows the host's effective content profile, lets an operator assign a profile
 * (direct host subscription) or unassign a direct one, lists the resolved mirror
 * sources, and applies/reapplies the profile to the host. All of the client functions
 * + backend routes already existed; only this UI was missing.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { toast } from 'sonner';
import { Badge, Button, Card, CardBody, CardHeader, EmptyState } from '@/components/ui';
import { humanizeLabel, humanizeStatus } from '@/utils/humanize';
import {
  addHostSubscription,
  applyHostContentProfile,
  getHostEffectiveProfile,
  getHostResolvedContent,
  listProfiles,
  removeHostSubscription,
  type ApplyOutcome,
  type ContentProfile,
  type EffectiveProfile,
  type ResolvedContent,
} from '@/services/contentProfileService';

const APPLY_OK: ReadonlySet<string> = new Set(['applied', 'noop']);

interface Props {
  systemId: number;
  canWrite: boolean;
}

const HostContentProfileCard: React.FC<Props> = ({ systemId, canWrite }) => {
  const [effective, setEffective] = useState<EffectiveProfile | null>(null);
  const [resolved, setResolved] = useState<ResolvedContent | null>(null);
  const [profiles, setProfiles] = useState<ContentProfile[]>([]);
  const [assignId, setAssignId] = useState<number | null>(null);
  const [busy, setBusy] = useState(false);
  const [lastOutcome, setLastOutcome] = useState<ApplyOutcome | null>(null);
  const [error, setError] = useState<string | null>(null);

  const refresh = useCallback(async () => {
    try {
      const [eff, res, profs] = await Promise.all([
        getHostEffectiveProfile(systemId),
        getHostResolvedContent(systemId).catch(() => null),
        listProfiles().catch(() => [] as ContentProfile[]),
      ]);
      setEffective(eff);
      setResolved(res);
      setProfiles(profs.filter((p) => !p.deleted_at));
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [systemId]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  const handleAssign = async () => {
    if (!assignId) return;
    setBusy(true);
    try {
      await addHostSubscription(assignId, systemId);
      toast.success('Profile assigned to host');
      setAssignId(null);
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Assign failed');
    } finally {
      setBusy(false);
    }
  };

  const handleUnassign = async (profileId: number) => {
    if (!window.confirm('Remove this host’s direct profile subscription?')) return;
    setBusy(true);
    try {
      await removeHostSubscription(profileId, systemId);
      toast.success('Direct subscription removed');
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Remove failed');
    } finally {
      setBusy(false);
    }
  };

  const handleApply = async () => {
    setBusy(true);
    try {
      const outcome = await applyHostContentProfile(systemId);
      setLastOutcome(outcome);
      if (APPLY_OK.has(outcome.state)) {
        toast.success(
          outcome.state === 'noop'
            ? 'Already up to date - nothing to apply'
            : `Applied: ${outcome.written_paths.length} written, ${outcome.removed_paths.length} removed`,
        );
      } else {
        toast.error(outcome.error_text || `Apply refused (${humanizeStatus(outcome.state)})`);
      }
      await refresh();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Apply failed');
    } finally {
      setBusy(false);
    }
  };

  const binding = effective?.profile ?? null;
  const isDirect = binding?.via_kind === 'direct';

  return (
    <Card>
      <CardHeader>
        <div className="flex items-center justify-between">
          <span>Content profile</span>
          {effective && (
            <Badge
              variant={
                effective.state === 'resolved'
                  ? 'success'
                  : effective.state === 'conflict'
                    ? 'danger'
                    : 'neutral'
              }
            >
              {effective.state === 'resolved'
                ? 'Assigned'
                : effective.state === 'conflict'
                  ? 'Conflict'
                  : 'None'}
            </Badge>
          )}
        </div>
      </CardHeader>
      <CardBody>
        {error && <p className="text-sm text-red-400">{error}</p>}
        {!effective && !error && <p className="text-sm text-gray-400">Loading…</p>}

        {effective?.state === 'conflict' && (
          <div className="rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-300">
            This host resolves to more than one profile at the same tier. Resolve the
            conflicting bindings before applying:
            <ul className="mt-2 list-inside list-disc text-xs">
              {effective.conflict_bindings.map((b) => (
                <li key={`${b.via_kind}-${b.via_id}-${b.profile_id}`}>
                  {b.profile_display_name} (via {humanizeLabel(b.via_kind).toLowerCase()}
                  {b.via_label ? ` ${b.via_label}` : ''})
                </li>
              ))}
            </ul>
          </div>
        )}

        {effective?.state === 'no_profile' && (
          <EmptyState
            title="No content profile assigned"
            description="Assign a profile so this host serves the right mirrors, then apply it."
          />
        )}

        {binding && (
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <div>
                <Link
                  href={`/content-profiles/${binding.profile_id}`}
                  className="text-blue-400 hover:text-blue-300"
                >
                  {binding.profile_display_name}
                </Link>
                <div className="text-xs text-gray-500">
                  {binding.profile_slug} · via {humanizeLabel(binding.via_kind).toLowerCase()}
                  {binding.via_label ? ` (${binding.via_label})` : ''}
                </div>
              </div>
              {canWrite && (
                <div className="flex items-center gap-2">
                  {isDirect && (
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => handleUnassign(binding.profile_id)}
                      disabled={busy}
                    >
                      Unassign
                    </Button>
                  )}
                  <Button
                    variant="primary"
                    size="sm"
                    onClick={handleApply}
                    disabled={busy}
                  >
                    {busy ? 'Applying…' : lastOutcome ? 'Reapply' : 'Apply now'}
                  </Button>
                </div>
              )}
            </div>

            {resolved && resolved.entries.length > 0 && (
              <div className="text-xs text-gray-400">
                Resolves to {resolved.entries.length} mirror source(s):{' '}
                {resolved.entries.map((e) => e.mirror_slug).join(', ')}
              </div>
            )}

            {lastOutcome && (
              <div className="rounded border border-zinc-800 bg-black/20 p-2 text-xs text-gray-400">
                Last apply: <span className="text-gray-200">{lastOutcome.state}</span>
                {' · '}
                {lastOutcome.written_paths.length} written,{' '}
                {lastOutcome.removed_paths.length} removed
                {lastOutcome.error_text ? ` · ${lastOutcome.error_text}` : ''}
              </div>
            )}
          </div>
        )}

        {canWrite && effective && effective.state !== 'conflict' && (
          <div className="mt-4 flex items-end gap-2 border-t border-zinc-800 pt-3">
            <label className="flex-1 text-xs text-gray-500">
              {binding ? 'Assign a different profile (direct)' : 'Assign a profile'}
              <select
                className="mt-1 w-full rounded border border-zinc-700 bg-black/30 px-2 py-1.5 text-sm text-gray-200"
                value={assignId ?? ''}
                onChange={(e) =>
                  setAssignId(e.target.value ? Number(e.target.value) : null)
                }
              >
                <option value="">Select profile...</option>
                {profiles.map((p) => (
                  <option key={p.id} value={p.id}>
                    {p.display_name} ({p.package_family})
                  </option>
                ))}
              </select>
            </label>
            <Button
              variant="outline"
              size="sm"
              onClick={handleAssign}
              disabled={busy || !assignId}
            >
              Assign
            </Button>
          </div>
        )}
      </CardBody>
    </Card>
  );
};

export default HostContentProfileCard;
