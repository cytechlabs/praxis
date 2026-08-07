import { Trash2 } from 'lucide-react';
import Link from 'next/link';
import {
  ActivationToken,
  ActivationTokenStatus,
} from '../../../services/activationTokenService';
import { Tag } from '../../../services/tagService';
import { Badge, Button, EmptyState } from '@/components/ui';

interface Props {
  tokens: ActivationToken[];
  groupNamesById: Record<number, string>;
  tagsById: Record<number, Tag>;
  usernamesById: Record<number, string>;
  onRevoke: (token: ActivationToken) => void;
  busyId: number | null;
}

const STATUS_VARIANT: Record<ActivationTokenStatus, 'success' | 'warning' | 'danger'> = {
  active: 'success',
  expired: 'warning',
  exhausted: 'warning',
  revoked: 'danger',
};

const STATUS_LABEL: Record<ActivationTokenStatus, string> = {
  active: 'Active',
  expired: 'Expired',
  exhausted: 'Exhausted',
  revoked: 'Revoked',
};

interface RelativeTime {
  /** True when the timestamp is in the past relative to now. */
  past: boolean;
  /** Absolute magnitude as a short label, e.g. "47m", "3d". */
  label: string;
}

/**
 * Returns the magnitude of |t - now| as a short label plus a flag
 * indicating whether it is in the past. Callers compose phrasing
 * ("in {label}" vs "{label} ago") so we never end up with
 * "expired -2h ago".
 */
const formatRelative = (iso: string): RelativeTime => {
  const deltaSec = Math.round((new Date(iso).getTime() - Date.now()) / 1000);
  const past = deltaSec < 0;
  const abs = Math.abs(deltaSec);
  let label: string;
  if (abs < 60) label = `${abs}s`;
  else if (abs < 3600) label = `${Math.round(abs / 60)}m`;
  else if (abs < 86400) label = `${Math.round(abs / 3600)}h`;
  else label = `${Math.round(abs / 86400)}d`;
  return { past, label };
};

const ActivationTokensTable = ({
  tokens,
  groupNamesById,
  tagsById,
  usernamesById,
  onRevoke,
  busyId,
}: Props) => {
  if (tokens.length === 0) {
    return (
      <EmptyState
        title="No activation tokens"
        description="Create an activation token to enroll a host with the M14 thin agent."
      />
    );
  }

  return (
    <div className="overflow-x-auto rounded-md border border-slate-800">
      <table className="min-w-full divide-y divide-slate-800 text-sm">
        <thead className="bg-slate-900/40 text-xs uppercase tracking-wider text-slate-400">
          <tr>
            <th className="px-3 py-2 text-left">Name</th>
            <th className="px-3 py-2 text-left">Target</th>
            <th className="px-3 py-2 text-left">Group</th>
            <th className="px-3 py-2 text-left">Tags</th>
            <th className="px-3 py-2 text-left">Prefix</th>
            <th className="px-3 py-2 text-left">Status</th>
            <th className="px-3 py-2 text-left">Expires</th>
            <th className="px-3 py-2 text-left">Created by</th>
            <th className="px-3 py-2 text-right">Actions</th>
          </tr>
        </thead>
        <tbody className="divide-y divide-slate-800 text-slate-200">
          {tokens.map((t) => {
            const rel = formatRelative(t.ttl_expires_at);
            const expiresAbs = new Date(t.ttl_expires_at).toISOString();
            const expiresPhrase = rel.past
              ? `expired ${rel.label} ago`
              : `in ${rel.label}`;
            const groupName = groupNamesById[t.default_group_id] ?? `#${t.default_group_id}`;
            const createdBy = usernamesById[t.created_by_user_id] ?? `user #${t.created_by_user_id}`;
            return (
              <tr key={t.id} className="hover:bg-slate-900/30">
                <td className="px-3 py-2">{t.name}</td>
                <td className="px-3 py-2">
                  {t.target_system_hostname ? (
                    <Link
                      href={`/system-management/system/${t.target_system_id}`}
                      className="text-slate-200 underline-offset-2 hover:underline"
                    >
                      {t.target_system_hostname}
                    </Link>
                  ) : (
                    <span className="text-slate-500">-</span>
                  )}
                </td>
                <td className="px-3 py-2 text-slate-300">{groupName}</td>
                <td className="px-3 py-2">
                  {t.default_tag_ids.length === 0 ? (
                    <span className="text-xs text-slate-500">-</span>
                  ) : (
                    <div className="flex flex-wrap gap-1">
                      {t.default_tag_ids.map((tid) => {
                        const tag = tagsById[tid];
                        return (
                          <span
                            key={tid}
                            className="inline-flex items-center rounded border border-slate-700 px-1.5 py-0.5 text-xs text-slate-300"
                            style={tag?.color ? { borderColor: tag.color } : undefined}
                          >
                            {tag?.name ?? `#${tid}`}
                          </span>
                        );
                      })}
                    </div>
                  )}
                </td>
                <td className="px-3 py-2 font-mono text-xs text-slate-400">
                  praxis_{t.token_prefix}…
                </td>
                <td className="px-3 py-2">
                  <Badge variant={STATUS_VARIANT[t.status]}>{STATUS_LABEL[t.status]}</Badge>
                </td>
                <td className="px-3 py-2" title={expiresAbs}>
                  {expiresPhrase}
                </td>
                <td className="px-3 py-2 text-slate-300">{createdBy}</td>
                <td className="px-3 py-2 text-right">
                  {t.status === 'active' ? (
                    <Button
                      variant="danger"
                      size="sm"
                      icon={<Trash2 className="h-3.5 w-3.5" />}
                      loading={busyId === t.id}
                      disabled={busyId !== null}
                      onClick={() => onRevoke(t)}
                    >
                      Revoke
                    </Button>
                  ) : (
                    <span className="text-xs text-slate-500">-</span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
};

export default ActivationTokensTable;
