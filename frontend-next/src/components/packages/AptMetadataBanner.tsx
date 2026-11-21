import React from 'react';
import { Badge } from '@/components/ui';
import { AptMetadataFreshness } from '@/services/packageService';

const MAX_LISTED = 5;

const STATE_LABEL: Record<string, string> = {
  partial: 'Partially refreshed',
  failed: 'Refresh failed',
  cached: 'Cached only',
};

/**
 * Tells the operator when update counts rest on APT metadata that no refresh
 * verified. Hosts whose freshness has never been recorded are unknown, not
 * unverified, and are not listed. Renders nothing when every recorded host is
 * verified.
 */
const AptMetadataBanner: React.FC<{
  rows: AptMetadataFreshness[];
  formatTimestamp: (value: string) => string;
}> = ({ rows, formatTimestamp }) => {
  const unverified = rows.filter(
    (r) => r.state === 'partial' || r.state === 'failed' || r.state === 'cached',
  );
  if (unverified.length === 0) return null;

  return (
    <div
      role="status"
      data-testid="apt-metadata-banner"
      className="mb-4 rounded-md border border-warning/30 bg-warning/15 p-3 text-sm"
    >
      <p className="font-medium text-content">
        {unverified.length === 1
          ? '1 host has update counts from unverified package metadata.'
          : `${unverified.length} hosts have update counts from unverified package metadata.`}{' '}
        The updates shown are last-known and may be out of date.
      </p>
      <ul className="mt-2 space-y-1">
        {unverified.slice(0, MAX_LISTED).map((r) => (
          <li key={r.system_id} className="flex flex-wrap items-center gap-2">
            <span className="font-medium">{r.hostname}</span>
            <Badge variant="warning">{STATE_LABEL[r.state] ?? r.state}</Badge>
            <span className="text-content-muted">
              {r.refreshed_at
                ? `Last verified refresh ${formatTimestamp(r.refreshed_at)}`
                : 'Never verified'}
            </span>
            {r.detail && <span className="text-content-muted">{r.detail}</span>}
          </li>
        ))}
      </ul>
      {unverified.length > MAX_LISTED && (
        <p className="mt-1 text-content-muted">
          and {unverified.length - MAX_LISTED} more
        </p>
      )}
    </div>
  );
};

export default AptMetadataBanner;
