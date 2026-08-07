import React, { useCallback, useEffect, useState } from 'react';
import Link from 'next/link';
import { Server, ShieldAlert, AlertTriangle } from 'lucide-react';
import { fetchFleetHealth } from '@/services/fleetHealthService';
import { fetchAllSecurityUpdates } from '@/services/packageService';
import { fetchFailedJobs } from '@/services/jobService';

/**
 * PRA-273 (workspace tabs): exception-first status badges - the always-rendered
 * five-signal ribbon is gone. A badge appears ONLY when its signal is in an
 * exception state, and each links to the page that owns the same number:
 *
 *   1. Unreachable systems - `fetchFleetHealth().unreachable` (existing top-bar /
 *      fleet-health semantics) → All Systems (unreachable filter).
 *   2. Critical security updates - `fetchAllSecurityUpdates().length`, the SAME
 *      source + calculation the Security Updates page uses for its headline count
 *      → Security Updates.
 *   3. Failed jobs - `fetchFailedJobs().total`, the server-computed shared count
 *      → Failed Jobs.
 *
 * There is deliberately NO active-jobs badge (running jobs are not an exception),
 * and no frontend-only grace-window logic - each count is the backend's.
 */
interface Counts {
  unreachable: number;
  criticalUpdates: number;
  failedJobs: number;
}

const ExceptionBadges: React.FC = () => {
  const [counts, setCounts] = useState<Counts>({
    unreachable: 0,
    criticalUpdates: 0,
    failedJobs: 0,
  });

  const load = useCallback(async () => {
    const [health, security, failed] = await Promise.all([
      fetchFleetHealth().catch(() => null),
      fetchAllSecurityUpdates().catch(() => null),
      fetchFailedJobs(1, 0).catch(() => null),
    ]);
    setCounts({
      unreachable: health?.unreachable ?? 0,
      criticalUpdates: Array.isArray(security) ? security.length : 0,
      failedJobs: failed?.total ?? 0,
    });
  }, []);

  useEffect(() => {
    load();
    const interval = setInterval(load, 30000);
    return () => clearInterval(interval);
  }, [load]);

  const badges = [
    {
      key: 'systems',
      icon: <Server size={13} />,
      count: counts.unreachable,
      label: counts.unreachable === 1 ? 'unreachable system' : 'unreachable systems',
      href: '/system-management/all-systems?status=Unreachable',
    },
    {
      key: 'security',
      icon: <ShieldAlert size={13} />,
      count: counts.criticalUpdates,
      label: 'critical updates',
      href: '/package-management/security-updates',
    },
    {
      key: 'jobs',
      icon: <AlertTriangle size={13} />,
      count: counts.failedJobs,
      label: counts.failedJobs === 1 ? 'failed job' : 'failed jobs',
      href: '/job-scheduling/failed-jobs',
    },
  ].filter((b) => b.count > 0);

  // Quiet healthy-state telemetry - the top chrome stays populated when there are
  // no exceptions, without adding noise (restrained muted text + a small dot).
  if (badges.length === 0) {
    return (
      <div
        className="flex items-center gap-1.5 text-xs text-content-subtle"
        title="No fleet exceptions"
      >
        <span className="h-1.5 w-1.5 rounded-full bg-success/80" />
        <span className="hidden lg:inline">No action needed</span>
      </div>
    );
  }

  return (
    <div className="flex items-center gap-2 text-xs">
      {badges.map((b) => (
        <Link
          key={b.key}
          href={b.href}
          className="flex items-center gap-1.5 rounded bg-danger/15 px-2 py-1 text-danger transition-colors hover:bg-danger/20 focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
        >
          {b.icon}
          <span className="font-semibold tabular-nums">{b.count}</span>
          <span className="hidden lg:inline">{b.label}</span>
          <span className="relative flex h-1.5 w-1.5">
            <span className="absolute inline-flex h-full w-full animate-ping rounded-full bg-danger opacity-75" />
            <span className="relative inline-flex h-1.5 w-1.5 rounded-full bg-danger" />
          </span>
        </Link>
      ))}
    </div>
  );
};

export default ExceptionBadges;
