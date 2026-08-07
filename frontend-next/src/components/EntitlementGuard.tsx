import React from 'react';
import { useAuth } from '@/context/AuthContext';
import { useEntitlements } from '@/context/EntitlementsContext';
import { ENTITLEMENTS } from '@/services/editionService';
import MainLayout from '@/components/MainLayout';
import PaidFeatureLock from '@/components/PaidFeatureLock';
import { LoadingState } from '@/components/ui';

/**
 * PRA-132: route-to-entitlement mapping for the dedicated paid pages. Prefix
 * matched like RoleGuard. Gating at the route boundary keeps the paid page from
 * mounting/fetching at all in the free edition, so we get a clean locked state
 * instead of a page that fires backend requests and collects 402s.
 */
const ENTITLEMENT_ROUTES: { prefix: string; key: string; label: string }[] = [
  { prefix: '/access/session-locks', key: ENTITLEMENTS.SESSION_LOCKS, label: 'Session locks' },
  {
    prefix: '/access/session-approvals',
    key: ENTITLEMENTS.SESSION_APPROVALS,
    label: 'Session approvals',
  },
  {
    prefix: '/access/access-reviews',
    key: ENTITLEMENTS.ACCESS_REVIEWS,
    label: 'Access reviews',
  },
  {
    prefix: '/ssh/approval-queue',
    key: ENTITLEMENTS.COMMAND_APPROVALS,
    label: 'Command approval queue',
  },
  {
    prefix: '/ssh/command-metrics',
    key: ENTITLEMENTS.COMMAND_METRICS,
    label: 'Command metrics',
  },
];

function matchRoute(pathname: string) {
  return ENTITLEMENT_ROUTES.find(
    (r) => pathname === r.prefix || pathname.startsWith(r.prefix + '/'),
  );
}

interface EntitlementGuardProps {
  children: React.ReactNode;
  pathname: string;
}

const EntitlementGuard: React.FC<EntitlementGuardProps> = ({ children, pathname }) => {
  const { user } = useAuth();
  const { hasEntitlement, loading } = useEntitlements();

  // Unauthenticated is handled upstream (ContentGuard). Unmatched routes and
  // still-resolving entitlement state pass through unchanged.
  if (!user) return <>{children}</>;
  const match = matchRoute(pathname);
  if (!match) return <>{children}</>;
  if (loading) {
    return (
      <MainLayout>
        <LoadingState label="Checking your plan" />
      </MainLayout>
    );
  }
  if (!hasEntitlement(match.key)) {
    return (
      <MainLayout>
        <PaidFeatureLock feature={match.label} />
      </MainLayout>
    );
  }
  return <>{children}</>;
};

export default EntitlementGuard;
