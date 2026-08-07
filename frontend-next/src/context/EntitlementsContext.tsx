import { createContext, useContext, useEffect, useState, useCallback } from 'react';
import type { ReactNode } from 'react';
import { useAuth } from './AuthContext';
import {
  getEdition,
  type EditionInfo,
  type OnlineRefreshStatus,
} from '../services/editionService';

/**
 * PRA-132: edition/entitlement awareness for the UI. Fetches the read-only
 * `/edition` surface once the user is authenticated and exposes a
 * `hasEntitlement(key)` helper plus edition metadata (host cap/count). On any
 * error it **fails closed to the free edition** so paid controls stay locked
 * rather than accidentally unlocked. Enforcement is server-side; this only
 * decides what the UI presents.
 */
interface EntitlementsContextType {
  edition: string;
  entitlements: Record<string, boolean>;
  hostCap: number | null; // null == unlimited
  hostCount: number | null;
  hostsOverCap: boolean;
  issuedTo: string | null;
  loading: boolean;
  isEnterprise: boolean;
  hasEntitlement: (key: string) => boolean;
  refresh: () => Promise<void>;
  // PRA-133 license status.
  tier: string;
  licenseState: string;
  instanceId: string | null;
  expiresAt: string | null;
  overCap: boolean;
  inGrace: boolean;
  graceUntil: string | null;
  // Online license refresh status (never carries the token).
  onlineRefresh: OnlineRefreshStatus | null;
  info: EditionInfo | null;
}

const EntitlementsContext = createContext<EntitlementsContextType | null>(null);

export function EntitlementsProvider({ children }: { children: ReactNode }) {
  const { user } = useAuth();
  const [info, setInfo] = useState<EditionInfo | null>(null);
  const [loading, setLoading] = useState(true);

  const load = useCallback(async () => {
    if (!user) {
      setInfo(null);
      setLoading(false);
      return;
    }
    setLoading(true);
    try {
      setInfo(await getEdition());
    } catch {
      // Fail closed to free edition on error.
      setInfo(null);
    } finally {
      setLoading(false);
    }
  }, [user]);

  useEffect(() => {
    load();
  }, [load]);

  const entitlements = info?.entitlements ?? {};
  const edition = info?.edition ?? 'free';

  const hasEntitlement = useCallback(
    (key: string) => Boolean(info?.entitlements?.[key]),
    [info],
  );

  const value: EntitlementsContextType = {
    edition,
    entitlements,
    hostCap: info?.host_cap ?? 15,
    hostCount: info?.host_count ?? null,
    hostsOverCap: info?.hosts_over_cap ?? false,
    issuedTo: info?.issued_to ?? null,
    loading,
    isEnterprise: edition !== 'free',
    hasEntitlement,
    refresh: load,
    tier: info?.tier ?? 'free',
    licenseState: info?.license_state ?? 'none',
    instanceId: info?.instance_id ?? null,
    expiresAt: info?.expires_at ?? null,
    overCap: info?.over_cap ?? false,
    inGrace: info?.in_grace ?? false,
    graceUntil: info?.grace_until ?? null,
    onlineRefresh: info?.online_refresh ?? null,
    info,
  };

  return (
    <EntitlementsContext.Provider value={value}>{children}</EntitlementsContext.Provider>
  );
}

export function useEntitlements(): EntitlementsContextType {
  const context = useContext(EntitlementsContext);
  if (!context) {
    throw new Error('useEntitlements must be used within an EntitlementsProvider');
  }
  return context;
}
