import { apiFetch, formatApiError } from '../utils/api';
import { PackageScope, scopeSearchParams } from './packageScope';

// Types

export interface PackageItem {
  id: number;
  name: string;
  installed_version: string;
  package_type: string;
  is_security_critical: boolean;
  is_held: boolean;
  installation_date: string | null;
  last_audited: string | null;
}

export interface PackageListResponse {
  system_id: number;
  total: number;
  limit: number;
  offset: number;
  packages: PackageItem[];
}

export interface ScanResult {
  system_id: number;
  hostname: string;
  status: string;
  packages_found: number;
  packages_added: number;
  packages_updated: number;
  updates_available: number;
  scanned_at: string;
  message?: string;
}

export interface PackageUpdateItem {
  id: number;
  package_id: number;
  package_name: string;
  system_id: number;
  installed_version: string;
  available_version: string;
  update_type: string;
  discovered_on: string;
}

export interface ApplyUpdatesResult {
  system_id: number;
  hostname: string;
  status: string;
  packages_updated: number;
  applied_at?: string;
  message?: string;
}

export interface PackageHistoryItem {
  id: number;
  package_id: number;
  package_name: string;
  system_id: number;
  operation: string;
  old_version: string | null;
  new_version: string | null;
  status: string;
  error_message: string | null;
  performed_at: string;
  performed_by: string | null;
}

export interface PackageHistoryResponse {
  total: number;
  limit: number;
  offset: number;
  history: PackageHistoryItem[];
}

export interface FleetSearchResult {
  package_id: number;
  name: string;
  installed_version: string;
  package_type: string;
  is_held: boolean;
  is_security_critical: boolean;
  system_id: number;
  hostname: string;
  available_version: string | null;
  update_type: string | null;
  has_update: boolean;
}

export interface FleetSearchResponse {
  total: number;
  limit: number;
  offset: number;
  results: FleetSearchResult[];
}

export interface BulkPackageResult {
  system_id: number;
  hostname: string;
  status: string;
  message?: string;
  packages_updated?: number;
  packages_skipped?: number;
  packages_held?: number;
  packages_unheld?: number;
}

export interface BulkUpdateResponse {
  total_systems: number;
  total_updated: number;
  total_skipped: number;
  total_errors: number;
  results: BulkPackageResult[];
}

export interface BulkHoldResponse {
  total_systems: number;
  total_held: number;
  total_errors: number;
  results: BulkPackageResult[];
}

export interface BulkUnholdResponse {
  total_systems: number;
  total_unheld: number;
  total_errors: number;
  results: BulkPackageResult[];
}

// API functions

export const fetchPackages = async (
  systemId: number,
  search?: string,
  limit = 100,
  offset = 0
): Promise<PackageListResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (search) params.set('search', search);

  const response = await apiFetch(`/api/backend/packages/${systemId}?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch packages'));
  }
  return response.json();
};

export const scanPackages = async (systemId: number): Promise<ScanResult> => {
  const response = await apiFetch(`/api/backend/packages/${systemId}/scan`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to scan packages'));
  }
  return response.json();
};

// Aggregate inventory row — a package plus the host it is installed on.
export interface ScopedPackageRow extends PackageItem {
  system_id: number;
  hostname: string;
}

export interface ScopedInventoryResponse {
  total: number;
  limit: number;
  offset: number;
  packages: ScopedPackageRow[];
}

/**
 * Installed-package inventory across a cohort (fleet / group / smart
 * group). Each row carries its hostname. `scope.type === 'system'` should use
 * {@link fetchPackages} instead; this endpoint is the multi-host aggregate.
 */
export const fetchScopedInventory = async (
  scope: PackageScope,
  search?: string,
  limit = 100,
  offset = 0
): Promise<ScopedInventoryResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (search) params.set('search', search);
  for (const [k, v] of Object.entries(scopeSearchParams(scope))) params.set(k, v);
  const response = await apiFetch(`/api/backend/packages/inventory?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to load package inventory'));
  }
  return response.json();
};

export const fetchAllUpdates = async (
  scope?: PackageScope
): Promise<PackageUpdateItem[]> => {
  const params = new URLSearchParams(scope ? scopeSearchParams(scope) : {});
  const qs = params.toString();
  const response = await apiFetch(
    `/api/backend/packages/updates/all${qs ? `?${qs}` : ''}`
  );
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch updates'));
  }
  return response.json();
};

export const fetchSystemUpdates = async (systemId: number): Promise<PackageUpdateItem[]> => {
  const response = await apiFetch(`/api/backend/packages/updates/${systemId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch updates'));
  }
  return response.json();
};

export const applyUpdates = async (
  systemId: number,
  packageNames?: string[]
): Promise<ApplyUpdatesResult> => {
  const response = await apiFetch(`/api/backend/packages/${systemId}/update`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(packageNames ? { package_names: packageNames } : {}),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to apply updates'));
  }
  return response.json();
};

export const fetchAllSecurityUpdates = async (
  scope?: PackageScope
): Promise<PackageUpdateItem[]> => {
  const params = new URLSearchParams(scope ? scopeSearchParams(scope) : {});
  const qs = params.toString();
  const response = await apiFetch(
    `/api/backend/packages/security/all${qs ? `?${qs}` : ''}`
  );
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch security updates'));
  }
  return response.json();
};

export const fetchSystemSecurityUpdates = async (
  systemId: number
): Promise<PackageUpdateItem[]> => {
  const response = await apiFetch(`/api/backend/packages/security/${systemId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch security updates'));
  }
  return response.json();
};

export const scanSecurityUpdates = async (systemId: number): Promise<ScanResult> => {
  const response = await apiFetch(`/api/backend/packages/${systemId}/scan-security`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to scan security updates'));
  }
  return response.json();
};

export const applySecurityUpdates = async (
  systemId: number
): Promise<ApplyUpdatesResult> => {
  const response = await apiFetch(`/api/backend/packages/${systemId}/update-security`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to apply security updates'));
  }
  return response.json();
};

export const holdPackages = async (
  systemId: number,
  packageNames: string[]
): Promise<{ system_id: number; hostname: string; status: string; packages_held: number }> => {
  const response = await apiFetch(`/api/backend/packages/${systemId}/hold`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package_names: packageNames }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to hold packages'));
  }
  return response.json();
};

export const unholdPackages = async (
  systemId: number,
  packageNames: string[]
): Promise<{ system_id: number; hostname: string; status: string; packages_unheld: number }> => {
  const response = await apiFetch(`/api/backend/packages/${systemId}/unhold`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package_names: packageNames }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to unhold packages'));
  }
  return response.json();
};

export const removePackages = async (
  systemId: number,
  packageNames: string[]
): Promise<{
  system_id: number;
  hostname: string;
  status: string;
  packages_removed: number;
  packages_skipped: number;
}> => {
  const response = await apiFetch(`/api/backend/packages/${systemId}/remove`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ package_names: packageNames }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to remove packages'));
  }
  return response.json();
};

export const fetchAllHistory = async (
  limit = 50,
  offset = 0,
  scope?: PackageScope
): Promise<PackageHistoryResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (scope) {
    for (const [k, v] of Object.entries(scopeSearchParams(scope))) params.set(k, v);
  }
  const response = await apiFetch(`/api/backend/packages/history/all?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch history'));
  }
  return response.json();
};

export const fetchSystemHistory = async (
  systemId: number,
  limit = 50,
  offset = 0
): Promise<PackageHistoryResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  const response = await apiFetch(`/api/backend/packages/history/${systemId}?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch history'));
  }
  return response.json();
};

export const searchFleetPackages = async (
  name: string,
  version?: string,
  isHeld?: boolean,
  hasUpdate?: boolean,
  limit = 50,
  offset = 0,
  scope?: PackageScope
): Promise<FleetSearchResponse> => {
  const params = new URLSearchParams({ name, limit: String(limit), offset: String(offset) });
  if (version) params.set('version', version);
  if (isHeld !== undefined) params.set('is_held', String(isHeld));
  if (hasUpdate !== undefined) params.set('has_update', String(hasUpdate));
  if (scope) {
    for (const [k, v] of Object.entries(scopeSearchParams(scope))) params.set(k, v);
  }

  const response = await apiFetch(`/api/backend/packages/search?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to search packages'));
  }
  return response.json();
};

export const bulkUpdatePackages = async (
  systemIds: number[],
  packageNames?: string[]
): Promise<BulkUpdateResponse> => {
  const response = await apiFetch('/api/backend/packages/bulk/update', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds, package_names: packageNames || null }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk update packages'));
  }
  return response.json();
};

export const bulkHoldPackages = async (
  systemIds: number[],
  packageNames: string[]
): Promise<BulkHoldResponse> => {
  const response = await apiFetch('/api/backend/packages/bulk/hold', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds, package_names: packageNames }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk hold packages'));
  }
  return response.json();
};

export const bulkUnholdPackages = async (
  systemIds: number[],
  packageNames: string[]
): Promise<BulkUnholdResponse> => {
  const response = await apiFetch('/api/backend/packages/bulk/unhold', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds, package_names: packageNames }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to unhold packages'));
  }
  return response.json();
};

// Cohort package/security refresh scan across a group/smart-group scope.
export interface CohortScanHostResult {
  system_id: number;
  hostname: string;
  status: string; // success | error | already_running
  message?: string | null;
}

export interface CohortScanResult {
  scope_type: string;
  scope_id: number | null;
  security: boolean;
  total: number;
  success_count: number;
  failure_count: number;
  skipped_count: number;
  results: CohortScanHostResult[];
  fleet_operation_id: number | null;
}

/**
 * Scan package (or security) inventory across a resolved cohort. The backend
 * resolves the scope and reports per-host scan status.
 */
export const scanScope = async (
  scope: PackageScope,
  opts?: { security?: boolean }
): Promise<CohortScanResult> => {
  const response = await apiFetch('/api/backend/packages/scope/scan', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      scope_type: scope.type,
      scope_id: scope.id,
      security: !!opts?.security,
    }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Cohort scan failed'));
  }
  return response.json();
};
