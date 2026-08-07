import { apiFetch, formatApiError } from '../utils/api';

export interface FleetHealth {
  total_systems: number;
  unreachable: number;
  never_checked: number;
  stale: number;
  connection_counts: Record<string, number>;
  checked_at: string;
}

export interface SystemHealthCheckResult {
  system_id: number;
  hostname: string;
  status: string;
  connection_status: string;
  consecutive_failures: number;
  response_time_ms: number;
  message: string;
  checked_at: string;
}

export interface BulkCheckResult {
  total: number;
  ok: number;
  failed: number;
  results: SystemHealthCheckResult[];
  // PRA-323: present when a fleet sweep was already running (single-flight).
  status?: string;
  message?: string;
}

export interface DashboardActiveJob {
  job_id: number;
  name: string;
  job_type: string;
  systems_targeted: number;
  systems_completed: number;
  systems_failed: number;
  progress_pct: number;
  started_at: string | null;
}

export interface DashboardRecentJob {
  history_id: number;
  job_id: number;
  job_name: string;
  status: string;
  systems_completed: number;
  systems_failed: number;
  started_at: string | null;
  ended_at: string | null;
}

export interface DashboardAttention {
  system_id: number;
  hostname: string;
  reason: string;
  detail: string;
}

export interface GroupedAttention {
  system_id: number;
  hostname: string;
  reasons: { reason: string; detail: string }[];
}

/**
 * Collapse the per-(system, reason) attention rows into one row per host so a
 * system with multiple attention reasons no longer appears multiple times.
 * First-seen host order is preserved, and exact reason/detail repeats are
 * de-duplicated.
 */
export function groupAttentionByHost(attention: DashboardAttention[]): GroupedAttention[] {
  const order: number[] = [];
  const byId = new Map<number, GroupedAttention>();
  for (const a of attention) {
    let group = byId.get(a.system_id);
    if (!group) {
      group = { system_id: a.system_id, hostname: a.hostname, reasons: [] };
      byId.set(a.system_id, group);
      order.push(a.system_id);
    }
    if (!group.reasons.some((r) => r.reason === a.reason && r.detail === a.detail)) {
      group.reasons.push({ reason: a.reason, detail: a.detail });
    }
  }
  return order.map((id) => byId.get(id)!);
}

export interface FleetDashboard {
  status_counts: Record<string, number>;
  systems_by_group: { group: string; count: number }[];
  systems_by_distro: { distro: string; count: number }[];
  patch_compliance: {
    total: number;
    up_to_date: number;
    // Systems-affected counts (distinct systems with pending updates).
    with_updates: number;
    with_security_updates: number;
    // PRA-277: total pending package-update ROWS across all systems.
    pending_package_updates: number;
    pending_security_updates: number;
  };
  active_jobs: DashboardActiveJob[];
  recent_jobs: DashboardRecentJob[];
  attention: DashboardAttention[];
  health: FleetHealth;
  generated_at: string;
}

export const fetchFleetHealth = async (): Promise<FleetHealth> => {
  const response = await apiFetch('/api/backend/fleet/health');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch fleet health'));
  }
  return response.json();
};

export const fetchFleetDashboard = async (): Promise<FleetDashboard> => {
  const response = await apiFetch('/api/backend/fleet/dashboard');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch fleet dashboard'));
  }
  return response.json();
};

export const checkSystemHealth = async (
  systemId: number
): Promise<SystemHealthCheckResult> => {
  const response = await apiFetch(`/api/backend/fleet/check/${systemId}`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Health check failed'));
  }
  return response.json();
};

export const bulkCheckSystems = async (
  systemIds: number[]
): Promise<BulkCheckResult> => {
  const response = await apiFetch('/api/backend/fleet/bulk/check', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Bulk health check failed'));
  }
  return response.json();
};

export const checkAllSystems = async (): Promise<BulkCheckResult> => {
  const response = await apiFetch('/api/backend/fleet/check-all', {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Check-all failed'));
  }
  return response.json();
};
