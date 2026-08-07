import { apiFetch, formatApiError } from '../utils/api';

export interface BulkResult {
  system_id: number;
  hostname: string;
  status: string;
  message?: string;
}

export interface BulkImportSystem {
  hostname: string;
  ip_address: string;
  distro?: string;
  distro_id?: number;
  status?: string;
  group?: string;
  group_id?: number;
  credential?: string;
  credentials_id?: number;
  environment?: string;
  tags?: string[];
  tag_ids?: number[];
}

export interface BulkImportResult {
  hostname: string;
  status: string;
  message: string;
}

export const bulkUpdateStatus = async (
  systemIds: number[],
  status: string
): Promise<{ total: number; updated: number; errors: number; results: BulkResult[] }> => {
  const response = await apiFetch('/api/backend/bulk/status', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds, status }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk update status'));
  }
  return response.json();
};

export const bulkUpdateGroup = async (
  systemIds: number[],
  groupId: number
): Promise<{ total: number; updated: number }> => {
  const response = await apiFetch('/api/backend/bulk/group', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds, group_id: groupId }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk update group'));
  }
  return response.json();
};

export const bulkDeleteSystems = async (
  systemIds: number[]
): Promise<{ total: number; deleted: number }> => {
  const response = await apiFetch('/api/backend/bulk/systems', {
    method: 'DELETE',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk delete systems'));
  }
  return response.json();
};

export const bulkAssignCredential = async (
  systemIds: number[],
  credentialId: number
): Promise<{ total: number; updated: number; errors: number; results: BulkResult[] }> => {
  const response = await apiFetch('/api/backend/bulk/credentials', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds, credential_id: credentialId }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk assign credential'));
  }
  return response.json();
};

export const bulkImport = async (
  systems: BulkImportSystem[],
  dryRun: boolean = false
): Promise<{ total: number; results: BulkImportResult[] }> => {
  const response = await apiFetch('/api/backend/bulk/import', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ systems, dry_run: dryRun }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to bulk import systems'));
  }
  return response.json();
};

export const fetchImportTemplate = async (): Promise<object> => {
  const response = await apiFetch('/api/backend/bulk/import/template');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch import template'));
  }
  return response.json();
};
