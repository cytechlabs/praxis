import { apiFetch, formatApiError } from '../utils/api';

interface VaultConfigData {
  is_internal: boolean;
  token: string;
  server_url: string | null;
}

interface VaultConfigResponse {
  id: number;
  is_internal: boolean;
  token: string;
  server_url: string | null;
  is_active: boolean;
  health_status: string | null;
  last_health_check: string | null;
  created_at: string;
  updated_at: string;
}

interface VaultHealthResponse {
  healthy: boolean;
  status: string;
  initialized?: boolean;
  sealed?: boolean;
  version?: string;
}

interface VaultKVStoresResponse {
  kv_stores: string[];
}

interface VaultSecretsResponse {
  secrets: string[];
  path: string;
}

interface SecretDataValue {
  string?: string;
  number?: number;
  boolean?: boolean;
}

interface SecretMetadata {
  created_time: string;
  current_version: number;
  versions: Record<string, { created_time: string }>;
}

interface VaultSecretDataResponse {
  data: Record<string, SecretDataValue | string | number | boolean>;
  metadata: SecretMetadata;
  path: string;
}

interface VaultSecretVersionsResponse {
  versions: number[];
  current_version: number;
  path: string;
}

interface VaultSecretVersionResponse {
  version: number;
  created_time: string;
  data: Record<string, SecretDataValue | string | number | boolean>;
}

export interface VaultSecretCreateRequest {
  path: string;
  data: Record<string, string>;
}

export interface VaultSecretPasswordUpdateRequest {
  path: string;
  username: string;
  new_password: string;
}

export const createVaultConfig = async (configData: VaultConfigData): Promise<VaultConfigResponse> => {
  const response = await apiFetch('/api/backend/vault/config', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(configData),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(formatApiError(data, 'Failed to create Vault configuration'));
  return data;
};

export const getActiveVaultConfig = async (): Promise<VaultConfigResponse | null> => {
  try {
    const response = await apiFetch('/api/backend/vault/config/active');
    if (response.status === 404) return null;
    if (!response.ok) {
      const error = await response.json();
      throw new Error(formatApiError(error, 'Failed to fetch active Vault configuration'));
    }
    return response.json();
  } catch (error) {
    if (error instanceof Error && error.message.includes('404')) return null;
    throw error;
  }
};

export const checkVaultHealth = async (): Promise<VaultHealthResponse> => {
  const response = await apiFetch('/api/backend/vault/health');
  const data = await response.json();
  if (!response.ok) {
    return { healthy: false, status: formatApiError(data, 'Health check failed') };
  }
  return data;
};

export const listKVStores = async (): Promise<string[]> => {
  const response = await apiFetch('/api/backend/vault/secrets/kv-stores');
  if (response.status === 503) {
    // Vault not configured — return empty instead of throwing
    return [];
  }
  if (response.status === 403) {
    throw new Error('Access denied: admin or maintainer role required');
  }
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to list KV stores'));
  }
  const data: VaultKVStoresResponse = await response.json();
  return data.kv_stores;
};

export const listSecrets = async (path: string): Promise<VaultSecretsResponse> => {
  const response = await apiFetch(`/api/backend/vault/secrets/secrets?path=${encodeURIComponent(path)}`);
  if (response.status === 503) {
    return { secrets: [], path };
  }
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to list secrets'));
  }
  return response.json();
};

export const getSecret = async (path: string): Promise<VaultSecretDataResponse> => {
  const response = await apiFetch(`/api/backend/vault/secrets/secret?path=${encodeURIComponent(path)}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to get secret'));
  }
  return response.json();
};

export const getSecretVersions = async (path: string): Promise<VaultSecretVersionsResponse> => {
  const response = await apiFetch(`/api/backend/vault/secrets/secret/versions?path=${encodeURIComponent(path)}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to get secret versions'));
  }
  return response.json();
};

export const getSecretVersion = async (path: string, version: number): Promise<VaultSecretVersionResponse> => {
  const response = await apiFetch(`/api/backend/vault/secrets/secret/version?path=${encodeURIComponent(path)}&version=${version}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to get secret version'));
  }
  return response.json();
};

export const createSecret = async (path: string, data: Record<string, string>): Promise<{ success: boolean }> => {
  const response = await apiFetch('/api/backend/vault/secrets/secret', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, data }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to create secret'));
  }
  return response.json();
};

export const updateSecretPassword = async (path: string, username: string, new_password: string): Promise<{ success: boolean }> => {
  const response = await apiFetch('/api/backend/vault/secrets/secret/password', {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path, username, new_password }),
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to update password'));
  }
  return response.json();
};

export const deleteSecret = async (path: string): Promise<{ success: boolean }> => {
  const response = await apiFetch(`/api/backend/vault/secrets/secret?path=${encodeURIComponent(path)}`, {
    method: 'DELETE',
  });

  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to delete secret'));
  }
  return response.json();
};
