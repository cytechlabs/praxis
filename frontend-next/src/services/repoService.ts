import { apiFetch, formatApiError } from '../utils/api';

export interface RepoItem {
  id: number;
  name: string;
  url: string;
  repo_type: string;
  enabled: boolean;
  file_path: string | null;
  components: string | null;
  distribution: string | null;
}

export interface DetectedRepo {
  type?: string;
  url?: string;
  distribution?: string;
  components?: string;
  name?: string;
  enabled?: boolean;
  section?: string;
  gpg_key_url?: string;
}

export interface RepoListResponse {
  system_id: number;
  hostname: string;
  package_manager: string;
  repos: RepoItem[];
  detected_repos: DetectedRepo[];
}

export interface AddRepoData {
  name: string;
  url: string;
  components?: string;
  distribution?: string;
  gpg_key_url?: string;
}

export interface RepoTemplate {
  name: string;
  url: string;
  components?: string;
  description: string;
}

export interface SyncResult {
  system_id: number;
  hostname: string;
  status: string;
  message: string;
  error: string | null;
  synced_at: string;
}

export const fetchRepos = async (systemId: number): Promise<RepoListResponse> => {
  const response = await apiFetch(`/api/backend/repos/${systemId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch repos'));
  }
  return response.json();
};

export const addRepo = async (systemId: number, data: AddRepoData): Promise<RepoItem> => {
  const response = await apiFetch(`/api/backend/repos/${systemId}`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to add repo'));
  }
  return response.json();
};

export const removeRepo = async (systemId: number, repoId: number): Promise<void> => {
  const response = await apiFetch(`/api/backend/repos/${systemId}/${repoId}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to remove repo'));
  }
};

export const syncRepos = async (systemId: number): Promise<SyncResult> => {
  const response = await apiFetch(`/api/backend/repos/${systemId}/sync`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to sync repos'));
  }
  return response.json();
};

export const fetchTemplates = async (
  systemId?: number
): Promise<{ distro?: string; templates: RepoTemplate[] | Record<string, RepoTemplate[]> }> => {
  const url = systemId
    ? `/api/backend/repos/templates/${systemId}`
    : '/api/backend/repos/templates/all';
  const response = await apiFetch(url);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch templates'));
  }
  return response.json();
};
