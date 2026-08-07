import { apiFetch, formatApiError } from '../utils/api';

// Types

export interface PackageFilter {
  names?: string[];
  keywords?: string[];
  security_only?: boolean;
}

export interface Job {
  id: number;
  name: string;
  description: string | null;
  job_type: string;
  schedule: string | null;
  is_recurring: boolean;
  status: string;
  target_type: string;
  target_ids: number[] | null;
  package_filter: PackageFilter | null;
  last_run: string | null;
  next_run: string | null;
  created_at: string;
  tag_match_logic?: string;
  max_parallel?: number;
  created_by: number;
  updated_at: string;
  depends_on_job_id?: number | null;
  chain_condition?: string;
  dependency_name?: string | null;
}

export interface JobCreate {
  name: string;
  description?: string;
  job_type: string;
  schedule?: string;
  is_recurring: boolean;
  target_type: string;
  target_ids?: number[];
  package_filter?: PackageFilter;
  tag_match_logic?: string;
  max_parallel?: number;
  depends_on_job_id?: number | null;
  chain_condition?: string;
}

export interface JobUpdate {
  name?: string;
  description?: string;
  job_type?: string;
  schedule?: string;
  is_recurring?: boolean;
  target_type?: string;
  target_ids?: number[];
  package_filter?: PackageFilter;
  tag_match_logic?: string;
  status?: string;
  max_parallel?: number;
  depends_on_job_id?: number | null;
  chain_condition?: string;
}

export interface JobChainNode {
  id: number;
  name: string;
  status: string;
  chain_condition: string;
  depends_on_job_id: number | null;
  children: JobChainNode[];
}

export interface DryRunPackagePreview {
  name: string;
  from_version: string;
  to_version: string;
  type: string;
}

export interface DryRunSystemPreview {
  system_id: number;
  hostname: string;
  action: string;
  packages_affected: DryRunPackagePreview[];
  installed_packages?: number;
}

export interface DryRunResponse {
  status: string;
  dry_run: boolean;
  job_id: number;
  job_name: string;
  job_type: string;
  systems_targeted: number;
  total_packages_affected: number;
  preview: DryRunSystemPreview[];
}

export interface RollbackResult {
  system_id: number;
  hostname: string;
  result: {
    status: string;
    message?: string;
    packages_rolled_back?: number;
  };
}

export interface RollbackResponse {
  status: string;
  history_id: number;
  job_id: number;
  total_systems: number;
  total_rolled_back: number;
  total_failed: number;
  results: RollbackResult[];
}

/**
 * Outcome of one job run on one system. `status` is always present; the
 * remaining fields depend on the job type (package counts for scans, applied
 * counts for updates, a message for skips and errors).
 */
export interface JobExecutionResult {
  status: string;
  message?: string;
  [field: string]: unknown;
}

/** One entry of a job run's per-system results. */
export interface JobResultEntry {
  system_id: number;
  hostname: string;
  result: JobExecutionResult;
}

export interface JobHistoryItem {
  id: number;
  job_id: number;
  job_name: string;
  job_type: string;
  start_time: string;
  end_time: string | null;
  status: string;
  /** Decoded server-side: an array of per-system entries, or null for a run
   *  that never recorded results (still in flight, or abandoned before the
   *  results were written). */
  result: JobResultEntry[] | null;
  error_message: string | null;
  systems_targeted: number;
  systems_completed: number;
  systems_failed: number;
  created_at: string;
}

export interface JobListResponse {
  total: number;
  limit: number;
  offset: number;
  jobs: Job[];
}

export interface JobHistoryResponse {
  total: number;
  limit: number;
  offset: number;
  history: JobHistoryItem[];
}

export interface JobRunResult {
  status: string;
  job_id: number;
  history_id: number;
  message: string;
}

// API functions

export const fetchJobs = async (
  status?: string,
  jobType?: string,
  limit = 100,
  offset = 0
): Promise<JobListResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  if (status) params.set('status', status);
  if (jobType) params.set('job_type', jobType);

  const response = await apiFetch(`/api/backend/jobs?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch jobs'));
  }
  return response.json();
};

export const createJob = async (data: JobCreate): Promise<Job> => {
  const response = await apiFetch('/api/backend/jobs', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to create job'));
  }
  return response.json();
};

export const fetchJob = async (jobId: number): Promise<Job> => {
  const response = await apiFetch(`/api/backend/jobs/${jobId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch job'));
  }
  return response.json();
};

export const updateJob = async (jobId: number, data: JobUpdate): Promise<Job> => {
  const response = await apiFetch(`/api/backend/jobs/${jobId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(data),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to update job'));
  }
  return response.json();
};

export const deleteJob = async (jobId: number): Promise<void> => {
  const response = await apiFetch(`/api/backend/jobs/${jobId}`, {
    method: 'DELETE',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to delete job'));
  }
};

export const fetchActiveJobs = async (): Promise<Job[]> => {
  const response = await apiFetch('/api/backend/jobs/active');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch active jobs'));
  }
  return response.json();
};

export const fetchFailedJobs = async (
  limit = 100,
  offset = 0
): Promise<JobHistoryResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  const response = await apiFetch(`/api/backend/jobs/failed?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch failed jobs'));
  }
  return response.json();
};

export const runJob = async (jobId: number): Promise<JobRunResult> => {
  const response = await apiFetch(`/api/backend/jobs/${jobId}/run`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to run job'));
  }
  return response.json();
};

export const cancelJob = async (
  jobId: number
): Promise<{ status: string; message: string }> => {
  const response = await apiFetch(`/api/backend/jobs/${jobId}/cancel`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to cancel job'));
  }
  return response.json();
};

export const fetchJobHistory = async (
  jobId: number,
  limit = 50,
  offset = 0
): Promise<JobHistoryResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  const response = await apiFetch(`/api/backend/jobs/${jobId}/history?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch job history'));
  }
  return response.json();
};

export const dryRunJob = async (jobId: number): Promise<DryRunResponse> => {
  const response = await apiFetch(`/api/backend/jobs/${jobId}/dry-run`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to dry-run job'));
  }
  return response.json();
};

export const rollbackJobHistory = async (historyId: number): Promise<RollbackResponse> => {
  const response = await apiFetch(`/api/backend/jobs/history/${historyId}/rollback`, {
    method: 'POST',
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to rollback job'));
  }
  return response.json();
};

export const fetchJobChains = async (): Promise<JobChainNode[]> => {
  const response = await apiFetch('/api/backend/jobs/chains');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch job chains'));
  }
  return response.json();
};

export const fetchAllJobHistory = async (
  limit = 50,
  offset = 0
): Promise<JobHistoryResponse> => {
  const params = new URLSearchParams({ limit: String(limit), offset: String(offset) });
  const response = await apiFetch(`/api/backend/jobs/history?${params}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch job history'));
  }
  return response.json();
};
