import { apiFetch, formatApiError } from '../utils/api';

interface ConnectionTestResult {
  system_id: number;
  hostname: string;
  ip_address: string;
  status: 'success' | 'warning' | 'failed' | 'error';
  message: string;
  response_time_ms: number;
  tested_at: string;
}

interface CommandExecutionResult {
  system_id: number;
  hostname: string;
  command: string;
  status: 'success' | 'warning' | 'failed' | 'error';
  stdout: string;
  stderr: string;
  exit_code: number | null;
  execution_time_ms: number;
  executed_at: string;
}

export const testConnection = async (systemId: number): Promise<ConnectionTestResult> => {
  const response = await apiFetch(`/api/backend/ssh/test/${systemId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to test connection'));
  }
  return response.json();
};

export const testAllConnections = async (): Promise<ConnectionTestResult[]> => {
  const response = await apiFetch('/api/backend/ssh/test-all');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to test connections'));
  }
  return response.json();
};

export const executeCommand = async (
  systemId: number,
  command: string,
  timeout?: number
): Promise<CommandExecutionResult> => {
  const url = new URL(`/api/backend/ssh/execute/${systemId}`, window.location.origin);
  url.searchParams.append('command', command);
  if (timeout !== undefined) {
    url.searchParams.append('timeout', timeout.toString());
  }

  const response = await apiFetch(url.toString(), { method: 'POST' });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to execute command'));
  }
  return response.json();
};

export const closeConnection = async (systemId: number): Promise<{ success: boolean }> => {
  const response = await apiFetch(`/api/backend/ssh/close/${systemId}`, { method: 'DELETE' });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to close connection'));
  }
  return response.json();
};

export const closeAllConnections = async (): Promise<{ closed_count: number }> => {
  const response = await apiFetch('/api/backend/ssh/close-all', { method: 'DELETE' });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to close connections'));
  }
  return response.json();
};
