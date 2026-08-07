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
