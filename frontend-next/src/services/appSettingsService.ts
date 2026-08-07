import { apiFetch, formatApiError } from '../utils/api';

export interface AppSetting {
  setting_key: string;
  setting_value: string;
}

export const fetchAppSettings = async (): Promise<AppSetting[]> => {
  const response = await apiFetch('/api/backend/app-settings');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch app settings'));
  }
  return response.json();
};

export const updateAppSettings = async (
  settings: Record<string, string>
): Promise<AppSetting[]> => {
  const response = await apiFetch('/api/backend/app-settings', {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ settings }),
  });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to update settings'));
  }
  return response.json();
};
