import { apiFetch, formatApiError } from '../utils/api';

export async function changePassword(currentPassword: string, newPassword: string) {
  const response = await apiFetch('/api/backend/auth/change-password', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({
      current_password: currentPassword,
      new_password: newPassword,
    }),
  });

  if (!response.ok) {
    const data = await response.json();
    throw new Error(formatApiError(data, 'Failed to change password'));
  }

  return await response.json();
}
