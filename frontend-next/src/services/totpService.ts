import { apiFetch } from '../utils/api';

export interface TotpStatus {
  enrolled: boolean;
  enrolled_at: string | null;
  recovery_codes_remaining: number;
}

export const getTotpStatus = async (): Promise<TotpStatus> => {
  const res = await apiFetch('/api/backend/totp/status');
  if (!res.ok) throw new Error('Failed to fetch TOTP status');
  return res.json();
};

export const beginEnrollment = async (): Promise<{ secret: string; uri: string }> => {
  const res = await apiFetch('/api/backend/totp/enroll-begin', { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to begin enrollment');
  return res.json();
};

export const verifyEnrollment = async (code: string): Promise<{ recovery_codes: string[] }> => {
  const res = await apiFetch('/api/backend/totp/enroll-verify', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Verification failed');
  return res.json();
};

export const stepUp = async (code: string): Promise<void> => {
  const res = await apiFetch('/api/backend/totp/step-up', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Step-up failed');
};

export const disableTotp = async (code: string): Promise<void> => {
  const res = await apiFetch('/api/backend/totp/disable', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Disable failed');
};

export const regenerateRecoveryCodes = async (code: string): Promise<{ recovery_codes: string[] }> => {
  const res = await apiFetch('/api/backend/totp/recovery-codes/regenerate', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ code }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'Rotation failed');
  return res.json();
};
