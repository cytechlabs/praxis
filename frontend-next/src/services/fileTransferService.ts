import { apiFetch } from '../utils/api';

export interface DirEntry {
  name: string;
  size: number;
  mtime: number;
  mode: number;
  is_dir: boolean;
  is_link: boolean;
}

export interface TransferAudit {
  id: number;
  user_id: number | null;
  system_id: number | null;
  login: string;
  direction: 'upload' | 'download' | 'mkdir' | 'unlink';
  remote_path: string;
  local_filename: string | null;
  size_bytes: number;
  sha256: string | null;
  status: 'in_progress' | 'success' | 'error';
  error_message: string | null;
  client_ip: string | null;
  started_at: string;
  ended_at: string | null;
}

export const listDir = async (systemId: number, path: string): Promise<{ path: string; entries: DirEntry[] }> => {
  const qs = new URLSearchParams({ path });
  const res = await apiFetch(`/api/backend/transfer/${systemId}/listdir?${qs}`);
  if (!res.ok) throw new Error((await res.json()).detail || 'listdir failed');
  const body = await res.json();
  return { path: body.path, entries: body.entries };
};

export const statPath = async (systemId: number, path: string) => {
  const qs = new URLSearchParams({ path });
  const res = await apiFetch(`/api/backend/transfer/${systemId}/stat?${qs}`);
  if (!res.ok) throw new Error((await res.json()).detail || 'stat failed');
  return res.json();
};

export const downloadUrl = (systemId: number, path: string): string => {
  const qs = new URLSearchParams({ path });
  return `/api/backend/transfer/${systemId}/download?${qs}`;
};

export const uploadFile = async (systemId: number, remotePath: string, file: File): Promise<void> => {
  const qs = new URLSearchParams({ path: remotePath });
  const form = new FormData();
  form.append('file', file);
  const res = await apiFetch(`/api/backend/transfer/${systemId}/upload?${qs}`, {
    method: 'POST',
    body: form,
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'upload failed');
};

export const mkdirPath = async (systemId: number, path: string): Promise<void> => {
  const res = await apiFetch(`/api/backend/transfer/${systemId}/mkdir`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ path }),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'mkdir failed');
};

export const unlinkPath = async (systemId: number, path: string): Promise<void> => {
  const qs = new URLSearchParams({ path });
  const res = await apiFetch(`/api/backend/transfer/${systemId}/unlink?${qs}`, { method: 'DELETE' });
  if (!res.ok) throw new Error((await res.json()).detail || 'delete failed');
};

export const listAudits = async (systemId?: number): Promise<TransferAudit[]> => {
  const qs = new URLSearchParams();
  if (systemId !== undefined) qs.set('system_id', String(systemId));
  const res = await apiFetch(`/api/backend/transfer/audits${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to fetch audits');
  return (await res.json()).audits;
};
