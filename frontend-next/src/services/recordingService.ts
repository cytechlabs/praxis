import { apiFetch } from '../utils/api';

export interface Recording {
  id: number;
  session_id: number;
  user_id: number | null;
  system_id: number | null;
  size_bytes: number;
  frame_count: number;
  started_at: string;
  ended_at: string | null;
  retention_expires_at: string;
  status: 'active' | 'finalized' | 'pruned' | 'errored';
  hostname?: string | null;
  login?: string | null;
}

export const listRecordings = async (params?: {
  mine_only?: boolean;
  system_id?: number;
  status?: string;
}): Promise<Recording[]> => {
  const qs = new URLSearchParams();
  if (params?.mine_only === false) qs.set('mine_only', 'false');
  if (params?.system_id !== undefined) qs.set('system_id', String(params.system_id));
  if (params?.status) qs.set('status', params.status);
  const res = await apiFetch(`/api/backend/recordings${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('Failed to fetch recordings');
  return (await res.json()).recordings;
};

export const getRecording = async (id: number): Promise<Recording> => {
  const res = await apiFetch(`/api/backend/recordings/${id}`);
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to fetch recording');
  return (await res.json()).recording;
};

export const castUrl = (id: number): string => `/api/backend/recordings/${id}/cast`;

export const deleteRecording = async (id: number): Promise<void> => {
  const res = await apiFetch(`/api/backend/recordings/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error((await res.json()).detail || 'Failed to delete');
};

/** Asciinema v2 frame: [elapsed_seconds, channel, data]. */
export type CastFrame = [number, string, string];

export interface CastHeader {
  version: number;
  width: number;
  height: number;
  timestamp?: number;
  env?: Record<string, string>;
}

export interface ParsedCast {
  header: CastHeader;
  frames: CastFrame[];
  duration: number;
}

export const fetchCast = async (id: number): Promise<ParsedCast> => {
  const res = await apiFetch(castUrl(id));
  if (!res.ok) throw new Error((await res.json().catch(() => ({}))).detail || 'Failed to fetch cast');
  const text = await res.text();
  const lines = text.split('\n').filter(Boolean);
  if (!lines.length) throw new Error('empty cast');
  const header = JSON.parse(lines[0]) as CastHeader;
  const frames: CastFrame[] = [];
  for (let i = 1; i < lines.length; i++) {
    try {
      const f = JSON.parse(lines[i]);
      if (Array.isArray(f) && f.length >= 3) frames.push(f as CastFrame);
    } catch {
      /* ignore malformed */
    }
  }
  const duration = frames.length ? frames[frames.length - 1][0] : 0;
  return { header, frames, duration };
};
