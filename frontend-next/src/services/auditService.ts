import { apiFetch } from '../utils/api';

export interface AuditEvent {
  schema_version: number;
  event_uuid: string;
  timestamp: string | null;
  action: string;
  outcome: 'success' | 'failure' | 'denied';
  actor: { user_id: number | null; username: string | null; ip: string | null };
  target: { kind: string | null; system_id: number | null; id: string | null };
  context: Record<string, unknown>;
}

export interface AuditSink {
  id: number;
  name: string;
  kind: 'syslog' | 'http' | 'file';
  target: string;
  hmac_secret_set: boolean;
  hmac_secret?: string | null;
  config: Record<string, unknown>;
  enabled: boolean;
  created_at: string | null;
}

export interface NewAuditSink {
  name: string;
  kind: 'syslog' | 'http' | 'file';
  target: string;
  hmac_secret?: string | null;
  config?: Record<string, unknown>;
  enabled?: boolean;
}

export interface AuditDelivery {
  id: number;
  event_id: number;
  status: 'pending' | 'delivered' | 'failed' | 'dead_letter';
  attempts: number;
  last_error: string | null;
  next_attempt_at: string | null;
  delivered_at: string | null;
}

export interface EventListParams {
  action?: string;
  actor_user_id?: number;
  system_id?: number;
  outcome?: string;
  since?: string;
  until?: string;
  limit?: number;
  offset?: number;
}

export const listAuditEvents = async (
  params?: EventListParams,
): Promise<{ total: number; events: AuditEvent[] & { id?: number }[] }> => {
  const qs = new URLSearchParams();
  if (params) {
    Object.entries(params).forEach(([k, v]) => {
      if (v !== undefined && v !== null && v !== '') qs.set(k, String(v));
    });
  }
  const res = await apiFetch(`/api/backend/audit/events${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error((await res.json()).detail || 'fetch events failed');
  const body = await res.json();
  return { total: body.total, events: body.events };
};

export const listAuditSinks = async (): Promise<AuditSink[]> => {
  const res = await apiFetch('/api/backend/audit/sinks');
  if (!res.ok) throw new Error('fetch sinks failed');
  return (await res.json()).sinks;
};

export const createAuditSink = async (payload: NewAuditSink): Promise<AuditSink> => {
  const res = await apiFetch('/api/backend/audit/sinks', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'create sink failed');
  return (await res.json()).sink;
};

export const updateAuditSink = async (id: number, payload: Partial<NewAuditSink>): Promise<AuditSink> => {
  const res = await apiFetch(`/api/backend/audit/sinks/${id}`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(payload),
  });
  if (!res.ok) throw new Error((await res.json()).detail || 'update sink failed');
  return (await res.json()).sink;
};

export const deleteAuditSink = async (id: number): Promise<void> => {
  const res = await apiFetch(`/api/backend/audit/sinks/${id}`, { method: 'DELETE' });
  if (!res.ok) throw new Error((await res.json()).detail || 'delete sink failed');
};

export const listSinkDeliveries = async (
  sinkId: number,
  status?: string,
): Promise<AuditDelivery[]> => {
  const qs = new URLSearchParams();
  if (status) qs.set('status', status);
  const res = await apiFetch(`/api/backend/audit/sinks/${sinkId}/deliveries${qs.toString() ? `?${qs}` : ''}`);
  if (!res.ok) throw new Error('fetch deliveries failed');
  return (await res.json()).deliveries;
};

export const retryDelivery = async (deliveryId: number): Promise<void> => {
  const res = await apiFetch(`/api/backend/audit/deliveries/${deliveryId}/retry`, { method: 'POST' });
  if (!res.ok) throw new Error((await res.json()).detail || 'retry failed');
};
