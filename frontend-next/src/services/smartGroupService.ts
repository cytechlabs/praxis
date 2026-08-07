/**
 * PRA-312 Slice 3: minimal smart-group list client.
 *
 * The smart-groups builder page has its own bespoke fetch; there was no shared
 * service. This exposes just the list read needed to populate a smart-group picker
 * (e.g. content-profile subscription assignment). Backend: GET /smart-groups.
 */
import { apiFetch, formatApiError } from '../utils/api';

export interface SmartGroupListItem {
  id: number;
  name: string;
  description: string | null;
  enabled: boolean;
  member_count: number;
}

export async function listSmartGroups(): Promise<SmartGroupListItem[]> {
  const res = await apiFetch('/api/backend/smart-groups');
  if (!res.ok) {
    let body: unknown = null;
    try {
      body = await res.json();
    } catch {
      /* swallow */
    }
    throw new Error(formatApiError(body, 'Failed to load smart groups'));
  }
  const data = await res.json();
  return (data?.smart_groups ?? []) as SmartGroupListItem[];
}
