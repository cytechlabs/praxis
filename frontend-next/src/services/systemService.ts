import { apiFetch, formatApiError } from '../utils/api';
import { sortByHostname } from '../utils/naturalSort';

interface SystemData {
  hostname: string;
  ip_address: string;
  distro_id: number;
  status: string;
  group_id: number;
  credentials_id: number;
  update_policy?: string;
  description?: string;
  environment?: string;
  tags?: string[];
}

interface RegistrationResponse {
  id: number;
  hostname: string;
  ip_address: string;
  status: string;
  registered_at: string;
  message: string;
}

export const registerSystem = async (systemData: SystemData): Promise<RegistrationResponse> => {
  const response = await apiFetch('/api/backend/systems/add-system', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(systemData),
  });

  const data = await response.json();
  if (!response.ok) {
    const error = new Error(formatApiError(data, 'Failed to register system')) as Error & { details?: string[] };
    if (data.details) error.details = data.details;
    throw error;
  }
  return data;
};

interface GroupData {
  name: string;
  description?: string;
  parent_id?: number;
}

export interface GroupResponse {
  id: number;
  name: string;
  description?: string;
  parent_id?: number;
  created_at: string;
  updated_at: string;
}

interface GroupDetailResponse extends GroupResponse {
  parent?: GroupResponse;
  children: GroupResponse[];
  system_count: number;
}

export const fetchGroups = async (): Promise<GroupResponse[]> => {
  const response = await apiFetch('/api/backend/groups');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch groups'));
  }
  return response.json();
};

export const fetchGroupDetails = async (groupId: number): Promise<GroupDetailResponse> => {
  const response = await apiFetch(`/api/backend/groups/${groupId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch group details'));
  }
  return response.json();
};

export const createGroup = async (groupData: GroupData): Promise<GroupResponse> => {
  const response = await apiFetch('/api/backend/groups', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(groupData),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(formatApiError(data, 'Failed to create group'));
  return data;
};

export const updateGroup = async (groupId: number, groupData: GroupData): Promise<GroupResponse> => {
  const response = await apiFetch(`/api/backend/groups/${groupId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(groupData),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(formatApiError(data, 'Failed to update group'));
  return data;
};

export const deleteGroup = async (groupId: number): Promise<void> => {
  const response = await apiFetch(`/api/backend/groups/${groupId}`, { method: 'DELETE' });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to delete group'));
  }
};

export const assignSystemsToGroup = async (groupId: number, systemIds: number[]): Promise<{success: boolean; message: string}> => {
  const response = await apiFetch(`/api/backend/groups/${groupId}/systems`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ system_ids: systemIds }),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(formatApiError(data, 'Failed to assign systems to group'));
  return data;
};

export const fetchGroupSystems = async (groupId: number): Promise<SystemListItem[]> => {
  const response = await apiFetch(`/api/backend/groups/${groupId}/systems`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch systems in group'));
  }
  return response.json();
};

export const fetchDistros = async () => {
  const response = await apiFetch('/api/backend/systems/distros');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch distributions'));
  }
  return response.json();
};

// Credential Management — secrets stored in Vault, DB has metadata only
interface CredentialData {
  name: string;
  auth_method: string;
  username?: string;
  sudo_method?: string;
  // Secrets — sent to backend, stored in Vault (not in DB)
  password?: string;
  ssh_key?: string;
  sudo_password?: string;
  vault_path?: string;
}

interface CredentialResponse {
  id: number;
  name: string;
  auth_method: string;
  username?: string;
  vault_path?: string;
  sudo_method?: string;
  systems?: SystemListItem[];
  created_at: string;
  updated_at: string;
}

export const revealCredentialSecret = async (credentialId: number): Promise<{ credential_id: number; data: Record<string, string> }> => {
  const response = await apiFetch(`/api/backend/credentials/${credentialId}/secret`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to reveal credential secret'));
  }
  return response.json();
};

export const fetchCredentials = async (): Promise<CredentialResponse[]> => {
  const response = await apiFetch('/api/backend/credentials');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch credentials'));
  }
  return response.json();
};

export const fetchCredentialDetails = async (credentialId: number): Promise<CredentialResponse> => {
  const response = await apiFetch(`/api/backend/credentials/${credentialId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch credential details'));
  }
  return response.json();
};

export const createCredential = async (credentialData: CredentialData): Promise<CredentialResponse> => {
  const response = await apiFetch('/api/backend/credentials', {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentialData),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(formatApiError(data, 'Failed to create credential'));
  return data;
};

export const updateCredential = async (credentialId: number, credentialData: CredentialData): Promise<CredentialResponse> => {
  const response = await apiFetch(`/api/backend/credentials/${credentialId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(credentialData),
  });

  const data = await response.json();
  if (!response.ok) throw new Error(formatApiError(data, 'Failed to update credential'));
  return data;
};

export const deleteCredential = async (credentialId: number): Promise<void> => {
  const response = await apiFetch(`/api/backend/credentials/${credentialId}`, { method: 'DELETE' });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to delete credential'));
  }
};

export const fetchSystemCredentials = async () => {
  const response = await apiFetch('/api/backend/systems/credentials');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch credentials'));
  }
  return response.json();
};

export interface SystemListItem {
  id: number;
  hostname: string;
  ip_address: string;
  status: string;
  os_version: string;
  registered_at: string;
  environment_type?: string;
  group_id: number;
  group_name: string;
  distro_name: string;
  ca_trust_deployed?: boolean;
  transport_preference?: TransportPreference;
  // PRA-348: last successful package scan time (durable "Last checked" source).
  last_audited?: string | null;
  tags?: { id: number; name: string; color: string }[];
}

// PRA-153 #4: per-host routing intent + agent-tunnel snapshot.
export type TransportPreference = 'auto' | 'ssh' | 'agent';

// Vocabulary returned by the backend's _compute_badge — see
// backend/app/api/routes/systems.py for the matrix.
export type BadgeState =
  | 'agent_connected'
  | 'agent_forced'
  | 'agent_unavailable'
  | 'ssh_forced'
  | 'ssh_fallback'
  | 'unknown';

export interface AgentHealth {
  state: 'healthy' | 'stale' | 'unregistered' | 'unknown';
  tunnel_session_id: string | null;
  since_seconds: number | null;
  last_heartbeat_age_seconds: number | null;
}

export interface SystemAgentHealth {
  system_id: number;
  transport_preference: TransportPreference;
  agent_health: AgentHealth;
  effective_transport: 'agent' | 'ssh' | null;
  badge_state: BadgeState;
}

export const fetchAllSystems = async (): Promise<SystemListItem[]> => {
  const response = await apiFetch('/api/backend/systems/all');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch systems'));
  }
  // PRA-352: return systems in natural hostname order so every selector/list that
  // consumes this shared path is deterministically sorted (praxis-tserver01 before
  // praxis-tserver02) instead of backend/insertion order.
  return sortByHostname(await response.json());
};

export interface SystemDetails {
  id: number;
  hostname: string;
  ip_address: string;
  status: string;
  os_version: string;
  registered_at: string;
  update_policy?: string;
  description?: string;
  group: { id: number; name: string; description?: string };
  distribution: { id: number; name: string; version: string };
  credentials_id?: number;
  ca_trust_deployed?: boolean;
  ca_trust_deployed_at?: string | null;
  principals_hook_deployed?: boolean;
  principals_hook_deployed_at?: string | null;
  transport_preference?: TransportPreference;
  metadata?: {
    environment_type?: string;
    owner_contact?: string;
    ssh_port?: number;
    connection_status?: string;
    last_connection?: string;
    location?: string;
    cpu_arch?: string;
    cpu_cores?: number;
    memory_total?: number;
    disk_total?: number;
    maintenance_window?: string;
  };
  tags?: { id: number; name: string; color: string }[];
}

export const fetchSystemDetails = async (systemId: number): Promise<SystemDetails> => {
  const response = await apiFetch(`/api/backend/systems/${systemId}`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch system details'));
  }
  return response.json();
};

export const updateSystem = async (systemId: number, systemData: SystemData): Promise<SystemDetails> => {
  const response = await apiFetch(`/api/backend/systems/${systemId}`, {
    method: 'PUT',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(systemData),
  });

  const data = await response.json();
  if (!response.ok) {
    const error = new Error(formatApiError(data, 'Failed to update system')) as Error & { details?: string[] };
    if (data.details) error.details = data.details;
    throw error;
  }
  return data;
};

export const deleteSystem = async (systemId: number): Promise<void> => {
  const response = await apiFetch(`/api/backend/systems/${systemId}`, { method: 'DELETE' });
  if (!response.ok) {
    const error = await response.json();
    throw new Error(error.error || 'Failed to delete system');
  }
};

// PRA-153 #4: per-host agent-health snapshot. Backs the host detail
// TransportBadge — fetched separately from system details so the
// page renders inventory immediately and the badge fills in once the
// broker call returns.
export const fetchAgentHealth = async (systemId: number): Promise<SystemAgentHealth> => {
  const response = await apiFetch(`/api/backend/systems/${systemId}/agent-health`);
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch agent health'));
  }
  return response.json();
};

// PRA-153 #4: bulk per-system agent-health for the systems list. One
// call returns all hosts the user can see; per-host broker errors
// degrade that host to badge_state="unknown" rather than failing the
// whole batch.
export const fetchAllAgentHealth = async (): Promise<SystemAgentHealth[]> => {
  const response = await apiFetch('/api/backend/systems/agent-health');
  if (!response.ok) {
    const error = await response.json();
    throw new Error(formatApiError(error, 'Failed to fetch agent health'));
  }
  const data = await response.json();
  return data.systems ?? [];
};

// PRA-338 / PRA-324: thin-agent status contract from GET /agent/status/{id}.
// This is the Praxis AGENT lifecycle + broker-tunnel liveness — a different
// concept from the SSH access broker (CA trust + principals hook) and from
// the transport BadgeState above (which folds in routing preference).
export type AgentLifecycle = 'not_enrolled' | 'active' | 'disabled' | 'revoked';
export type AgentLiveness = 'online' | 'stale' | 'offline' | 'unknown';

export interface ThinAgentStatus {
  system_id: number;
  hostname: string;
  // Enrollment lifecycle (DB): does this host have a thin agent at all.
  agent_status: AgentLifecycle;
  // Live broker tunnel state (derived from the broker registry). unknown
  // means "broker unreachable, couldn't tell" — NOT the same as offline.
  agent_liveness: AgentLiveness;
  agent_version: string | null;
  agent_last_seen_at: string | null;
  agent_cert_expires_at: string | null;
  agent_status_reason: string | null;
  agent_revoked_at: string | null;
  agent_revocation_reason: string | null;
  transport_preference: TransportPreference;
}

// PRA-338: admin-only per-host thin-agent status. Fetched independently of
// system details so a slow/failed broker call renders a local "unavailable"
// state on the card instead of stalling or breaking the whole host page.
export const fetchThinAgentStatus = async (systemId: number): Promise<ThinAgentStatus> => {
  const response = await apiFetch(`/api/backend/agent/status/${systemId}`);
  if (!response.ok) {
    const error = await response.json().catch(() => ({}));
    throw new Error(formatApiError(error, 'Failed to fetch thin-agent status'));
  }
  return response.json();
};

// PRA-153 #4: admin-only. Maintainers + auditors hit 403; the UI
// gates the toggle on isAdmin so this endpoint should never be
// invoked from a non-admin session, but the backend is the source
// of truth.
export const updateTransportPreference = async (
  systemId: number,
  preference: TransportPreference,
): Promise<{ system_id: number; hostname: string; transport_preference: TransportPreference }> => {
  const response = await apiFetch(`/api/backend/systems/${systemId}/transport-preference`, {
    method: 'PATCH',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ transport_preference: preference }),
  });
  const data = await response.json();
  if (!response.ok) {
    throw new Error(formatApiError(data, 'Failed to update transport preference'));
  }
  return data;
};
