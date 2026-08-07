import { apiFetch } from '../utils/api';

export interface SSHSecurityPolicy {
  id: number;
  name: string;
  description?: string;
  max_auth_tries: number;
  connection_timeout: number;
  idle_timeout: number;
  require_host_key_verification: boolean;
  minimum_key_size: number;
  allowed_auth_methods: string;
  allowed_ciphers: string;
  allowed_macs: string;
  allowed_kex: string;
  log_commands: boolean;
  log_file_transfers: boolean;
  created_at: string;
  updated_at: string;
  created_by: number;
}

export interface SSHSecurityPolicyCreate {
  name: string;
  description?: string;
  max_auth_tries?: number;
  connection_timeout?: number;
  idle_timeout?: number;
  require_host_key_verification?: boolean;
  minimum_key_size?: number;
  allowed_auth_methods?: string;
  allowed_ciphers?: string;
  allowed_macs?: string;
  allowed_kex?: string;
  log_commands?: boolean;
  log_file_transfers?: boolean;
}

export interface SSHSecurityPolicyUpdate {
  name?: string;
  description?: string;
  max_auth_tries?: number;
  connection_timeout?: number;
  idle_timeout?: number;
  require_host_key_verification?: boolean;
  minimum_key_size?: number;
  allowed_auth_methods?: string;
  allowed_ciphers?: string;
  allowed_macs?: string;
  allowed_kex?: string;
  log_commands?: boolean;
  log_file_transfers?: boolean;
}

export interface SSHSecurityLog {
  id: number;
  system_id: number;
  event_type: string;
  event_details: string;
  source_ip?: string;
  username?: string;
  success: boolean;
  timestamp: string;
}

export interface SSHHostKey {
  id: number;
  system_id: number;
  hostname: string;
  key_type: string;
  public_key: string;
  fingerprint: string;
  verified: boolean;
  first_seen: string;
  last_seen: string;
  created_at: string;
  updated_at: string;
}

export interface SSHHostKeyUpdate {
  verified?: boolean;
}

export interface PaginatedResponse<T> {
  total: number;
  data: T[];
}

class SSHSecurityService {
  private baseUrl = '/api/backend/ssh-security';

  async getPolicies(skip = 0, limit = 100): Promise<{ policies: SSHSecurityPolicy[]; total: number }> {
    const response = await apiFetch(`${this.baseUrl}/policies?skip=${skip}&limit=${limit}`);
    if (!response.ok) throw new Error('Failed to fetch SSH security policies');
    return response.json();
  }

  async getPolicy(id: number): Promise<SSHSecurityPolicy> {
    const response = await apiFetch(`${this.baseUrl}/policies/${id}`);
    if (!response.ok) throw new Error('Failed to fetch SSH security policy');
    return response.json();
  }

  async createPolicy(policy: SSHSecurityPolicyCreate): Promise<SSHSecurityPolicy> {
    const response = await apiFetch(`${this.baseUrl}/policies`, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    });
    if (!response.ok) throw new Error('Failed to create SSH security policy');
    return response.json();
  }

  async updatePolicy(id: number, policy: SSHSecurityPolicyUpdate): Promise<SSHSecurityPolicy> {
    const response = await apiFetch(`${this.baseUrl}/policies/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(policy),
    });
    if (!response.ok) throw new Error('Failed to update SSH security policy');
    return response.json();
  }

  async deletePolicy(id: number): Promise<void> {
    const response = await apiFetch(`${this.baseUrl}/policies/${id}`, { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to delete SSH security policy');
  }

  async getLogs(
    skip = 0,
    limit = 100,
    systemId?: number,
    eventType?: string,
    success?: boolean
  ): Promise<{ logs: SSHSecurityLog[]; total: number }> {
    const params = new URLSearchParams({ skip: skip.toString(), limit: limit.toString() });
    if (systemId) params.append('system_id', systemId.toString());
    if (eventType) params.append('event_type', eventType);
    if (success !== undefined) params.append('success', success.toString());

    const response = await apiFetch(`${this.baseUrl}/logs?${params.toString()}`);
    if (!response.ok) throw new Error('Failed to fetch SSH security logs');
    return response.json();
  }

  async getLog(id: number): Promise<SSHSecurityLog> {
    const response = await apiFetch(`${this.baseUrl}/logs/${id}`);
    if (!response.ok) throw new Error('Failed to fetch SSH security log');
    return response.json();
  }

  async getHostKeys(
    skip = 0,
    limit = 100,
    systemId?: number,
    verified?: boolean
  ): Promise<{ host_keys: SSHHostKey[]; total: number }> {
    const params = new URLSearchParams({ skip: skip.toString(), limit: limit.toString() });
    if (systemId) params.append('system_id', systemId.toString());
    if (verified !== undefined) params.append('verified', verified.toString());

    const response = await apiFetch(`${this.baseUrl}/host-keys?${params.toString()}`);
    if (!response.ok) throw new Error('Failed to fetch SSH host keys');
    return response.json();
  }

  async getHostKey(id: number): Promise<SSHHostKey> {
    const response = await apiFetch(`${this.baseUrl}/host-keys/${id}`);
    if (!response.ok) throw new Error('Failed to fetch SSH host key');
    return response.json();
  }

  async updateHostKey(id: number, hostKey: SSHHostKeyUpdate): Promise<SSHHostKey> {
    const response = await apiFetch(`${this.baseUrl}/host-keys/${id}`, {
      method: 'PUT',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(hostKey),
    });
    if (!response.ok) throw new Error('Failed to update SSH host key');
    return response.json();
  }

  async deleteHostKey(id: number): Promise<void> {
    const response = await apiFetch(`${this.baseUrl}/host-keys/${id}`, { method: 'DELETE' });
    if (!response.ok) throw new Error('Failed to delete SSH host key');
  }

  async getEventTypes(): Promise<{ event_types: string[] }> {
    const response = await apiFetch(`${this.baseUrl}/event-types`);
    if (!response.ok) throw new Error('Failed to fetch SSH security event types');
    return response.json();
  }
}

export const sshSecurityService = new SSHSecurityService();

export const fetchSSHSecurityPolicies = async (): Promise<{ policies: SSHSecurityPolicy[]; total: number }> => {
  return sshSecurityService.getPolicies();
};
