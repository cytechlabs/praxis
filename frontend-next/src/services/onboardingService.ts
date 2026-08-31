import { apiFetch, formatApiError } from '../utils/api';

/**
 * Guided first-system onboarding.
 *
 * Every call returns the whole draft, so the wizard never has to reassemble
 * state from partial responses or guess what the backend accepted. Errors carry
 * the backend's structured code alongside its message: the UI decides what to
 * offer from the code, and shows the message, so no transport or exception text
 * is ever parsed or displayed here.
 */

export type OnboardingStep =
  | 'connect'
  | 'authenticate'
  | 'verify'
  | 'discover'
  | 'organize'
  | 'confirm'
  | 'finish';

export type CheckName =
  | 'address'
  | 'network'
  | 'host_identity'
  | 'authentication'
  | 'command'
  | 'sudo';

export type CheckStatus = 'pass' | 'fail' | 'skipped';

export interface VerificationCheck {
  check: CheckName;
  status: CheckStatus;
  reason_code: string;
  message: string;
}

export interface Verification {
  verified: boolean;
  completed_at: string;
  checks: VerificationCheck[];
  host_key_fingerprint: string | null;
  host_key_type: string | null;
}

export interface Discovery {
  effective_hostname: string | null;
  fqdn: string | null;
  distro_name: string | null;
  distro_version: string | null;
  architecture: string | null;
  package_family: string | null;
  package_manager: string | null;
  support_mapping: 'matched' | 'unknown' | 'declared';
  distro_id: number | null;
  confirmed_unknown: boolean;
  collected_at: string;
}

export interface CredentialSummary {
  id: number;
  name: string;
  username: string | null;
  auth_method: string;
  sudo_method: string;
  source: 'managed' | 'linked';
}

export interface Draft {
  id: string;
  status: string;
  current_step: OnboardingStep;
  state_version: number;
  expires_at: string | null;
  connection: {
    address?: string;
    ssh_port?: number;
    hostname?: string | null;
    resolved_ip?: string | null;
  };
  organization: {
    group_id?: number | null;
    environment?: string | null;
    description?: string | null;
    tags?: string[];
    transport_preference?: string | null;
    update_policy?: string | null;
  };
  verification: Verification | null;
  discovery: Discovery | null;
  verification_skipped: boolean;
  credential: CredentialSummary | null;
  ssh_security_policy: { id: number; name: string } | null;
  host_key: {
    fingerprint: string | null;
    key_type: string | null;
    decision: 'pending' | 'trusted' | 'rejected';
  };
  finalized_system_id: number | null;
  finalize_token?: string;
}

export interface Capabilities {
  can_onboard: boolean;
  can_create_credential: boolean;
  scope: 'tenant_wide' | 'scoped';
  roles: string[];
}

export interface FollowUp {
  key: string;
  label: string;
  description: string;
}

export interface ConfirmResponse {
  draft: Draft;
  preview: {
    hostname: string | null;
    ip_address: string | null;
    ssh_port: number | null;
    group: { id: number; name: string } | null;
    ssh_security_policy: { id: number; name: string } | null;
    environment: string;
    description: string | null;
    tags: string[];
    transport_preference: string;
    update_policy: string | null;
    status: string;
    verified: boolean;
    verification_skipped: boolean;
    host_key_fingerprint: string | null;
    host_key_decision: string;
  };
  license: Record<string, unknown>;
  follow_ups: FollowUp[];
}

/**
 * An error that kept the backend's reason code.
 *
 * The code is what the UI branches on; `message` is already operator-facing
 * text chosen by the backend, so it is displayed rather than rewritten.
 */
export class OnboardingError extends Error {
  code: string;
  reasonCode?: string;
  checks?: VerificationCheck[];

  constructor(code: string, message: string, extra?: Record<string, unknown>) {
    super(message);
    this.name = 'OnboardingError';
    this.code = code;
    this.reasonCode = extra?.reason_code as string | undefined;
    this.checks = extra?.checks as VerificationCheck[] | undefined;
  }
}

async function request<T>(path: string, init?: RequestInit): Promise<T> {
  const response = await apiFetch(`/api/backend/onboarding${path}`, {
    headers: init?.body ? { 'Content-Type': 'application/json' } : undefined,
    ...init,
  });

  const body = await response.json().catch(() => ({}));
  if (!response.ok) {
    const detail = (body as { detail?: unknown }).detail;
    if (detail && typeof detail === 'object' && 'code' in (detail as object)) {
      const detailRecord = detail as Record<string, unknown>;
      throw new OnboardingError(
        String(detailRecord.code),
        String(
          detailRecord.message ?? 'This step could not be completed.',
        ),
        detailRecord,
      );
    }
    throw new OnboardingError('request_failed', formatApiError(body, 'This step could not be completed.'));
  }
  return body as T;
}

const versionQuery = (version?: number) =>
  version === undefined ? '' : `?state_version=${version}`;

export const fetchCapabilities = () =>
  request<{ capabilities: Capabilities; license: Record<string, unknown> }>('/capabilities');

export const createDraft = () =>
  request<{ draft: Draft; capabilities: Capabilities }>('/drafts', { method: 'POST' });

export const fetchDraft = (id: string) =>
  request<{ draft: Draft; capabilities: Capabilities }>(`/drafts/${id}`);

export const cancelDraft = (id: string) =>
  request<{ draft: Draft }>(`/drafts/${id}`, { method: 'DELETE' });

export const fetchCredentialOptions = () =>
  request<{
    credentials: CredentialSummary[];
    ssh_security_policies: {
      id: number;
      name: string;
      description: string | null;
      requires_host_key_verification: boolean;
      is_default: boolean;
    }[];
    default_ssh_security_policy_id: number | null;
    capabilities: Capabilities;
  }>('/credential-options');

export const fetchOrganizationOptions = () =>
  request<{
    groups: { id: number; name: string }[];
    default_group_id: number | null;
    distros: { id: number; name: string; version: string }[];
    environments: string[];
    transport_preferences: string[];
    capabilities: Capabilities;
  }>('/organization-options');

export const saveConnection = (
  id: string,
  body: { address: string; ssh_port: number; hostname?: string | null },
  version?: number,
) =>
  request<{ draft: Draft }>(`/drafts/${id}/connect${versionQuery(version)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  });

export const saveAuthentication = (
  id: string,
  body: { credential_id: number; ssh_security_policy_id?: number | null },
  version?: number,
) =>
  request<{ draft: Draft }>(`/drafts/${id}/authenticate${versionQuery(version)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  });

export const runVerification = (id: string, version?: number) =>
  request<{ draft: Draft }>(`/drafts/${id}/verify${versionQuery(version)}`, {
    method: 'POST',
  });

export const decideHostKey = (
  id: string,
  body: { accept: boolean; fingerprint: string },
  version?: number,
) =>
  request<{ draft: Draft }>(`/drafts/${id}/host-key${versionQuery(version)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  });

export const skipVerification = (id: string, version?: number) =>
  request<{ draft: Draft }>(`/drafts/${id}/skip-verification${versionQuery(version)}`, {
    method: 'POST',
    body: JSON.stringify({ acknowledged: true }),
  });

export const runDiscovery = (id: string, version?: number) =>
  request<{ draft: Draft }>(`/drafts/${id}/discover${versionQuery(version)}`, {
    method: 'POST',
  });

/**
 * The body the discovery-confirmation step sends, once a distribution is bound.
 *
 * `confirmed_unknown` is always false. A host with no catalogue mapping cannot
 * be patched, rolled back, mirrored, or assessed, so there is no acknowledgement
 * that makes one manageable and the backend refuses the request either way.
 */
export interface DiscoveryConfirmationBody {
  distro_id: number;
  confirmed_unknown: false;
}

/**
 * The request for a chosen distribution, or `null` when there is nothing to
 * send.
 *
 * `null` means the operator has not bound this host to a supported release yet,
 * which is not a request worth making: it is the one thing the step exists to
 * collect. The caller keeps them on Discover instead of sending it and
 * rendering a refusal.
 */
export function buildDiscoveryConfirmation(
  chosenDistroId: string,
): DiscoveryConfirmationBody | null {
  const trimmed = chosenDistroId.trim();
  if (!trimmed) return null;
  const distroId = Number(trimmed);
  if (!Number.isInteger(distroId) || distroId < 1) return null;
  return { distro_id: distroId, confirmed_unknown: false };
}

export const confirmDiscovery = (
  id: string,
  body: DiscoveryConfirmationBody,
  version?: number,
) =>
  request<{ draft: Draft }>(
    `/drafts/${id}/discovery-confirmation${versionQuery(version)}`,
    { method: 'PUT', body: JSON.stringify(body) },
  );

export const saveOrganization = (
  id: string,
  body: Record<string, unknown>,
  version?: number,
) =>
  request<{ draft: Draft }>(`/drafts/${id}/organize${versionQuery(version)}`, {
    method: 'PUT',
    body: JSON.stringify(body),
  });

export const confirmDraft = (id: string) =>
  request<ConfirmResponse>(`/drafts/${id}/confirm`, { method: 'POST' });

export const finishDraft = (
  id: string,
  body: { finalize_token: string; state_version: number },
) =>
  request<{
    system_id: number;
    hostname: string;
    status: string;
    created: boolean;
    verification_skipped: boolean;
  }>(`/drafts/${id}/finish`, { method: 'POST', body: JSON.stringify(body) });
