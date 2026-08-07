/**
 * PRA-159 #5: content profile API client.
 *
 * Profiles are the host-facing object. Hosts (or groups, or smart
 * groups) subscribe to a profile, and the apply orchestrator writes
 * /etc source-list config based on the profile's effective
 * resolution. See backend ContentProfileService for the resolution
 * contract.
 */
import { apiFetch } from '../utils/api';
import type { PackageFamily } from './contentChannelService';

// PRA-238: requests must go through the Next.js `/api/backend` proxy rewrite
// (see next.config.ts). Bare `/content-profiles` and `/systems/...` paths 404
// in the browser. Mirror the working `mirrorService.ts` pattern with shared
// BASE constants.
const BASE = '/api/backend/content-profiles';
const SYSTEMS_BASE = '/api/backend/systems';

export type ResolutionState = 'no_profile' | 'resolved' | 'conflict';
export type ViaKind = 'direct' | 'group' | 'smart_group';
export type ScopeKind = 'host' | 'group' | 'smart_group';
export type ApplyOutcomeState =
  | 'applied'
  | 'noop'
  | 'refused_no_profile'
  | 'refused_conflict'
  | 'failed';

export interface ChannelLink {
  id: number;
  channel_id: number;
  channel_slug: string;
  channel_display_name: string;
}

export interface ContentProfile {
  id: number;
  slug: string;
  display_name: string;
  package_family: PackageFamily;
  description: string | null;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
  channels: ChannelLink[];
}

export interface SubscriptionRow {
  id: number;
  profile_id: number;
  scope_kind: ScopeKind;
  scope_id: number;
  scope_label: string;
  created_at: string;
}

export interface ProfileSubscriber {
  host_id: number;
  hostname: string;
  via_kind: ViaKind;
  via_id: number | null;
  via_label: string | null;
}

export interface EffectiveProfileBinding {
  profile_id: number;
  profile_slug: string;
  profile_display_name: string;
  via_kind: ViaKind;
  via_id: number | null;
  via_label: string | null;
}

export interface EffectiveProfile {
  state: ResolutionState;
  profile: EffectiveProfileBinding | null;
  conflict_bindings: EffectiveProfileBinding[];
}

export interface ResolvedMirrorEntry {
  channel_id: number;
  channel_slug: string;
  mirror_id: number;
  mirror_slug: string;
  package_family: PackageFamily;
  suite: string;
  components: string[];
  architectures: string[];
  pinned_run_id: number | null;
  pinned_manifest_sha256: string | null;
}

export interface ResolvedContent {
  state: ResolutionState;
  profile: EffectiveProfileBinding | null;
  conflict_bindings: EffectiveProfileBinding[];
  entries: ResolvedMirrorEntry[];
}

export interface ApplyOutcome {
  state: ApplyOutcomeState;
  profile_slug: string | null;
  written_paths: string[];
  removed_paths: string[];
  trust_installed_for_mirrors: string[];
  credentials_issued_for_mirrors: string[];
  error_text: string | null;
}

// ---------------------------------------------------------------------------
// CRUD
// ---------------------------------------------------------------------------

export async function listProfiles(opts: { include_deleted?: boolean } = {}): Promise<ContentProfile[]> {
  const qs = opts.include_deleted ? '?include_deleted=true' : '';
  const res = await apiFetch(`${BASE}${qs}`);
  if (!res.ok) throw new Error(`list profiles failed (${res.status})`);
  return res.json();
}

export async function getProfile(
  id: number,
  opts: { include_deleted?: boolean } = {},
): Promise<ContentProfile> {
  const qs = opts.include_deleted ? '?include_deleted=true' : '';
  const res = await apiFetch(`${BASE}/${id}${qs}`);
  if (!res.ok) throw new Error(`get profile ${id} failed (${res.status})`);
  return res.json();
}

export interface CreateProfileInput {
  slug: string;
  display_name: string;
  package_family: PackageFamily;
  description?: string | null;
}

export async function createProfile(input: CreateProfileInput): Promise<ContentProfile> {
  const res = await apiFetch(BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`create profile failed (${res.status}): ${body}`);
  }
  return res.json();
}

export async function deleteProfile(id: number): Promise<void> {
  const res = await apiFetch(`${BASE}/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`delete profile failed (${res.status}): ${body}`);
  }
}

// ---------------------------------------------------------------------------
// Channels
// ---------------------------------------------------------------------------

export async function addProfileChannel(
  profileId: number,
  channelId: number,
): Promise<ContentProfile> {
  const res = await apiFetch(`${BASE}/${profileId}/channels`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ channel_id: channelId }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`add channel to profile failed (${res.status}): ${body}`);
  }
  return res.json();
}

export async function removeProfileChannel(
  profileId: number,
  channelId: number,
): Promise<void> {
  const res = await apiFetch(
    `${BASE}/${profileId}/channels/${channelId}`,
    { method: 'DELETE' },
  );
  if (!res.ok) {
    throw new Error(`remove channel from profile failed (${res.status})`);
  }
}

// ---------------------------------------------------------------------------
// Subscriptions
// ---------------------------------------------------------------------------

export async function listProfileSubscriptions(
  profileId: number,
): Promise<SubscriptionRow[]> {
  const res = await apiFetch(`${BASE}/${profileId}/subscriptions`);
  if (!res.ok) throw new Error(`list subscriptions failed (${res.status})`);
  return res.json();
}

export async function listProfileSubscribers(
  profileId: number,
): Promise<ProfileSubscriber[]> {
  const res = await apiFetch(`${BASE}/${profileId}/subscribers`);
  if (!res.ok) throw new Error(`list subscribers failed (${res.status})`);
  return res.json();
}

export async function addHostSubscription(
  profileId: number,
  hostId: number,
): Promise<SubscriptionRow> {
  const res = await apiFetch(`${BASE}/${profileId}/hosts`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ host_id: hostId }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`add host subscription failed (${res.status}): ${body}`);
  }
  return res.json();
}

export async function removeHostSubscription(
  profileId: number,
  hostId: number,
): Promise<void> {
  const res = await apiFetch(
    `${BASE}/${profileId}/hosts/${hostId}`,
    { method: 'DELETE' },
  );
  if (!res.ok) {
    throw new Error(`remove host subscription failed (${res.status})`);
  }
}

export async function addGroupSubscription(
  profileId: number,
  groupId: number,
): Promise<SubscriptionRow> {
  const res = await apiFetch(`${BASE}/${profileId}/groups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ group_id: groupId }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`add group subscription failed (${res.status}): ${body}`);
  }
  return res.json();
}

export async function removeGroupSubscription(
  profileId: number,
  groupId: number,
): Promise<void> {
  const res = await apiFetch(
    `${BASE}/${profileId}/groups/${groupId}`,
    { method: 'DELETE' },
  );
  if (!res.ok) {
    throw new Error(`remove group subscription failed (${res.status})`);
  }
}

export async function addSmartGroupSubscription(
  profileId: number,
  smartGroupId: number,
): Promise<SubscriptionRow> {
  const res = await apiFetch(`${BASE}/${profileId}/smart-groups`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify({ smart_group_id: smartGroupId }),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`add smart-group subscription failed (${res.status}): ${body}`);
  }
  return res.json();
}

export async function removeSmartGroupSubscription(
  profileId: number,
  smartGroupId: number,
): Promise<void> {
  const res = await apiFetch(
    `${BASE}/${profileId}/smart-groups/${smartGroupId}`,
    { method: 'DELETE' },
  );
  if (!res.ok) {
    throw new Error(`remove smart-group subscription failed (${res.status})`);
  }
}

// ---------------------------------------------------------------------------
// Resolved + apply (host-scoped)
// ---------------------------------------------------------------------------

export async function getProfileResolved(profileId: number): Promise<ResolvedContent> {
  const res = await apiFetch(`${BASE}/${profileId}/resolved`);
  if (!res.ok) throw new Error(`get resolved failed (${res.status})`);
  return res.json();
}

export async function getHostEffectiveProfile(
  systemId: number,
): Promise<EffectiveProfile> {
  const res = await apiFetch(`${SYSTEMS_BASE}/${systemId}/content-profile`);
  if (!res.ok) throw new Error(`get effective profile failed (${res.status})`);
  return res.json();
}

export async function getHostResolvedContent(
  systemId: number,
): Promise<ResolvedContent> {
  const res = await apiFetch(`${SYSTEMS_BASE}/${systemId}/content-profile/resolved`);
  if (!res.ok) throw new Error(`get host resolved failed (${res.status})`);
  return res.json();
}

export async function applyHostContentProfile(
  systemId: number,
): Promise<ApplyOutcome> {
  const res = await apiFetch(`${SYSTEMS_BASE}/${systemId}/content-profile/apply`, {
    method: 'POST',
  });
  // 200 (applied/noop), 409 (refused), 502 (failed) all return the
  // structured ApplyOutcome shape.
  const text = await res.text();
  let body: ApplyOutcome;
  try {
    body = JSON.parse(text);
  } catch {
    throw new Error(`apply: unparseable response (${res.status}): ${text}`);
  }
  return body;
}

export function applyOutcomeIsTerminalSuccess(o: ApplyOutcome): boolean {
  return o.state === 'applied' || o.state === 'noop';
}
