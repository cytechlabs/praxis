/**
 * PRA-159 #5: content channel API client.
 *
 * Channels are pure content composition — they bundle one or more
 * mirrors of the same package_family. Hosts subscribe to
 * ContentProfile rows that compose channels, NOT to channels
 * directly (see contentProfileService.ts).
 */
import { apiFetch } from '../utils/api';

// PRA-238: requests must go through the Next.js `/api/backend` proxy rewrite
// (see next.config.ts). Bare `/content-channels` paths 404 in the browser.
// Mirror the working `mirrorService.ts` pattern with a shared BASE constant.
const BASE = '/api/backend/content-channels';

export type PackageFamily = 'deb' | 'rpm';

export interface ContentChannelRepo {
  id: number;
  channel_id: number;
  mirror_id: number;
  mirror_slug: string;
  suite_override: string | null;
  effective_suite: string;
  pinned_run_id: number | null;
  pinned_manifest_sha256: string | null;
  created_at: string;
  updated_at: string;
}

export interface ContentChannel {
  id: number;
  slug: string;
  display_name: string;
  package_family: PackageFamily;
  description: string | null;
  deleted_at: string | null;
  created_at: string;
  updated_at: string;
  repos: ContentChannelRepo[];
}

export async function listChannels(opts: { include_deleted?: boolean } = {}): Promise<ContentChannel[]> {
  const qs = opts.include_deleted ? '?include_deleted=true' : '';
  const res = await apiFetch(`${BASE}${qs}`);
  if (!res.ok) throw new Error(`failed to list channels (${res.status})`);
  return res.json();
}

export async function getChannel(id: number, opts: { include_deleted?: boolean } = {}): Promise<ContentChannel> {
  const qs = opts.include_deleted ? '?include_deleted=true' : '';
  const res = await apiFetch(`${BASE}/${id}${qs}`);
  if (!res.ok) throw new Error(`failed to get channel ${id} (${res.status})`);
  return res.json();
}

export interface CreateChannelInput {
  slug: string;
  display_name: string;
  package_family: PackageFamily;
  description?: string | null;
}

export async function createChannel(input: CreateChannelInput): Promise<ContentChannel> {
  const res = await apiFetch(BASE, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`create channel failed (${res.status}): ${body}`);
  }
  return res.json();
}

export async function deleteChannel(id: number): Promise<void> {
  const res = await apiFetch(`${BASE}/${id}`, { method: 'DELETE' });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`delete channel failed (${res.status}): ${body}`);
  }
}

export interface AddChannelRepoInput {
  mirror_id: number;
  suite_override?: string | null;
  pinned_run_id?: number | null;
}

export async function addChannelRepo(
  channelId: number,
  input: AddChannelRepoInput,
): Promise<ContentChannelRepo> {
  const res = await apiFetch(`${BASE}/${channelId}/repos`, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: JSON.stringify(input),
  });
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`add channel repo failed (${res.status}): ${body}`);
  }
  return res.json();
}

export async function removeChannelRepo(
  channelId: number,
  repoId: number,
): Promise<void> {
  const res = await apiFetch(`${BASE}/${channelId}/repos/${repoId}`, {
    method: 'DELETE',
  });
  if (!res.ok) {
    throw new Error(`remove channel repo failed (${res.status})`);
  }
}

export async function updateChannelRepoPin(
  channelId: number,
  repoId: number,
  pinnedRunId: number | null,
): Promise<ContentChannelRepo> {
  const res = await apiFetch(
    `${BASE}/${channelId}/repos/${repoId}/pin`,
    {
      method: 'PATCH',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ pinned_run_id: pinnedRunId }),
    },
  );
  if (!res.ok) {
    const body = await res.text();
    throw new Error(`update pin failed (${res.status}): ${body}`);
  }
  return res.json();
}
