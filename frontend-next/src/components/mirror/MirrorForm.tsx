/**
 * PRA-312 Slice 2: create/edit form for a package mirror.
 *
 * Fills the biggest content-workflow gap - mirrors were API-only. Fields mirror the
 * backend MirrorRepoCreate / MirrorRepoUpdate schemas. On edit, structural fields
 * (slug, package_family, source_mode) are read-only: slug is immutable backend-side,
 * and changing family/source-mode on a mirror that already holds content is a footgun,
 * so we surface them but don't let the form mutate them.
 */
import React, { useState } from 'react';
import { toast } from 'sonner';
import { Modal, nativeSelectClass } from '@/components/ui';
import {
  createMirror,
  updateMirror,
  type MirrorRepo,
  type MirrorRepoCreateInput,
} from '@/services/mirrorService';

const inputGeometryCls = 'w-full rounded border border-border-strong px-2 py-1.5 text-sm';
const inputCls = `${inputGeometryCls} bg-surface-sunken text-content focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong focus:outline-none`;
const selectCls = `${inputGeometryCls} ${nativeSelectClass}`;
const labelCls = 'block text-xs uppercase tracking-wide text-content-subtle mb-1';

function csvToList(v: string): string[] {
  return v
    .split(',')
    .map((s) => s.trim())
    .filter(Boolean);
}

interface Props {
  open: boolean;
  onClose: () => void;
  onSaved: (m: MirrorRepo) => void;
  /** When set, the form edits this mirror; otherwise it creates a new one. */
  existing?: MirrorRepo | null;
}

const MirrorForm: React.FC<Props> = ({ open, onClose, onSaved, existing }) => {
  const isEdit = !!existing;
  const [slug, setSlug] = useState(existing?.slug ?? '');
  const [displayName, setDisplayName] = useState(existing?.display_name ?? '');
  const [family, setFamily] = useState(existing?.package_family ?? 'deb');
  const [sourceMode, setSourceMode] = useState(
    existing?.source_mode ?? 'upstream_sync',
  );
  const [upstreamUrl, setUpstreamUrl] = useState(existing?.upstream_url ?? '');
  const [distribution, setDistribution] = useState(existing?.distribution ?? '');
  const [components, setComponents] = useState(
    (existing?.components ?? []).join(', '),
  );
  const [architectures, setArchitectures] = useState(
    (existing?.architectures ?? ['amd64']).join(', '),
  );
  const [cron, setCron] = useState(existing?.sync_schedule_cron ?? '0 2 * * *');
  const [enabled, setEnabled] = useState(existing?.enabled ?? true);
  const [verifySig, setVerifySig] = useState(
    existing?.verify_upstream_signature ?? true,
  );
  const [keepCount, setKeepCount] = useState(
    String(existing?.retention_keep_count ?? 10),
  );
  const [keepDays, setKeepDays] = useState(
    String(existing?.retention_keep_within_days ?? 30),
  );
  const [saving, setSaving] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    try {
      const common = {
        display_name: displayName.trim(),
        upstream_url: upstreamUrl.trim(),
        distribution: distribution.trim(),
        components: csvToList(components),
        architectures: csvToList(architectures),
        sync_schedule_cron: cron.trim(),
        enabled,
        verify_upstream_signature: verifySig,
        retention_keep_count: Number(keepCount),
        retention_keep_within_days: Number(keepDays),
      };
      let saved: MirrorRepo;
      if (isEdit && existing) {
        saved = await updateMirror(existing.id, common);
        toast.success(`Mirror "${existing.slug}" updated`);
      } else {
        const payload: MirrorRepoCreateInput = {
          slug: slug.trim(),
          package_family: family as MirrorRepoCreateInput['package_family'],
          source_mode: sourceMode as MirrorRepoCreateInput['source_mode'],
          ...common,
        };
        saved = await createMirror(payload);
        toast.success(`Mirror "${saved.slug}" created`);
      }
      onSaved(saved);
      onClose();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Save failed');
    } finally {
      setSaving(false);
    }
  };

  return (
    <Modal
      open={open}
      onClose={onClose}
      title={isEdit ? `Edit mirror: ${existing?.slug}` : 'New mirror'}
      maxWidth="max-w-2xl"
    >
      <form onSubmit={submit} className="space-y-3">
        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelCls}>Slug {isEdit && '(immutable)'}</label>
            <input
              className={inputCls}
              value={slug}
              onChange={(e) => setSlug(e.target.value)}
              placeholder="ubuntu-jammy"
              disabled={isEdit}
              required
            />
          </div>
          <div>
            <label className={labelCls}>Display name</label>
            <input
              className={inputCls}
              value={displayName}
              onChange={(e) => setDisplayName(e.target.value)}
              placeholder="Ubuntu 22.04 LTS"
              required
            />
          </div>
          <div>
            <label className={labelCls}>Package family</label>
            <select
              className={selectCls}
              value={family}
              onChange={(e) => setFamily(e.target.value as 'deb' | 'rpm')}
              disabled={isEdit}
            >
              <option value="deb">deb (apt)</option>
              <option value="rpm">rpm (yum/dnf)</option>
            </select>
          </div>
          <div>
            <label className={labelCls}>Source mode</label>
            <select
              className={selectCls}
              value={sourceMode}
              onChange={(e) =>
                setSourceMode(e.target.value as 'upstream_sync' | 'imported_offline')
              }
              disabled={isEdit}
            >
              <option value="upstream_sync">upstream_sync</option>
              <option value="imported_offline">imported_offline (airgap)</option>
            </select>
          </div>
        </div>

        <div>
          <label className={labelCls}>Upstream URL</label>
          <input
            className={inputCls}
            value={upstreamUrl}
            onChange={(e) => setUpstreamUrl(e.target.value)}
            placeholder="http://archive.ubuntu.com/ubuntu"
            required
          />
        </div>

        <div className="grid grid-cols-2 gap-3">
          <div>
            <label className={labelCls}>Distribution / release</label>
            <input
              className={inputCls}
              value={distribution}
              onChange={(e) => setDistribution(e.target.value)}
              placeholder="jammy"
              required
            />
          </div>
          <div>
            <label className={labelCls}>Sync schedule (cron)</label>
            <input
              className={inputCls}
              value={cron}
              onChange={(e) => setCron(e.target.value)}
              placeholder="0 2 * * *"
              required
            />
          </div>
          <div>
            <label className={labelCls}>Components (comma-separated)</label>
            <input
              className={inputCls}
              value={components}
              onChange={(e) => setComponents(e.target.value)}
              placeholder="main, universe"
            />
          </div>
          <div>
            <label className={labelCls}>Architectures (comma-separated)</label>
            <input
              className={inputCls}
              value={architectures}
              onChange={(e) => setArchitectures(e.target.value)}
              placeholder="amd64, arm64"
              required
            />
          </div>
          <div>
            <label className={labelCls}>Retention: keep last N runs</label>
            <input
              type="number"
              min={1}
              className={inputCls}
              value={keepCount}
              onChange={(e) => setKeepCount(e.target.value)}
            />
          </div>
          <div>
            <label className={labelCls}>Retention: keep within days</label>
            <input
              type="number"
              min={1}
              className={inputCls}
              value={keepDays}
              onChange={(e) => setKeepDays(e.target.value)}
            />
          </div>
        </div>

        <div className="flex items-center gap-6 pt-1">
          <label className="flex items-center gap-2 text-sm text-content">
            <input
              type="checkbox"
              checked={enabled}
              onChange={(e) => setEnabled(e.target.checked)}
            />
            Enabled
          </label>
          <label className="flex items-center gap-2 text-sm text-content">
            <input
              type="checkbox"
              checked={verifySig}
              onChange={(e) => setVerifySig(e.target.checked)}
            />
            Verify upstream signature
          </label>
        </div>

        <div className="flex justify-end gap-2 pt-3">
          <button
            type="button"
            onClick={onClose}
            className="rounded px-3 py-1.5 text-sm text-content hover:bg-white/5"
          >
            Cancel
          </button>
          <button
            type="submit"
            disabled={saving}
            className="rounded bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-50"
          >
            {saving ? 'Saving…' : isEdit ? 'Save changes' : 'Create mirror'}
          </button>
        </div>
      </form>
    </Modal>
  );
};

export default MirrorForm;
