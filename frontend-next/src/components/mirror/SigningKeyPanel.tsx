/**
 * PRA-158 #5c: signing-key panel on the mirror detail page.
 *
 * Surfaces the active signing key, any pending_cutover, and any
 * rotating_out keys, plus the operator action buttons:
 *
 *   * Generate signing key (if no_key_yet)
 *   * Rotate (rotate-prepare; disabled while pending_cutover exists)
 *   * Cut over (with inline preview of blocking hosts; force toggle
 *     gated behind admin role)
 *   * Retire (per rotating_out key)
 *
 * Reads the trust bundle once on mount + after each successful action;
 * the bundle is the canonical "non-retired keys for this mirror" view
 * and matches what hosts trust right now.
 */
import React, { useCallback, useEffect, useMemo, useState } from 'react';
import { AlertTriangle, KeyRound, RefreshCw, RotateCw, Trash2 } from 'lucide-react';
import { toast } from 'sonner';

import { Badge, Button } from '@/components/ui';
import {
  bootstrapSigningKey,
  cutover,
  CutoverBlockedError,
  getCutoverPreview,
  getTrustBundle,
  retireKey,
  rotatePrepare,
  type CutoverPreview,
  type MirrorRepo,
  type MirrorSigningKeyStatus,
  type TrustBundle,
  type TrustBundleEntry,
} from '@/services/mirrorService';

interface SigningKeyPanelProps {
  mirror: MirrorRepo;
  /** Gates the Force-cutover toggle. Matches the backend's
   * require_role("admin", "maintainer") on POST /signing-key/cutover -
   * narrowing this to admin-only would hide the override from
   * maintainers who are already authorized for it. */
  canForceCutover: boolean;
  /** Called after any state-changing action completes so the parent can
   * refresh its own ``MirrorRepo`` (signing_status field changes). */
  onChange?: () => void;
}

const STATUS_LABEL: Record<MirrorSigningKeyStatus, string> = {
  active: 'Active',
  pending_cutover: 'Pending cutover',
  rotating_out: 'Rotating out',
  retired: 'Retired',
};

const STATUS_VARIANT: Record<
  MirrorSigningKeyStatus,
  'success' | 'info' | 'warning' | 'neutral'
> = {
  active: 'success',
  pending_cutover: 'info',
  rotating_out: 'warning',
  retired: 'neutral',
};

const SigningKeyPanel: React.FC<SigningKeyPanelProps> = ({
  mirror,
  canForceCutover,
  onChange,
}) => {
  const [bundle, setBundle] = useState<TrustBundle | null>(null);
  const [loading, setLoading] = useState(true);
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [preview, setPreview] = useState<CutoverPreview | null>(null);
  const [forceCutover, setForceCutover] = useState(false);

  const refresh = useCallback(async () => {
    setLoading(true);
    try {
      const data = await getTrustBundle(mirror.id);
      setBundle(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    } finally {
      setLoading(false);
    }
  }, [mirror.id]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Pending and active drive the action-button visibility; rotating_out
  // keys are rendered inline in the main bundle.keys list with their
  // own retire button per row, so no separate memo is needed.
  const pending = useMemo(
    () => bundle?.keys.find((k) => k.status === 'pending_cutover') ?? null,
    [bundle]
  );
  const active = useMemo(
    () => bundle?.keys.find((k) => k.status === 'active') ?? null,
    [bundle]
  );

  // Refresh the cutover preview whenever a pending key exists so the
  // operator sees blocking hosts before clicking Cut over.
  useEffect(() => {
    if (!pending) {
      setPreview(null);
      return;
    }
    let cancelled = false;
    (async () => {
      try {
        const p = await getCutoverPreview(mirror.id);
        if (!cancelled) setPreview(p);
      } catch (e) {
        if (!cancelled) {
          // Preview failures are non-fatal - surface inline but
          // don't block the action.
          console.warn('cutover preview load failed:', e);
        }
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [mirror.id, pending]);

  const handleBootstrap = async () => {
    setBusy(true);
    try {
      await bootstrapSigningKey(mirror.id);
      toast.success(`Signing key generated for "${mirror.slug}".`);
      await refresh();
      onChange?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to bootstrap key');
    } finally {
      setBusy(false);
    }
  };

  const handleRotatePrepare = async () => {
    setBusy(true);
    try {
      await rotatePrepare(mirror.id);
      toast.success('New pending key generated. Install trust on hosts before cutting over.');
      await refresh();
      onChange?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to prepare rotation');
    } finally {
      setBusy(false);
    }
  };

  const handleCutover = async () => {
    setBusy(true);
    try {
      await cutover(mirror.id, { force: forceCutover });
      toast.success('Cutover complete. Native signing now uses the new key.');
      setForceCutover(false);
      await refresh();
      onChange?.();
    } catch (e) {
      if (e instanceof CutoverBlockedError) {
        setPreview(e.preview);
        toast.error(
          `Cutover blocked: ${e.preview.hosts_missing_pending.length} host(s) still need install-trust.`
        );
      } else {
        toast.error(e instanceof Error ? e.message : 'Failed to cut over');
      }
    } finally {
      setBusy(false);
    }
  };

  const handleRetire = async (key: TrustBundleEntry) => {
    if (
      !window.confirm(
        `Retire signing key ${key.fingerprint}? It will be dropped from the trust ` +
          'bundle. Re-run install-trust on hosts afterwards to clean up their ' +
          'on-host fingerprint sets.'
      )
    ) {
      return;
    }
    setBusy(true);
    try {
      await retireKey(mirror.id, key.id);
      toast.success(`Retired ${key.fingerprint.slice(0, 16)}…`);
      await refresh();
      onChange?.();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to retire key');
    } finally {
      setBusy(false);
    }
  };

  return (
    <section className="rounded border border-zinc-800 bg-[#111115] p-4">
      <div className="mb-3 flex items-center justify-between">
        <h2 className="flex items-center gap-2 text-sm font-semibold text-gray-200">
          <KeyRound size={16} /> Signing keys
        </h2>
        <button
          type="button"
          onClick={refresh}
          disabled={loading}
          className="text-xs text-gray-400 hover:text-gray-200"
          title="Refresh trust bundle"
        >
          <RefreshCw size={14} className={loading ? 'animate-spin' : ''} />
        </button>
      </div>

      {error && (
        <div className="mb-3 rounded border border-red-900/40 bg-red-900/10 p-2 text-xs text-red-300">
          {error}
        </div>
      )}

      {loading && bundle === null && <div className="text-sm text-gray-400">Loading…</div>}

      {bundle && bundle.keys.length === 0 && (
        <div className="space-y-3">
          <p className="text-sm text-gray-400">
            No signing key yet. Praxis can&apos;t sign mirror metadata until one
            exists. Generate one to enable native + manifest signing on the
            next sync.
          </p>
          <Button onClick={handleBootstrap} disabled={busy} variant="primary">
            <KeyRound size={14} className="mr-1" />
            Generate signing key
          </Button>
        </div>
      )}

      {bundle && bundle.keys.length > 0 && (
        <div className="space-y-3">
          <ul className="space-y-2">
            {bundle.keys.map((k) => (
              <li
                key={k.fingerprint}
                className="flex items-center justify-between rounded border border-zinc-800/60 bg-black/20 px-3 py-2"
              >
                <div className="flex flex-col gap-1">
                  <div className="flex items-center gap-2">
                    <Badge variant={STATUS_VARIANT[k.status]}>
                      {STATUS_LABEL[k.status]}
                    </Badge>
                    <span className="font-mono text-xs text-gray-400">
                      {k.fingerprint}
                    </span>
                  </div>
                  <span className="text-xs text-gray-500">{k.uid}</span>
                </div>
                {k.status === 'rotating_out' && (
                  <Button
                    onClick={() => handleRetire(k)}
                    disabled={busy}
                    variant="ghost"
                    size="sm"
                    title="Retire this key (drops it from the trust bundle)"
                  >
                    <Trash2 size={12} className="mr-1" /> Retire
                  </Button>
                )}
              </li>
            ))}
          </ul>

          <div className="flex flex-wrap items-center gap-2 border-t border-zinc-800/60 pt-3">
            {!pending && active && (
              <Button onClick={handleRotatePrepare} disabled={busy} variant="outline">
                <RotateCw size={14} className="mr-1" /> Rotate
              </Button>
            )}

            {pending && (
              <div className="flex flex-1 flex-col gap-2">
                <div className="flex items-center gap-2">
                  <Button onClick={handleCutover} disabled={busy} variant="primary">
                    <RotateCw size={14} className="mr-1" /> Cut over
                  </Button>
                  {canForceCutover && (
                    <label className="flex items-center gap-1 text-xs text-gray-400">
                      <input
                        type="checkbox"
                        checked={forceCutover}
                        onChange={(e) => setForceCutover(e.target.checked)}
                        className="rounded border-zinc-700 bg-zinc-900"
                      />
                      Force (override gate; emits audit event)
                    </label>
                  )}
                </div>
                {preview && (
                  <CutoverPreviewSummary preview={preview} forced={forceCutover} />
                )}
              </div>
            )}
          </div>
        </div>
      )}
    </section>
  );
};

const CutoverPreviewSummary: React.FC<{
  preview: CutoverPreview;
  forced: boolean;
}> = ({ preview, forced }) => {
  const total =
    preview.hosts_missing_pending.length +
    preview.hosts_never_installed.length +
    preview.hosts_stale_trust_record.length;

  if (total === 0) {
    return (
      <p className="text-xs text-green-400">
        Every known host trusts the pending key. Cutover will succeed.
      </p>
    );
  }
  return (
    <div className="rounded border border-yellow-900/40 bg-yellow-900/10 p-2 text-xs text-yellow-200">
      <div className="flex items-center gap-1 font-semibold">
        <AlertTriangle size={12} />
        {total} host{total === 1 ? '' : 's'} not yet trusting the pending key.
      </div>
      {preview.hosts_missing_pending.length > 0 && (
        <div className="mt-1">
          Missing pending fingerprint:{' '}
          <span className="font-mono">
            {preview.hosts_missing_pending.join(', ')}
          </span>
        </div>
      )}
      {forced ? (
        <div className="mt-1 text-yellow-300">
          Force is enabled - cutover will proceed and emit an audit event with
          the host counts above.
        </div>
      ) : (
        <div className="mt-1 text-gray-400">
          Run install-trust on those hosts before cutting over, or enable Force
          to override.
        </div>
      )}
    </div>
  );
};

export default SigningKeyPanel;
