import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import { Copy, KeyRound, Plus, RefreshCw, Trash2 } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { Badge, PageHeader } from '@/components/ui';
import { useAuth } from '@/context/AuthContext';
import {
  addImportTrustKey,
  bootstrapSigningKey,
  listImportTrustKeys,
  listSigningKeys,
  removeImportTrustKey,
  retireSigningKey,
  rotateSigningKey,
  signingKeyStatusLabel,
  signingKeyStatusVariant,
  type BundleSigningKey,
  type ImportTrustKey,
} from '@/services/airgapService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

async function copyToClipboard(text: string, label: string): Promise<void> {
  try {
    await navigator.clipboard.writeText(text);
    toast.success(`${label} copied to clipboard`);
  } catch {
    toast.error('Copy failed - select and copy manually');
  }
}

const AirgapPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const { isAdmin } = useAuth();

  const [signingKeys, setSigningKeys] = useState<BundleSigningKey[] | null>(null);
  const [signingError, setSigningError] = useState<string | null>(null);
  const [trustKeys, setTrustKeys] = useState<ImportTrustKey[] | null>(null);
  const [trustError, setTrustError] = useState<string | null>(null);

  const [bootstrapping, setBootstrapping] = useState(false);
  const [rotating, setRotating] = useState(false);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [retiringId, setRetiringId] = useState<number | null>(null);
  const [showActiveKey, setShowActiveKey] = useState(false);

  const [pinText, setPinText] = useState('');
  const [addingPin, setAddingPin] = useState(false);
  const [addPinError, setAddPinError] = useState<string | null>(null);
  const [showDeletedPins, setShowDeletedPins] = useState(false);
  const [removingId, setRemovingId] = useState<number | null>(null);

  const refreshSigning = useCallback(async () => {
    try {
      const data = await listSigningKeys();
      setSigningKeys(data);
      setSigningError(null);
    } catch (e) {
      setSigningError(e instanceof Error ? e.message : String(e));
    }
  }, []);

  const refreshTrust = useCallback(async () => {
    try {
      const data = await listImportTrustKeys(showDeletedPins);
      setTrustKeys(data);
      setTrustError(null);
    } catch (e) {
      setTrustError(e instanceof Error ? e.message : String(e));
    }
  }, [showDeletedPins]);

  useEffect(() => {
    refreshSigning();
  }, [refreshSigning]);

  useEffect(() => {
    refreshTrust();
  }, [refreshTrust]);

  const handleBootstrap = async () => {
    setBootstrapping(true);
    try {
      const res = await bootstrapSigningKey();
      toast.success(
        res.created
          ? `Signing key created (${res.fingerprint})`
          : 'Signing key already present'
      );
      refreshSigning();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to bootstrap signing key');
    } finally {
      setBootstrapping(false);
    }
  };

  const handleRotate = async () => {
    setRotating(true);
    try {
      const res = await rotateSigningKey();
      toast.success(`Rotated. New active key: ${res.new.fingerprint}`);
      setConfirmRotate(false);
      setShowActiveKey(true);
      refreshSigning();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to rotate signing key');
    } finally {
      setRotating(false);
    }
  };

  const handleRetire = async (key: BundleSigningKey) => {
    if (!window.confirm(`Retire key ${key.fingerprint}? It can no longer verify bundles.`)) {
      return;
    }
    setRetiringId(key.id);
    try {
      await retireSigningKey(key.id);
      toast.success(`Retired key ${key.fingerprint}`);
      refreshSigning();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to retire key');
    } finally {
      setRetiringId(null);
    }
  };

  const handleAddPin = async () => {
    const text = pinText.trim();
    if (!text) return;
    setAddingPin(true);
    setAddPinError(null);
    try {
      const pin = await addImportTrustKey(text);
      toast.success(`Pinned trust key ${pin.gpg_fingerprint}`);
      setPinText('');
      refreshTrust();
    } catch (e) {
      setAddPinError(e instanceof Error ? e.message : 'Failed to add trust pin');
    } finally {
      setAddingPin(false);
    }
  };

  const handleRemovePin = async (pin: ImportTrustKey) => {
    if (!window.confirm(`Remove trust pin ${pin.gpg_fingerprint}?`)) return;
    setRemovingId(pin.id);
    try {
      await removeImportTrustKey(pin.id);
      toast.success(`Removed trust pin ${pin.gpg_fingerprint}`);
      refreshTrust();
    } catch (e) {
      toast.error(e instanceof Error ? e.message : 'Failed to remove trust pin');
    } finally {
      setRemovingId(null);
    }
  };

  const activeKey = signingKeys?.find((k) => k.status === 'active') ?? null;
  const otherKeys = (signingKeys ?? []).filter((k) => k.status !== 'active');

  return (
    <MainLayout>
      <Head>
        <title>Airgap Signing Keys · Praxis</title>
      </Head>
      <div className="p-6">
        <PageHeader
          title="Airgap Signing Keys"
          subtitle="Manage the key that signs airgap export bundles and the public keys the import-side instance trusts. Rotate on the connected side, then pin the new public key on the airgapped side before importing bundles signed by it."
        />

        {/* ---------------------------------------------------------------- */}
        {/* Section A - Bundle Signing Keys (export / connected side)         */}
        {/* ---------------------------------------------------------------- */}
        <section className="mb-8">
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-300">
            Bundle signing keys
          </h2>
          <p className="mb-3 text-xs text-gray-500">
            This is the export/connected side. The active key signs every bundle
            you export. Rotating mints a new active key; the old one keeps
            verifying already-exported bundles until you retire it.
          </p>

          {signingError && (
            <div className="mb-4 rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-300">
              {signingError}
            </div>
          )}

          {signingKeys === null && !signingError && (
            <div className="text-gray-400">Loading…</div>
          )}

          {signingKeys !== null && signingKeys.length === 0 && !signingError && (
            <div className="rounded border border-zinc-800 bg-[#111115] p-6 text-sm text-gray-400">
              <div className="mb-3">No signing key yet.</div>
              {isAdmin ? (
                <button
                  onClick={handleBootstrap}
                  disabled={bootstrapping}
                  className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <KeyRound size={16} /> {bootstrapping ? 'Bootstrapping…' : 'Bootstrap key'}
                </button>
              ) : (
                <span className="text-gray-500">An admin must bootstrap the signing key.</span>
              )}
            </div>
          )}

          {activeKey && (
            <div className="mb-4 rounded border border-zinc-800 bg-[#111115] p-4">
              <div className="flex flex-wrap items-start justify-between gap-3">
                <div className="min-w-0">
                  <div className="mb-1 flex items-center gap-2">
                    <Badge variant={signingKeyStatusVariant(activeKey.status)}>
                      {signingKeyStatusLabel(activeKey.status)}
                    </Badge>
                    <span className="text-xs text-gray-500">
                      Created {formatTimestamp(activeKey.created_at) || '-'}
                    </span>
                  </div>
                  <div className="break-all font-mono text-sm text-gray-200">
                    {activeKey.fingerprint}
                  </div>
                  <div className="break-all text-xs text-gray-500">{activeKey.key_uid}</div>
                </div>
                {isAdmin && (
                  <button
                    onClick={() => setConfirmRotate(true)}
                    disabled={rotating}
                    className="inline-flex items-center gap-1 rounded border border-zinc-700 px-3 py-1.5 text-sm text-gray-200 hover:bg-zinc-800 disabled:opacity-40"
                  >
                    <RefreshCw size={16} className={rotating ? 'animate-spin' : ''} /> Rotate
                  </button>
                )}
              </div>

              {activeKey.armored_public_key && (
                <div className="mt-3">
                  <div className="flex flex-wrap items-center gap-2">
                    <button
                      onClick={() =>
                        copyToClipboard(activeKey.armored_public_key ?? '', 'Public key')
                      }
                      className="inline-flex items-center gap-1 rounded border border-zinc-700 px-2.5 py-1 text-xs text-gray-200 hover:bg-zinc-800"
                    >
                      <Copy size={14} /> Copy public key
                    </button>
                    <button
                      onClick={() => setShowActiveKey((v) => !v)}
                      className="rounded px-2 py-1 text-xs text-blue-400 hover:text-blue-300"
                    >
                      {showActiveKey ? 'Hide public key' : 'Show public key'}
                    </button>
                    <span className="text-xs text-gray-500">
                      Distribute this to the airgapped instance and pin it below.
                    </span>
                  </div>
                  {showActiveKey && (
                    <textarea
                      readOnly
                      value={activeKey.armored_public_key}
                      rows={8}
                      className="mt-2 w-full rounded bg-black/40 px-2 py-1 font-mono text-xs text-gray-300"
                    />
                  )}
                </div>
              )}

              {confirmRotate && (
                <div className="mt-3 rounded border border-yellow-900/40 bg-yellow-900/10 p-3">
                  <p className="text-sm text-yellow-200">
                    Rotating generates a new active signing key. Bundles you export
                    <strong> after</strong> rotating are signed by the <strong>new</strong> key
                    - the import-side instance must <strong>pin the new public key</strong>{' '}
                    (below / on the airgapped side) <strong>before</strong> importing those
                    bundles. The old key stays valid for verifying already-exported bundles
                    until you retire it.
                  </p>
                  <div className="mt-3 flex gap-2">
                    <button
                      onClick={handleRotate}
                      disabled={rotating}
                      className="rounded bg-yellow-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-yellow-500 disabled:opacity-40"
                    >
                      {rotating ? 'Rotating…' : 'Rotate now'}
                    </button>
                    <button
                      onClick={() => setConfirmRotate(false)}
                      disabled={rotating}
                      className="rounded border border-zinc-700 px-3 py-1.5 text-sm text-gray-300 hover:bg-zinc-800 disabled:opacity-40"
                    >
                      Cancel
                    </button>
                  </div>
                </div>
              )}
            </div>
          )}

          {otherKeys.length > 0 && (
            <div className="overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
              <table className="w-full text-sm">
                <thead className="border-b border-zinc-800 text-left text-gray-400">
                  <tr>
                    <th className="px-4 py-2">Fingerprint</th>
                    <th className="px-4 py-2">Status</th>
                    <th className="px-4 py-2">Created</th>
                    <th className="px-4 py-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {otherKeys.map((k) => (
                    <tr key={k.id} className="hover:bg-zinc-900/40">
                      <td className="px-4 py-2 font-mono text-gray-300">
                        <div className="break-all">{k.fingerprint}</div>
                        <div className="break-all text-xs text-gray-500">{k.key_uid}</div>
                      </td>
                      <td className="px-4 py-2">
                        <Badge variant={signingKeyStatusVariant(k.status)}>
                          {signingKeyStatusLabel(k.status)}
                        </Badge>
                      </td>
                      <td className="px-4 py-2 text-gray-400">
                        {formatTimestamp(k.created_at) || '-'}
                      </td>
                      <td className="px-4 py-2 text-right">
                        {k.armored_public_key && (
                          <button
                            onClick={() =>
                              copyToClipboard(k.armored_public_key ?? '', 'Public key')
                            }
                            className="inline-flex items-center gap-1 rounded p-1 text-gray-400 hover:text-blue-400"
                            title="Copy public key"
                          >
                            <Copy size={16} />
                          </button>
                        )}
                        {isAdmin && k.status === 'rotating_out' && (
                          <button
                            onClick={() => handleRetire(k)}
                            disabled={retiringId === k.id}
                            className="ml-1 inline-flex items-center gap-1 rounded p-1 text-gray-400 hover:text-red-400 disabled:opacity-30"
                            title="Retire key"
                          >
                            <Trash2 size={16} />
                          </button>
                        )}
                      </td>
                    </tr>
                  ))}
                </tbody>
              </table>
            </div>
          )}
        </section>

        {/* ---------------------------------------------------------------- */}
        {/* Section B - Import Trust Pins (airgapped / import side)           */}
        {/* ---------------------------------------------------------------- */}
        <section>
          <h2 className="mb-2 text-sm font-semibold uppercase tracking-wide text-gray-300">
            Import trust pins
          </h2>
          <p className="mb-3 text-xs text-gray-500">
            This is the airgapped/import side. Pin the new public key{' '}
            <strong>before</strong> importing bundles signed by it; remove the old pin only
            after you no longer import bundles signed by that key.
          </p>

          {trustError && (
            <div className="mb-4 rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-300">
              {trustError}
            </div>
          )}

          {isAdmin && (
            <div className="mb-4 rounded border border-zinc-800 bg-[#111115] p-4">
              <label className="text-xs text-gray-400">
                Armored PGP public key block
                <textarea
                  className="mt-1 w-full rounded bg-black/40 px-2 py-1 font-mono text-xs text-gray-100"
                  rows={6}
                  value={pinText}
                  onChange={(e) => {
                    setPinText(e.target.value);
                    if (addPinError) setAddPinError(null);
                  }}
                  placeholder={'-----BEGIN PGP PUBLIC KEY BLOCK-----\n…\n-----END PGP PUBLIC KEY BLOCK-----'}
                />
              </label>
              {addPinError && (
                <div className="mt-2 rounded border border-red-900/40 bg-red-900/10 p-2 text-xs text-red-300">
                  {addPinError}
                </div>
              )}
              <div className="mt-3">
                <button
                  onClick={handleAddPin}
                  disabled={addingPin || !pinText.trim()}
                  className="inline-flex items-center gap-1 rounded bg-blue-600 px-3 py-1.5 text-sm font-medium text-white hover:bg-blue-500 disabled:opacity-40"
                >
                  <Plus size={16} /> {addingPin ? 'Adding…' : 'Add trust pin'}
                </button>
              </div>
            </div>
          )}

          <div className="mb-2 flex items-center justify-between">
            <label className="flex items-center gap-2 text-xs text-gray-400">
              <input
                type="checkbox"
                checked={showDeletedPins}
                onChange={(e) => setShowDeletedPins(e.target.checked)}
              />
              Show removed pins
            </label>
          </div>

          {trustKeys === null && !trustError && (
            <div className="text-gray-400">Loading…</div>
          )}

          {trustKeys !== null && trustKeys.length === 0 && !trustError && (
            <div className="rounded border border-zinc-800 bg-[#111115] p-6 text-sm text-gray-400">
              No import trust pins yet.
              {isAdmin
                ? ' Paste an armored public key above to pin one.'
                : ' An admin can pin a public key here.'}
            </div>
          )}

          {trustKeys && trustKeys.length > 0 && (
            <div className="overflow-x-auto rounded border border-zinc-800 bg-[#111115]">
              <table className="w-full text-sm">
                <thead className="border-b border-zinc-800 text-left text-gray-400">
                  <tr>
                    <th className="px-4 py-2">Fingerprint</th>
                    <th className="px-4 py-2">Key UID</th>
                    <th className="px-4 py-2">Added</th>
                    <th className="px-4 py-2 text-right">Actions</th>
                  </tr>
                </thead>
                <tbody className="divide-y divide-zinc-800">
                  {trustKeys.map((pin) => {
                    const removed = pin.deleted_at !== null;
                    return (
                      <tr
                        key={pin.id}
                        className={removed ? 'opacity-50' : 'hover:bg-zinc-900/40'}
                      >
                        <td className="px-4 py-2 font-mono text-gray-300">
                          <div className="break-all">{pin.gpg_fingerprint}</div>
                          {removed && (
                            <div className="text-xs text-gray-500">
                              Removed {formatTimestamp(pin.deleted_at) || '-'}
                            </div>
                          )}
                        </td>
                        <td className="px-4 py-2 break-all text-gray-400">{pin.key_uid}</td>
                        <td className="px-4 py-2 text-gray-400">
                          {formatTimestamp(pin.added_at) || '-'}
                        </td>
                        <td className="px-4 py-2 text-right">
                          {isAdmin && !removed && (
                            <button
                              onClick={() => handleRemovePin(pin)}
                              disabled={removingId === pin.id}
                              className="inline-flex items-center gap-1 rounded p-1 text-gray-400 hover:text-red-400 disabled:opacity-30"
                              title="Remove trust pin"
                            >
                              <Trash2 size={16} />
                            </button>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
        </section>
      </div>
    </MainLayout>
  );
};

export default AirgapPage;
