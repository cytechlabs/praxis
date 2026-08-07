import React, { useEffect, useState } from 'react';
import { toast } from 'sonner';
import { apiFetch, formatApiError } from '@/utils/api';
import { Key, Save, Copy, RotateCcw, ShieldOff, History } from 'lucide-react';
import { Button } from '@/components/ui';

interface IdentitySettings {
  user_cert_ttl_seconds: number;
  default_principal: string | null;
  ca_identifier: string | null;
  ca_public_key: string | null;
}

interface Rotation {
  id: number;
  event_type: 'rotate' | 'revoke';
  ca_identifier: string | null;
  performed_by: number | null;
  performed_at: string | null;
}

const DEFAULTS = {
  user_cert_ttl_seconds: 300,
  default_principal: '',
};

const SSHIdentityTab: React.FC = () => {
  const [settings, setSettings] = useState<IdentitySettings | null>(null);
  const [ttl, setTtl] = useState(DEFAULTS.user_cert_ttl_seconds);
  const [principal, setPrincipal] = useState('');
  const [loading, setLoading] = useState(true);
  const [saving, setSaving] = useState(false);
  const [rotations, setRotations] = useState<Rotation[]>([]);
  const [rotating, setRotating] = useState(false);
  const [revoking, setRevoking] = useState(false);
  const [confirmRotate, setConfirmRotate] = useState(false);
  const [confirmRevoke, setConfirmRevoke] = useState(false);

  useEffect(() => {
    load();
    loadRotations();
  }, []);

  const loadRotations = async () => {
    try {
      const res = await apiFetch('/api/backend/ssh-identity/rotations');
      if (res.ok) setRotations((await res.json()).rotations || []);
    } catch { /* ignore */ }
  };

  const doRotate = async () => {
    setConfirmRotate(false);
    setRotating(true);
    try {
      const res = await apiFetch('/api/backend/ssh-identity/rotate-ca', { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Rotation failed'));
      }
      const data = await res.json();
      toast.success(`CA rotated - ${data.systems_flagged_for_redeploy} system(s) need redeploy`);
      load(); loadRotations();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Rotation failed');
    } finally { setRotating(false); }
  };

  const doRevoke = async () => {
    setConfirmRevoke(false);
    setRevoking(true);
    try {
      const res = await apiFetch('/api/backend/ssh-identity/revoke-user-certs', { method: 'POST' });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Revoke failed'));
      }
      toast.success('User cert pool cleared; new ops will force fresh signing');
      load(); loadRotations();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Revoke failed');
    } finally { setRevoking(false); }
  };

  const load = async () => {
    try {
      const res = await apiFetch('/api/backend/ssh-identity/settings');
      if (!res.ok) throw new Error('Failed to load settings');
      const data = await res.json();
      setSettings(data);
      setTtl(data.user_cert_ttl_seconds);
      setPrincipal(data.default_principal || '');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load');
    } finally {
      setLoading(false);
    }
  };

  const handleSave = async () => {
    setSaving(true);
    try {
      const res = await apiFetch('/api/backend/ssh-identity/settings', {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          user_cert_ttl_seconds: ttl,
          default_principal: principal || null,
        }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Failed'));
      }
      const data = await res.json();
      setSettings(data);
      toast.success('SSH identity settings saved');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to save');
    } finally {
      setSaving(false);
    }
  };

  const copyToClipboard = (text: string) => {
    navigator.clipboard.writeText(text);
    toast.success('Copied to clipboard');
  };

  if (loading) {
    return <div className="flex items-center justify-center py-12"><div className="animate-spin rounded-full h-8 w-8 border-b-2 border-red-500" /></div>;
  }

  const hasChanges = ttl !== settings?.user_cert_ttl_seconds || principal !== (settings?.default_principal || '');

  return (
    <div>
      <div className="flex items-center gap-3 mb-6">
        <Key className="text-red-500" size={24} />
        <div>
          <h2 className="text-lg font-semibold text-gray-200">SSH Identity (Zero-Trust CA)</h2>
          <p className="text-sm text-gray-400">
            Configure the Vault-signed SSH certificate issued for each connection.
          </p>
        </div>
      </div>

      {/* Settings */}
      <div className="bg-[#0c0c0f] border border-gray-800/60 rounded-lg p-4 mb-6">
        <div className="mb-4">
          <label className="block text-sm font-medium text-gray-200 mb-1">User Certificate TTL (seconds)</label>
          <p className="text-xs text-gray-400 mb-2">How long each signed user certificate is valid. Short TTLs are preferred (300s = 5 min).</p>
          <div className="flex items-center gap-2">
            <input type="number" value={ttl} onChange={(e) => setTtl(parseInt(e.target.value) || 60)}
              min={60} max={3600}
              className="w-32 bg-[#09090b] border border-gray-700/60 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600" />
            <span className="text-xs text-gray-500">Range: 60 – 3600</span>
          </div>
        </div>

        <div>
          <label className="block text-sm font-medium text-gray-200 mb-1">Default Principal</label>
          <p className="text-xs text-gray-400 mb-2">
            Linux username authorized by the signed cert. Leave blank to use each system&apos;s credential username.
          </p>
          <input value={principal} onChange={(e) => setPrincipal(e.target.value)}
            placeholder="e.g. praxis-agent (blank = per-credential username)"
            className="w-full bg-[#09090b] border border-gray-700/60 rounded px-3 py-1.5 text-sm text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600" />
        </div>
      </div>

      {/* CA info (read-only) */}
      <div className="bg-[#0c0c0f] border border-gray-800/60 rounded-lg p-4 mb-6">
        <h3 className="text-sm font-semibold text-gray-300 mb-3">Vault SSH CA</h3>

        <div className="mb-3">
          <label className="block text-xs text-gray-400 mb-1">CA Identifier</label>
          <code className="block text-xs bg-[#09090b] px-3 py-2 rounded text-gray-300">
            {settings?.ca_identifier || '(not set)'}
          </code>
        </div>

        <div>
          <div className="flex items-center justify-between mb-1">
            <label className="text-xs text-gray-400">CA Public Key</label>
            {settings?.ca_public_key && (
              <Button variant="ghost" size="sm" onClick={() => copyToClipboard(settings.ca_public_key!)}
                icon={<Copy size={12} />}>
                Copy
              </Button>
            )}
          </div>
          {settings?.ca_public_key ? (
            <code className="block text-xs bg-[#09090b] px-3 py-2 rounded text-gray-300 break-all font-mono">
              {settings.ca_public_key}
            </code>
          ) : (
            <div className="text-xs text-yellow-500 bg-[#09090b] px-3 py-2 rounded">
              Vault SSH CA not available - check Vault configuration.
            </div>
          )}
        </div>
      </div>

      <div className="flex justify-end pt-4 border-t border-gray-800/60">
        <Button variant="primary" onClick={handleSave} disabled={!hasChanges || saving}
          loading={saving} icon={<Save size={14} />}>
          {saving ? 'Saving...' : 'Save Settings'}
        </Button>
      </div>

      {/* Destructive actions (PRA-128) */}
      <div className="mt-8 border border-red-900/40 rounded-lg p-4 bg-red-900/5 space-y-3">
        <h3 className="text-sm font-semibold text-red-300">Danger zone</h3>
        <div className="flex flex-wrap gap-3">
          <Button variant="outline" icon={<RotateCcw size={14} />} onClick={() => setConfirmRotate(true)} disabled={rotating}>
            Rotate CA
          </Button>
          <Button variant="outline" icon={<ShieldOff size={14} />} onClick={() => setConfirmRevoke(true)} disabled={revoking}>
            Revoke all user certs
          </Button>
        </div>
        <p className="text-xs text-gray-500">
          Rotating regenerates the Vault SSH CA and flags every system for redeploy. Revoking drops pooled SSH
          sessions so new operations force fresh cert signing - existing short-lived certs complete their TTL.
        </p>
      </div>

      {/* Rotation history */}
      {rotations.length > 0 && (
        <div className="mt-6 border border-gray-800/60 rounded-lg overflow-hidden">
          <div className="px-4 py-2 bg-[#0c0c0f] border-b border-gray-800/60 flex items-center gap-2 text-sm text-gray-300">
            <History size={14} /> Rotation history
          </div>
          <table className="w-full text-xs text-gray-300">
            <thead className="bg-[#0c0c0f] text-gray-500">
              <tr>
                <th className="px-3 py-2 text-left">When</th>
                <th className="px-3 py-2 text-left">Event</th>
                <th className="px-3 py-2 text-left">CA Identifier</th>
                <th className="px-3 py-2 text-left">By (user id)</th>
              </tr>
            </thead>
            <tbody className="divide-y divide-gray-800/50">
              {rotations.map(r => (
                <tr key={r.id} className="hover:bg-white/[0.03]">
                  <td className="px-3 py-2 text-gray-400">{r.performed_at || '-'}</td>
                  <td className="px-3 py-2">
                    <span className={`px-1.5 py-0.5 rounded text-xs ${r.event_type === 'rotate' ? 'bg-red-900/50 text-red-200' : 'bg-amber-900/50 text-amber-200'}`}>
                      {r.event_type}
                    </span>
                  </td>
                  <td className="px-3 py-2 font-mono">{r.ca_identifier || '-'}</td>
                  <td className="px-3 py-2">{r.performed_by ?? '-'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        </div>
      )}

      {/* Confirm modals */}
      {confirmRotate && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={() => setConfirmRotate(false)}>
          <div className="bg-[#0c0c0f] border border-red-900/60 rounded-lg p-6 max-w-md space-y-4" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-bold text-red-300">Rotate SSH CA?</h3>
            <p className="text-sm text-gray-300">
              This regenerates the Vault SSH CA keypair. All existing signed user certs become unusable
              immediately. Every system is flagged for redeploy - admins must redeploy CA trust to restore
              cert-based SSH. Password auth is unaffected.
            </p>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setConfirmRotate(false)}>Cancel</Button>
              <Button variant="primary" onClick={doRotate} loading={rotating}>Rotate</Button>
            </div>
          </div>
        </div>
      )}

      {confirmRevoke && (
        <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/70" onClick={() => setConfirmRevoke(false)}>
          <div className="bg-[#0c0c0f] border border-amber-900/60 rounded-lg p-6 max-w-md space-y-4" onClick={e => e.stopPropagation()}>
            <h3 className="text-lg font-bold text-amber-300">Revoke all user certs?</h3>
            <p className="text-sm text-gray-300">
              Drops every pooled SSH session so new operations force fresh cert signing. Existing short-lived
              certs complete their TTL naturally. The Vault CA is unchanged.
            </p>
            <div className="flex justify-end gap-2">
              <Button variant="outline" onClick={() => setConfirmRevoke(false)}>Cancel</Button>
              <Button variant="primary" onClick={doRevoke} loading={revoking}>Revoke</Button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default SSHIdentityTab;
