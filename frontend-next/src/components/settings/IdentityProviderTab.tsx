import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { apiFetch, formatApiError } from '@/utils/api';
import { Shield, Trash2, TestTube, Save, Plus, X } from 'lucide-react';
import { Button } from '@/components/ui';

interface OIDCProvider {
  id: number;
  name: string;
  discovery_url: string;
  client_id: string;
  role_claim: string;
  role_mapping: Record<string, string> | null;
  enabled: boolean;
  created_at: string | null;
  updated_at: string | null;
}

interface FormData {
  name: string;
  discovery_url: string;
  client_id: string;
  client_secret: string;
  role_claim: string;
  role_mapping: string;
  enabled: boolean;
}

const emptyForm: FormData = {
  name: '',
  discovery_url: '',
  client_id: '',
  client_secret: '',
  role_claim: 'roles',
  role_mapping: '{"admin": "admin", "user": "auditor"}',
  enabled: false,
};

const IdentityProviderTab: React.FC = () => {
  const [providers, setProviders] = useState<OIDCProvider[]>([]);
  const [loading, setLoading] = useState(true);
  const [editing, setEditing] = useState<number | 'new' | null>(null);
  const [formData, setFormData] = useState<FormData>(emptyForm);
  const [saving, setSaving] = useState(false);
  const [testing, setTesting] = useState(false);
  const [testResult, setTestResult] = useState<{success: boolean; issuer?: string; error?: string} | null>(null);

  const loadProviders = async () => {
    try {
      setLoading(true);
      const res = await apiFetch('/api/backend/auth/oidc/providers');
      if (res.ok) {
        setProviders(await res.json());
      }
    } catch (err) {
      console.error('Error loading providers:', err);
    } finally {
      setLoading(false);
    }
  };

  useEffect(() => {
    loadProviders();
  }, []);

  const handleEdit = (provider: OIDCProvider) => {
    setEditing(provider.id);
    setFormData({
      name: provider.name,
      discovery_url: provider.discovery_url,
      client_id: provider.client_id,
      client_secret: '',
      role_claim: provider.role_claim,
      role_mapping: provider.role_mapping ? JSON.stringify(provider.role_mapping, null, 2) : '{}',
      enabled: provider.enabled,
    });
    setTestResult(null);
  };

  const handleNew = () => {
    setEditing('new');
    setFormData(emptyForm);
    setTestResult(null);
  };

  const handleCancel = () => {
    setEditing(null);
    setTestResult(null);
  };

  const handleTest = async () => {
    if (!formData.discovery_url) {
      toast.error('Discovery URL is required');
      return;
    }
    setTesting(true);
    setTestResult(null);
    try {
      const res = await apiFetch(`/api/backend/auth/oidc/providers/test?discovery_url=${encodeURIComponent(formData.discovery_url)}`, { method: 'POST' });
      const result = await res.json();
      setTestResult(result);
      if (result.success) {
        toast.success(`Connected to ${result.issuer}`);
      } else {
        toast.error(`Connection failed: ${result.error}`);
      }
    } catch {
      toast.error('Connection test failed');
    } finally {
      setTesting(false);
    }
  };

  const handleSave = async () => {
    if (!formData.name || !formData.discovery_url || !formData.client_id) {
      toast.error('Name, Discovery URL, and Client ID are required');
      return;
    }

    // Validate role_mapping JSON
    let roleMapping = null;
    if (formData.role_mapping.trim()) {
      try {
        roleMapping = JSON.parse(formData.role_mapping);
      } catch {
        toast.error('Role mapping must be valid JSON');
        return;
      }
    }

    setSaving(true);
    try {
      const body: Record<string, unknown> = {
        name: formData.name,
        discovery_url: formData.discovery_url,
        client_id: formData.client_id,
        role_claim: formData.role_claim,
        role_mapping: roleMapping,
        enabled: formData.enabled,
      };
      if (formData.client_secret) {
        body.client_secret = formData.client_secret;
      }

      let res;
      if (editing === 'new') {
        if (!formData.client_secret) {
          toast.error('Client Secret is required for new providers');
          setSaving(false);
          return;
        }
        res = await apiFetch('/api/backend/auth/oidc/providers', {
          method: 'POST',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
      } else {
        res = await apiFetch(`/api/backend/auth/oidc/providers/${editing}`, {
          method: 'PUT',
          headers: { 'Content-Type': 'application/json' },
          body: JSON.stringify(body),
        });
      }

      if (res.ok) {
        toast.success(editing === 'new' ? 'Provider created' : 'Provider updated');
        setEditing(null);
        loadProviders();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to save provider'));
      }
    } catch {
      toast.error('Failed to save provider');
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async (id: number) => {
    if (!confirm('Delete this identity provider?')) return;
    try {
      const res = await apiFetch(`/api/backend/auth/oidc/providers/${id}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success('Provider deleted');
        loadProviders();
      }
    } catch {
      toast.error('Failed to delete provider');
    }
  };

  const handleToggle = async (provider: OIDCProvider) => {
    try {
      const res = await apiFetch(`/api/backend/auth/oidc/providers/${provider.id}`, {
        method: 'PUT',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ enabled: !provider.enabled }),
      });
      if (res.ok) {
        toast.success(provider.enabled ? 'Provider disabled' : 'Provider enabled');
        loadProviders();
      }
    } catch {
      toast.error('Failed to toggle provider');
    }
  };

  if (loading) {
    return <div className="text-gray-400 p-4">Loading identity providers...</div>;
  }

  // Editing form
  if (editing !== null) {
    return (
      <div className="bg-[#0c0c0f] border border-gray-800/60 rounded-lg p-6">
        <div className="flex items-center justify-between mb-6">
          <h3 className="text-lg font-semibold text-gray-100">
            {editing === 'new' ? 'Add Identity Provider' : 'Edit Identity Provider'}
          </h3>
          <button onClick={handleCancel} className="text-gray-400 hover:text-gray-200">
            <X size={20} />
          </button>
        </div>

        <div className="space-y-4">
          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Provider Name</label>
            <input
              type="text"
              value={formData.name}
              onChange={(e) => setFormData({ ...formData, name: e.target.value })}
              placeholder="e.g., Okta, Azure AD, Keycloak"
              className="w-full px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
            />
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Discovery URL</label>
            <div className="flex gap-2">
              <input
                type="text"
                value={formData.discovery_url}
                onChange={(e) => setFormData({ ...formData, discovery_url: e.target.value })}
                placeholder="https://your-provider.com/.well-known/openid-configuration"
                className="flex-1 px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
              />
              <Button
                variant="outline"
                onClick={handleTest}
                disabled={testing}
                loading={testing}
                icon={<TestTube size={16} />}
              >
                {testing ? 'Testing...' : 'Test'}
              </Button>
            </div>
            {testResult && (
              <div className={`mt-2 p-2 rounded text-sm ${testResult.success ? 'bg-green-900/30 text-green-400' : 'bg-red-900/30 text-red-400'}`}>
                {testResult.success ? `Connected to ${testResult.issuer}` : `Failed: ${testResult.error}`}
              </div>
            )}
          </div>

          <div className="grid grid-cols-2 gap-4">
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">Client ID</label>
              <input
                type="text"
                value={formData.client_id}
                onChange={(e) => setFormData({ ...formData, client_id: e.target.value })}
                className="w-full px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
              />
            </div>
            <div>
              <label className="block text-sm font-medium text-gray-300 mb-1">
                Client Secret {editing !== 'new' && <span className="text-gray-500">(leave blank to keep current)</span>}
              </label>
              <input
                type="password"
                value={formData.client_secret}
                onChange={(e) => setFormData({ ...formData, client_secret: e.target.value })}
                className="w-full px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
              />
            </div>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Role Claim</label>
            <input
              type="text"
              value={formData.role_claim}
              onChange={(e) => setFormData({ ...formData, role_claim: e.target.value })}
              placeholder="roles, groups, resource_access.praxis.roles"
              className="w-full px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
            />
            <p className="mt-1 text-xs text-gray-500">
              JWT claim containing user roles. Supports dot notation for nested claims.
            </p>
          </div>

          <div>
            <label className="block text-sm font-medium text-gray-300 mb-1">Role Mapping (JSON)</label>
            <textarea
              value={formData.role_mapping}
              onChange={(e) => setFormData({ ...formData, role_mapping: e.target.value })}
              rows={4}
              placeholder='{"admin_group": "admin", "users": "maintainer", "viewers": "auditor"}'
              className="w-full px-3 py-2 bg-[#09090b] border border-gray-700/60 rounded-md text-gray-200 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600 font-mono text-sm"
            />
            <p className="mt-1 text-xs text-gray-500">
              Maps provider role/group values to Praxis roles (admin, maintainer, auditor).
            </p>
          </div>

          <div className="flex items-center gap-2">
            <input
              type="checkbox"
              id="enabled"
              checked={formData.enabled}
              onChange={(e) => setFormData({ ...formData, enabled: e.target.checked })}
              className="rounded border-gray-700"
            />
            <label htmlFor="enabled" className="text-sm text-gray-300">
              Enable SSO login
            </label>
          </div>

          <div className="flex justify-end gap-3 pt-4 border-t border-gray-800/60">
            <Button variant="outline" onClick={handleCancel}>
              Cancel
            </Button>
            <Button
              variant="primary"
              onClick={handleSave}
              disabled={saving}
              loading={saving}
              icon={<Save size={16} />}
            >
              {saving ? 'Saving...' : 'Save'}
            </Button>
          </div>
        </div>
      </div>
    );
  }

  // Provider list
  return (
    <div>
      <div className="flex items-center justify-between mb-4">
        <div>
          <h3 className="text-lg font-semibold text-gray-100">Identity Provider</h3>
          <p className="text-sm text-gray-400">Configure OIDC/OAuth2 single sign-on</p>
        </div>
        <Button variant="primary" onClick={handleNew} icon={<Plus size={16} />}>
          Add Provider
        </Button>
      </div>

      {providers.length === 0 ? (
        <div className="bg-[#0c0c0f] border border-gray-800/60 rounded-lg p-8 text-center">
          <Shield size={48} className="mx-auto text-gray-600 mb-4" />
          <p className="text-gray-400 mb-2">No identity provider configured</p>
          <p className="text-sm text-gray-500">
            Add an OIDC provider to enable single sign-on alongside local authentication.
          </p>
        </div>
      ) : (
        <div className="space-y-3">
          {providers.map((provider) => (
            <div
              key={provider.id}
              className="bg-[#0c0c0f] border border-gray-800/60 rounded-lg p-4 flex items-center justify-between"
            >
              <div className="flex items-center gap-4">
                <Shield size={24} className={provider.enabled ? 'text-green-400' : 'text-gray-600'} />
                <div>
                  <div className="flex items-center gap-2">
                    <span className="text-gray-100 font-medium">{provider.name}</span>
                    <span className={`px-2 py-0.5 text-xs rounded-full ${provider.enabled ? 'bg-green-900/30 text-green-400' : 'bg-gray-800 text-gray-500'}`}>
                      {provider.enabled ? 'Enabled' : 'Disabled'}
                    </span>
                  </div>
                  <div className="text-sm text-gray-500 mt-1">
                    {provider.discovery_url}
                  </div>
                  <div className="text-xs text-gray-600 mt-1">
                    Client ID: {provider.client_id} | Claim: {provider.role_claim}
                  </div>
                </div>
              </div>
              <div className="flex items-center gap-2">
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleToggle(provider)}
                >
                  {provider.enabled ? 'Disable' : 'Enable'}
                </Button>
                <Button
                  variant="outline"
                  size="sm"
                  onClick={() => handleEdit(provider)}
                >
                  Edit
                </Button>
                <Button
                  variant="danger"
                  size="sm"
                  onClick={() => handleDelete(provider.id)}
                  icon={<Trash2 size={14} />}
                />
              </div>
            </div>
          ))}
        </div>
      )}
    </div>
  );
};

export default IdentityProviderTab;
