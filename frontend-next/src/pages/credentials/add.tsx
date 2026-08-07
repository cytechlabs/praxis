import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { apiFetch, formatApiError } from '../../utils/api';
import { useAuth } from '../../context/AuthContext';
import { useRouter } from 'next/router';
import MainLayout from '@/components/MainLayout';
import { listKVStores, listSecrets, getSecret } from '@/services/vaultService';
import { PageHeader, Button, Card, CardBody, Input, Select } from '@/components/ui';
import { Key, Lock, Database, ChevronDown, Search, Save, Plus, Link2 } from 'lucide-react';
import Link from 'next/link';
import Head from 'next/head';

type CreationMode = 'managed' | 'linked';
type AuthMethod = 'password' | 'ssh_key';

interface CredentialFormData {
  name: string;
  auth_method: string;
  username: string;
  password: string;
  ssh_key: string;
  vault_path: string;
  sudo_method: string;
  sudo_password: string;
}

interface SecretDataType {
  path: string;
  data: Record<string, unknown>;
  metadata: {
    created_time: string;
    current_version: number;
    versions: Record<string, { created_time: string }>;
  };
}

const AddCredentialPage: React.FC = () => {
  const { user, canWrite } = useAuth();
  const router = useRouter();
  const [loading, setLoading] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [mode, setMode] = useState<CreationMode>('managed');
  const [authMethod, setAuthMethod] = useState<AuthMethod>('password');

  // Linked-mode vault picker state
  const [kvStores, setKvStores] = useState<string[]>([]);
  const [selectedKvStore, setSelectedKvStore] = useState<string>('');
  const [secrets, setSecrets] = useState<string[]>([]);
  const [secretSearch, setSecretSearch] = useState<string>('');
  const [selectedSecret, setSelectedSecret] = useState<string>('');
  const [secretData, setSecretData] = useState<SecretDataType | null>(null);
  const [loadingVault, setLoadingVault] = useState<boolean>(false);
  const [vaultError, setVaultError] = useState<string | null>(null);
  const [showSecretSelector, setShowSecretSelector] = useState<boolean>(false);

  const [formData, setFormData] = useState<CredentialFormData>({
    name: '',
    auth_method: 'password',
    username: '',
    password: '',
    ssh_key: '',
    vault_path: '',
    sudo_method: 'none',
    sudo_password: '',
  });

  useEffect(() => {
    if (mode !== 'linked' || !user) return;
    const loadStores = async () => {
      try {
        setLoadingVault(true);
        setVaultError(null);
        const stores = await listKVStores();
        setKvStores(stores);
        if (stores.length > 0 && !selectedKvStore) {
          setSelectedKvStore(stores[0]);
        }
      } catch (err) {
        setVaultError(err instanceof Error ? err.message : 'Failed to load KV stores');
      } finally {
        setLoadingVault(false);
      }
    };
    loadStores();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user, mode]);

  useEffect(() => {
    if (mode !== 'linked' || !user || !selectedKvStore) return;
    const loadSecrets = async () => {
      try {
        setLoadingVault(true);
        setVaultError(null);
        const result = await listSecrets(selectedKvStore);
        setSecrets(result.secrets);
      } catch (err) {
        setVaultError(err instanceof Error ? err.message : 'Failed to load secrets');
      } finally {
        setLoadingVault(false);
      }
    };
    loadSecrets();
  }, [selectedKvStore, user, mode]);

  useEffect(() => {
    if (mode !== 'linked' || !user || !selectedSecret) return;
    const loadSecretData = async () => {
      try {
        setLoadingVault(true);
        setVaultError(null);
        const data = await getSecret(selectedSecret);
        setSecretData(data);
        setFormData((prev) => ({
          ...prev,
          vault_path: selectedSecret,
          name: prev.name || selectedSecret.split('/').pop() || '',
        }));
      } catch (err) {
        setVaultError(err instanceof Error ? err.message : 'Failed to load secret data');
      } finally {
        setLoadingVault(false);
      }
    };
    loadSecretData();
  }, [selectedSecret, user, mode]);

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleModeChange = (next: CreationMode) => {
    setMode(next);
    setError(null);
    setFieldErrors({});
    if (next === 'managed') {
      setFormData((prev) => ({ ...prev, vault_path: '' }));
      setSelectedSecret('');
      setSecretData(null);
    } else {
      setFormData((prev) => ({ ...prev, password: '', ssh_key: '', auth_method: 'password' }));
      setAuthMethod('password');
    }
  };

  const handleAuthMethodChange = (next: AuthMethod) => {
    setAuthMethod(next);
    setFormData((prev) => ({
      ...prev,
      auth_method: next,
      ...(next === 'password' ? { ssh_key: '' } : { password: '' }),
    }));
  };

  const handleSelectSecret = (path: string) => {
    setSelectedSecret(`${selectedKvStore}/${path}`);
    setShowSecretSelector(false);
  };

  const filteredSecrets = secretSearch
    ? secrets.filter((s) => s.toLowerCase().includes(secretSearch.toLowerCase()))
    : secrets;

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setLoading(true);
    setError(null);
    setFieldErrors({});

    const errors: Record<string, string> = {};
    if (!formData.name.trim()) errors.name = 'Name is required';
    if (mode === 'managed') {
      if (authMethod === 'password') {
        if (!formData.username.trim()) errors.username = 'Username is required';
        if (!formData.password) errors.password = 'Password is required';
      } else if (!formData.ssh_key) {
        errors.ssh_key = 'SSH key is required';
      }
    } else if (!formData.vault_path) {
      errors.vault_path = 'Select a Vault secret to link';
    }
    if (formData.sudo_method === 'password' && !formData.sudo_password && mode === 'managed') {
      errors.sudo_password = 'Sudo password is required when sudo method is "password"';
    }

    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      setError('Please fix the errors below');
      setLoading(false);
      return;
    }

    try {
      const response = await apiFetch('/api/backend/credentials', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify(formData),
      });
      const data = await response.json();
      if (!response.ok) throw new Error(formatApiError(data, 'Failed to create credential'));
      toast.success('Credential created');
      router.push('/credentials/all');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create credential';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  if (!canWrite) {
    return (
      <MainLayout>
        <Head>
          <title>Add Credential | Praxis</title>
        </Head>
        <div className="text-center">
          <h1 className="text-xl font-semibold text-gray-100">Access Denied</h1>
          <p className="text-gray-400 mt-2">You do not have permission to access this page.</p>
        </div>
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>Add Credential | Praxis</title>
      </Head>
      <PageHeader
        title="Add New Credential"
        actions={
          <Link href="/credentials/all">
            <Button variant="outline">Cancel</Button>
          </Link>
        }
      />

      {error && (
        <div className="mb-4 p-4 bg-red-900/40 border border-red-700 text-red-200 rounded" role="alert">
          <p className="font-bold">Error</p>
          <p>{error}</p>
        </div>
      )}

      <form onSubmit={handleSubmit} className="space-y-6">
        {/* Creation mode picker */}
        <Card>
          <CardBody>
            <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-1">
              How should we store the secret?
            </h2>
            <p className="text-xs text-gray-500 mb-4">
              Every credential is backed by OpenBao (a Vault-compatible secrets service). Choose whether to create a new secret
              for it or link to one that already exists.
            </p>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              <button
                type="button"
                onClick={() => handleModeChange('managed')}
                className={`text-left p-4 rounded-lg border transition-colors ${
                  mode === 'managed'
                    ? 'border-red-600 bg-red-900/20'
                    : 'border-gray-800 bg-gray-900/30 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Plus size={16} className="text-red-400" />
                  <span className="text-sm font-semibold text-gray-200">Create new secret</span>
                </div>
                <p className="text-xs text-gray-500">
                  Enter a username + password or SSH key. Praxis writes it to Vault under
                  <code className="ml-1 text-gray-400">praxis/credentials/&lt;name&gt;</code>.
                </p>
              </button>
              <button
                type="button"
                onClick={() => handleModeChange('linked')}
                className={`text-left p-4 rounded-lg border transition-colors ${
                  mode === 'linked'
                    ? 'border-red-600 bg-red-900/20'
                    : 'border-gray-800 bg-gray-900/30 hover:border-gray-700'
                }`}
              >
                <div className="flex items-center gap-2 mb-1">
                  <Link2 size={16} className="text-slate-300" />
                  <span className="text-sm font-semibold text-gray-200">
                    Link to existing Vault secret
                  </span>
                </div>
                <p className="text-xs text-gray-500">
                  Pick a secret already stored in Vault. Praxis just records its path - no copy is
                  made.
                </p>
              </button>
            </div>
          </CardBody>
        </Card>

        {/* Identity + secret */}
        <Card>
          <CardBody>
            <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-4">
              {mode === 'managed' ? 'Identity & Secret' : 'Identity & Linked Secret'}
            </h2>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <div className="md:col-span-2">
                <Input
                  label="Credential Name *"
                  name="name"
                  value={formData.name}
                  onChange={handleChange}
                  placeholder="e.g. prod-ansible-svc"
                  required
                  error={fieldErrors.name}
                />
              </div>

              {mode === 'managed' && (
                <div className="md:col-span-2">
                  <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider mb-2">
                    Auth Method
                  </label>
                  <div className="flex gap-3">
                    <Button
                      variant={authMethod === 'password' ? 'primary' : 'outline'}
                      icon={<Lock size={16} />}
                      onClick={() => handleAuthMethodChange('password')}
                      type="button"
                    >
                      Username & Password
                    </Button>
                    <Button
                      variant={authMethod === 'ssh_key' ? 'primary' : 'outline'}
                      icon={<Key size={16} />}
                      onClick={() => handleAuthMethodChange('ssh_key')}
                      type="button"
                    >
                      SSH Key
                    </Button>
                  </div>
                </div>
              )}

              {mode === 'managed' && authMethod === 'password' && (
                <>
                  <Input
                    label="Username *"
                    name="username"
                    value={formData.username}
                    onChange={handleChange}
                    required
                    error={fieldErrors.username}
                  />
                  <Input
                    label="Password *"
                    type="password"
                    name="password"
                    value={formData.password}
                    onChange={handleChange}
                    required
                    autoComplete="new-password"
                    error={fieldErrors.password}
                  />
                </>
              )}

              {mode === 'managed' && authMethod === 'ssh_key' && (
                <>
                  <div className="md:col-span-2">
                    <Input
                      label="Username"
                      name="username"
                      value={formData.username}
                      onChange={handleChange}
                      placeholder="Optional - username associated with this key"
                    />
                  </div>
                  <div className="md:col-span-2">
                    <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                      SSH Private Key *
                    </label>
                    <textarea
                      name="ssh_key"
                      value={formData.ssh_key}
                      onChange={handleChange}
                      required
                      rows={8}
                      placeholder="Paste SSH private key here"
                      className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-md text-sm text-gray-200 font-mono placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                    />
                  </div>
                </>
              )}

              {mode === 'linked' && (
                <div className="md:col-span-2">
                  <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                    Vault Secret *
                  </label>
                  <div className="relative">
                    <input
                      type="text"
                      name="vault_path"
                      value={formData.vault_path}
                      onChange={handleChange}
                      required
                      readOnly
                      onClick={() => setShowSecretSelector((s) => !s)}
                      placeholder="Click to select a secret"
                      className="w-full px-3 py-2 pr-10 bg-gray-900/50 border border-gray-700 rounded-md text-sm text-gray-200 font-mono cursor-pointer focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                    />
                    <button
                      type="button"
                      className="absolute right-2 top-1/2 -translate-y-1/2 text-gray-400 hover:text-gray-200"
                      onClick={() => setShowSecretSelector((s) => !s)}
                    >
                      <ChevronDown size={18} />
                    </button>
                  </div>

                  {showSecretSelector && (
                    <div className="mt-2 bg-gray-950 border border-gray-800 rounded-md p-4">
                      {loadingVault ? (
                        <div className="flex justify-center items-center h-32">
                          <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-500" />
                        </div>
                      ) : vaultError ? (
                        <div className="text-red-400 text-sm p-2">{vaultError}</div>
                      ) : (
                        <div className="space-y-3">
                          <Select
                            label="KV Store"
                            value={selectedKvStore}
                            onChange={(e) => setSelectedKvStore(e.target.value)}
                          >
                            {kvStores.map((store, i) => (
                              <option key={i} value={store}>
                                {store}
                              </option>
                            ))}
                          </Select>

                          <div>
                            <label className="block text-xs font-medium text-gray-400 uppercase tracking-wider mb-1">
                              Secrets
                            </label>
                            <div className="relative">
                              <input
                                type="text"
                                value={secretSearch}
                                onChange={(e) => setSecretSearch(e.target.value)}
                                placeholder="Search secrets..."
                                className="w-full pl-9 pr-3 py-2 bg-gray-900/50 border border-gray-700 rounded-md text-sm text-gray-200 placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                              />
                              <Search
                                size={14}
                                className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500"
                              />
                            </div>
                          </div>

                          <div className="max-h-60 overflow-y-auto">
                            {filteredSecrets.length === 0 ? (
                              <p className="text-gray-500 text-center py-4 text-sm">
                                {secrets.length === 0 ? 'No secrets in this store' : 'No matches'}
                              </p>
                            ) : (
                              <div className="space-y-1">
                                {filteredSecrets.map((secret, i) => (
                                  <button
                                    key={i}
                                    type="button"
                                    onClick={() => handleSelectSecret(secret)}
                                    className="w-full text-left px-3 py-2 rounded-md bg-gray-900 text-gray-300 hover:bg-gray-800 flex items-center gap-2 text-sm"
                                  >
                                    <Database size={14} className="text-slate-300 shrink-0" />
                                    <span className="truncate font-mono">{secret}</span>
                                  </button>
                                ))}
                              </div>
                            )}
                          </div>
                        </div>
                      )}
                    </div>
                  )}

                  {secretData && (
                    <div className="mt-4 bg-gray-950 border border-gray-800 rounded-md p-4">
                      <h3 className="text-xs font-semibold text-gray-400 uppercase tracking-wider mb-2">
                        Preview
                      </h3>
                      <table className="w-full text-sm">
                        <thead>
                          <tr className="border-b border-gray-800">
                            <th scope="col" className="text-left pb-2 text-gray-500 font-medium">Key</th>
                            <th scope="col" className="text-left pb-2 text-gray-500 font-medium">Value</th>
                          </tr>
                        </thead>
                        <tbody>
                          {Object.entries(secretData.data).map(([key, value]) => (
                            <tr key={key} className="border-b border-gray-800/50">
                              <td className="py-2 pr-4 text-gray-300 font-mono">{key}</td>
                              <td className="py-2 text-gray-200 break-all">
                                {key.toLowerCase().includes('password') ? (
                                  <span className="bg-gray-800 px-2 py-0.5 rounded text-xs">
                                    ••••••••
                                  </span>
                                ) : (
                                  String(value)
                                )}
                              </td>
                            </tr>
                          ))}
                        </tbody>
                      </table>
                    </div>
                  )}
                </div>
              )}
            </div>
          </CardBody>
        </Card>

        {/* Sudo */}
        <Card>
          <CardBody>
            <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-4">
              Sudo Configuration
            </h2>
            <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
              <Select
                label="Sudo Method"
                name="sudo_method"
                value={formData.sudo_method}
                onChange={handleChange}
              >
                <option value="none">None / Root user</option>
                <option value="nopasswd">NOPASSWD (sudo without password)</option>
                <option value="password">Password (uses sudo password)</option>
              </Select>

              {formData.sudo_method === 'password' && mode === 'managed' && (
                <Input
                  label="Sudo Password *"
                  type="password"
                  name="sudo_password"
                  value={formData.sudo_password}
                  onChange={handleChange}
                  required
                  autoComplete="new-password"
                  error={fieldErrors.sudo_password}
                />
              )}
            </div>
            {formData.sudo_method === 'password' && mode === 'linked' && (
              <p className="text-xs text-gray-500 mt-3">
                When using a linked secret, the sudo password should already be stored in the linked
                Vault secret as a key named <code className="text-gray-400">sudo_password</code>.
              </p>
            )}
          </CardBody>
        </Card>

        <div className="flex justify-end gap-3">
          <Link href="/credentials/all">
            <Button variant="outline" type="button">
              Cancel
            </Button>
          </Link>
          <Button type="submit" variant="primary" icon={<Save size={16} />} loading={loading}>
            Save Credential
          </Button>
        </div>
      </form>
    </MainLayout>
  );
};

export default AddCredentialPage;
