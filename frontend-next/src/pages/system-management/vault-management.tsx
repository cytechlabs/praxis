import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import { useAuth } from '@/context/AuthContext';
import { useRouter } from 'next/router';
import MainLayout from '@/components/MainLayout';
import {
  listKVStores,
  listSecrets,
  getSecret,
  getSecretVersions,
  getSecretVersion,
  createSecret,
  deleteSecret,
  updateSecretPassword,
} from '@/services/vaultService';
import { createCredential } from '@/services/systemService';
import {
  Key,
  Lock,
  Plus,
  Trash2,
  Eye,
  EyeOff,
  RefreshCw,
  Save,
  Edit,
  Settings,
  Link as LinkIcon,
  ChevronLeft,
} from 'lucide-react';
import VaultSettingsTab from '@/components/settings/VaultSettingsTab';
import { Modal, ConfirmModal, Input, Button } from '@/components/ui';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface SecretDataValue {
  string?: string;
  number?: number;
  boolean?: boolean;
}

interface SecretMetadata {
  created_time: string;
  current_version: number;
  versions: Record<string, { created_time: string }>;
}

interface SecretData {
  path: string;
  data: Record<string, SecretDataValue | string | number | boolean>;
  metadata: SecretMetadata;
}

interface SecretVersion {
  version: number;
  created_time: string;
  data: Record<string, SecretDataValue | string | number | boolean>;
}

const VaultManagementPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const { user, canWrite } = useAuth();
  const router = useRouter();
  const [loading, setLoading] = useState<boolean>(true);
  const [error, setError] = useState<string | null>(null);
  const [kvStores, setKvStores] = useState<string[]>([]);
  const [selectedKvStore, setSelectedKvStore] = useState<string>('');
  const [currentPath, setCurrentPath] = useState<string>('');
  const [secrets, setSecrets] = useState<string[]>([]);
  const [selectedSecret, setSelectedSecret] = useState<string>('');
  const [secretData, setSecretData] = useState<SecretData | null>(null);
  const [secretVersions, setSecretVersions] = useState<number[]>([]);
  const [selectedVersion, setSelectedVersion] = useState<number>(0);
  const [versionData, setVersionData] = useState<SecretVersion | null>(null);
  const [showSettings, setShowSettings] = useState<boolean>(false);
  const [revealedPasswords, setRevealedPasswords] = useState<Set<string>>(new Set());

  // Modal state
  const [showNewSecretModal, setShowNewSecretModal] = useState<boolean>(false);
  const [showPasswordUpdateModal, setShowPasswordUpdateModal] = useState<boolean>(false);
  const [showCreateCredentialModal, setShowCreateCredentialModal] = useState<boolean>(false);
  const [deleteTarget, setDeleteTarget] = useState<string | null>(null);

  // New secret form state
  const [newSecretPath, setNewSecretPath] = useState<string>('');
  const [newSecretData, setNewSecretData] = useState<Record<string, string>>({
    username: '',
    password: '',
  });

  // Password update state
  const [passwordUpdateData, setPasswordUpdateData] = useState<{
    username: string;
    newPassword: string;
  }>({ username: '', newPassword: '' });

  // Create credential state
  const [credentialName, setCredentialName] = useState<string>('');
  const [credentialCreated, setCredentialCreated] = useState<boolean>(false);

  const loadKvStores = useCallback(async () => {
    if (!user) return;
    try {
      setLoading(true);
      setError(null);
      const stores = await listKVStores();
      setKvStores(stores);
      if (stores.length > 0 && !selectedKvStore) {
        setSelectedKvStore(stores[0]);
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : 'Failed to load KV stores';
      if (message.includes('No Vault client') || message.includes('No active Vault')) {
        setKvStores([]);
      } else if (message.includes('Requires one of') || message.includes('403')) {
        setError('You do not have permission to access Vault secrets. Admin or maintainer role required.');
      } else {
        setError(message);
      }
    } finally {
      setLoading(false);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  useEffect(() => {
    if (user && canWrite) {
      loadKvStores();
    } else if (user && !canWrite) {
      setLoading(false);
      setError('You do not have permission to access Vault secrets. Admin or maintainer role required.');
    }
  }, [user, canWrite, loadKvStores]);

  const loadSecrets = useCallback(
    async (path: string) => {
      if (!user) return;
      try {
        setLoading(true);
        setError(null);
        const result = await listSecrets(path);
        setSecrets(result.secrets);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load secrets');
      } finally {
        setLoading(false);
      }
    },
    [user]
  );

  useEffect(() => {
    if (selectedKvStore && user) {
      setCurrentPath(selectedKvStore);
      loadSecrets(selectedKvStore);
      setSelectedSecret('');
      setSecretData(null);
      setSecretVersions([]);
      setSelectedVersion(0);
      setVersionData(null);
    }
  }, [selectedKvStore, user, loadSecrets]);

  const loadSecretData = useCallback(
    async (path: string) => {
      if (!user) return;
      try {
        setLoading(true);
        setError(null);
        const data = await getSecret(path);
        setSecretData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load secret data');
      } finally {
        setLoading(false);
      }
    },
    [user]
  );

  const loadSecretVersions = useCallback(
    async (path: string) => {
      if (!user) return;
      try {
        setLoading(true);
        setError(null);
        const data = await getSecretVersions(path);
        setSecretVersions(data.versions);
        setSelectedVersion(data.current_version);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load secret versions');
      } finally {
        setLoading(false);
      }
    },
    [user]
  );

  useEffect(() => {
    if (selectedSecret && user) {
      loadSecretData(selectedSecret);
      loadSecretVersions(selectedSecret);
      setRevealedPasswords(new Set());
    }
  }, [selectedSecret, user, loadSecretData, loadSecretVersions]);

  const loadVersionData = useCallback(
    async (path: string, version: number) => {
      if (!user) return;
      try {
        setLoading(true);
        setError(null);
        const data = await getSecretVersion(path, version);
        setVersionData(data);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load version data');
      } finally {
        setLoading(false);
      }
    },
    [user]
  );

  useEffect(() => {
    if (selectedSecret && selectedVersion > 0 && user) {
      loadVersionData(selectedSecret, selectedVersion);
    }
  }, [selectedVersion, selectedSecret, user, loadVersionData]);

  const handleCreateSecret = async () => {
    if (!user || !selectedKvStore) return;
    try {
      setLoading(true);
      setError(null);
      const fullPath = `${currentPath}/${newSecretPath}`;
      await createSecret(fullPath, newSecretData);
      setShowNewSecretModal(false);
      setNewSecretPath('');
      setNewSecretData({ username: '', password: '' });
      await loadSecrets(currentPath);
      toast.success('Secret created');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create secret';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleDeleteSecret = async () => {
    if (!user || !deleteTarget) return;
    try {
      setLoading(true);
      setError(null);
      await deleteSecret(deleteTarget);
      if (selectedSecret === deleteTarget) {
        setSelectedSecret('');
        setSecretData(null);
        setSecretVersions([]);
        setSelectedVersion(0);
        setVersionData(null);
      }
      await loadSecrets(currentPath);
      toast.success('Secret deleted');
      setDeleteTarget(null);
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to delete secret';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleCreateCredentialFromSecret = async () => {
    if (!user || !selectedSecret || !versionData || !credentialName) return;
    try {
      setLoading(true);
      setError(null);
      await createCredential({
        name: credentialName,
        auth_method: 'password',
        vault_path: selectedSecret,
      });
      setCredentialCreated(true);
      toast.success('Credential created');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to create credential';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleUpdatePassword = async () => {
    if (!user || !selectedSecret || !passwordUpdateData.newPassword) return;
    try {
      setLoading(true);
      setError(null);
      await updateSecretPassword(
        selectedSecret,
        passwordUpdateData.username,
        passwordUpdateData.newPassword
      );
      setShowPasswordUpdateModal(false);
      setPasswordUpdateData({ username: '', newPassword: '' });
      await loadSecretData(selectedSecret);
      await loadSecretVersions(selectedSecret);
      toast.success('Password updated');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to update password';
      setError(msg);
      toast.error(msg);
    } finally {
      setLoading(false);
    }
  };

  const handleNewSecretDataChange = (key: string, value: string) => {
    setNewSecretData((prev) => ({ ...prev, [key]: value }));
  };

  const addNewSecretField = () => {
    setNewSecretData((prev) => ({
      ...prev,
      [`key${Object.keys(prev).length + 1}`]: '',
    }));
  };

  const removeNewSecretField = (key: string) => {
    const newData = { ...newSecretData };
    delete newData[key];
    setNewSecretData(newData);
  };

  const togglePasswordReveal = (key: string) => {
    setRevealedPasswords((prev) => {
      const next = new Set(prev);
      if (next.has(key)) {
        next.delete(key);
      } else {
        next.add(key);
      }
      return next;
    });
  };

  const formatDate = (dateString: string) => {
    if (!dateString || dateString === 'unknown') return 'Unknown';
    try {
      return formatTimestamp(new Date(dateString));
    } catch {
      return dateString;
    }
  };

  const navigateUp = () => {
    if (!currentPath || currentPath === selectedKvStore) return;
    const parts = currentPath.split('/');
    parts.pop();
    const parent = parts.join('/') || selectedKvStore;
    setCurrentPath(parent);
    loadSecrets(parent);
  };

  return (
    <MainLayout>
      <Head>
        <title>Vault Management | Praxis</title>
      </Head>
      <div className="p-6">
        <div className="flex justify-between items-center mb-6">
          <h1 className="text-2xl font-semibold text-content">Vault Management</h1>
          <div className="flex gap-2">
            <Button
              variant="outline"
              icon={<Settings size={16} />}
              onClick={() => setShowSettings(!showSettings)}
            >
              {showSettings ? 'Show Secrets' : 'Settings'}
            </Button>
            {!showSettings && (
              <Button
                variant="primary"
                icon={<RefreshCw size={16} />}
                onClick={loadKvStores}
                disabled={loading}
              >
                Refresh
              </Button>
            )}
          </div>
        </div>

        {error && (
          <div className="mb-4 p-4 bg-red-900/40 border border-red-700 text-red-200 rounded">
            {error}
          </div>
        )}

        {showSettings ? (
          <div className="bg-surface-raised border border-border/60 rounded-lg p-4">
            <VaultSettingsTab onConfigSaved={loadKvStores} />
          </div>
        ) : (
          <div className="grid grid-cols-1 lg:grid-cols-12 gap-6">
            {/* KV Store Selection */}
            <div className="lg:col-span-3 bg-surface-raised border border-border/60 rounded-lg p-4">
              <h2 className="text-sm font-semibold mb-3 text-content uppercase tracking-wider flex items-center">
                <Key size={16} className="mr-2" />
                KV Stores
              </h2>

              {loading && kvStores.length === 0 ? (
                <div className="flex justify-center items-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-500" />
                </div>
              ) : kvStores.length === 0 ? (
                <p className="text-content-subtle text-center py-4 text-sm">No KV stores found</p>
              ) : (
                <div className="space-y-1">
                  {kvStores.map((store, index) => (
                    <button
                      key={index}
                      onClick={() => setSelectedKvStore(store)}
                      className={`w-full text-left px-3 py-2 rounded-md text-sm truncate transition-colors ${
                        selectedKvStore === store
                          ? 'bg-red-600 text-white'
                          : 'bg-surface-sunken/50 text-content hover:bg-surface-overlay'
                      }`}
                      title={store}
                    >
                      {store}
                    </button>
                  ))}
                </div>
              )}
            </div>

            {/* Secrets List */}
            <div className="lg:col-span-4 bg-surface-raised border border-border/60 rounded-lg p-4 min-w-0">
              <div className="flex justify-between items-center mb-3 gap-2">
                <h2 className="text-sm font-semibold text-content uppercase tracking-wider flex items-center min-w-0">
                  <Lock size={16} className="mr-2 shrink-0" />
                  <span className="truncate">Secrets</span>
                </h2>
                {canWrite && selectedKvStore && (
                  <button
                    onClick={() => {
                      setNewSecretPath('');
                      setNewSecretData({ username: '', password: '' });
                      setShowNewSecretModal(true);
                    }}
                    className="p-1.5 bg-red-600 text-white rounded-md hover:bg-red-700 transition-colors shrink-0"
                    aria-label="Add New Secret" title="Add New Secret"
                  >
                    <Plus size={14} />
                  </button>
                )}
              </div>

              {currentPath && currentPath !== selectedKvStore && (
                <div className="mb-2 flex items-center gap-1">
                  <button
                    onClick={navigateUp}
                    className="p-1 text-content-muted hover:text-content rounded"
                    aria-label="Up one level" title="Up one level"
                  >
                    <ChevronLeft size={14} />
                  </button>
                  <code className="text-xs text-content-subtle truncate font-mono" title={currentPath}>
                    {currentPath}
                  </code>
                </div>
              )}

              {!selectedKvStore ? (
                <p className="text-content-subtle text-center py-4 text-sm">Select a KV store first</p>
              ) : loading && secrets.length === 0 ? (
                <div className="flex justify-center items-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-500" />
                </div>
              ) : secrets.length === 0 ? (
                <p className="text-content-subtle text-center py-4 text-sm">No secrets found</p>
              ) : (
                <div className="space-y-1 max-h-[60vh] overflow-y-auto pr-1">
                  {secrets.map((secret, index) => {
                    const isFolder = secret.endsWith('/');
                    const fullPath = `${currentPath}/${secret.replace(/\/$/, '')}`;
                    const isSelected = !isFolder && selectedSecret === fullPath;
                    return (
                      <div key={index} className="flex items-center gap-1 group">
                        <button
                          onClick={() => {
                            if (isFolder) {
                              const next = `${currentPath}/${secret.slice(0, -1)}`;
                              setCurrentPath(next);
                              loadSecrets(next);
                              setSelectedSecret('');
                              setSecretData(null);
                              setSecretVersions([]);
                            } else {
                              setSelectedSecret(fullPath);
                            }
                          }}
                          className={`flex-1 min-w-0 text-left px-3 py-2 rounded-md text-sm truncate transition-colors ${
                            isSelected
                              ? 'bg-red-600 text-white'
                              : 'bg-surface-sunken/50 text-content hover:bg-surface-overlay'
                          }`}
                          title={secret}
                        >
                          {isFolder ? `📁 ${secret}` : secret}
                        </button>
                        {canWrite && !isFolder && (
                          <button
                            onClick={() => setDeleteTarget(fullPath)}
                            className="p-1.5 bg-surface-sunken/50 text-content-subtle rounded-md hover:bg-red-700 hover:text-white transition-colors opacity-0 group-hover:opacity-100 shrink-0"
                            aria-label="Delete Secret" title="Delete Secret"
                          >
                            <Trash2 size={14} />
                          </button>
                        )}
                      </div>
                    );
                  })}
                </div>
              )}
            </div>

            {/* Secret Details */}
            <div className="lg:col-span-5 bg-surface-raised border border-border/60 rounded-lg p-4 min-w-0">
              <h2 className="text-sm font-semibold mb-3 text-content uppercase tracking-wider flex items-center">
                <Eye size={16} className="mr-2" />
                Secret Details
              </h2>

              {!selectedSecret ? (
                <p className="text-content-subtle text-center py-8 text-sm">
                  Select a secret to view details
                </p>
              ) : loading && !secretData ? (
                <div className="flex justify-center items-center h-32">
                  <div className="animate-spin rounded-full h-8 w-8 border-t-2 border-b-2 border-red-500" />
                </div>
              ) : !secretData ? (
                <p className="text-content-subtle text-center py-4 text-sm">Failed to load secret data</p>
              ) : (
                <div className="space-y-4">
                  {/* Path */}
                  <div>
                    <div className="flex justify-between items-center mb-2 gap-2">
                      <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wider">
                        Path
                      </h3>
                      {canWrite && (
                        <Button
                          variant="outline"
                          icon={<LinkIcon size={14} />}
                          onClick={() => {
                            setCredentialName('');
                            setCredentialCreated(false);
                            setShowCreateCredentialModal(true);
                          }}
                          className="text-xs py-1"
                        >
                          Create Credential
                        </Button>
                      )}
                    </div>
                    <code className="block bg-surface-sunken/50 border border-border p-2 rounded text-sm text-content break-all font-mono">
                      {secretData.path}
                    </code>
                  </div>

                  {/* Data + version */}
                  <div>
                    <div className="flex justify-between items-center mb-2 gap-2">
                      <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wider">
                        Data
                      </h3>
                      <div className="flex items-center gap-2">
                        <span className="text-xs text-content-subtle">Version</span>
                        <select
                          value={selectedVersion}
                          onChange={(e) => setSelectedVersion(Number(e.target.value))}
                          className="bg-surface-sunken/50 text-content px-2 py-1 rounded-md border border-border-strong text-xs focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                        >
                          {secretVersions.map((version) => (
                            <option key={version} value={version}>
                              {version}
                            </option>
                          ))}
                        </select>
                      </div>
                    </div>

                    {loading && !versionData ? (
                      <div className="flex justify-center items-center h-16">
                        <div className="animate-spin rounded-full h-6 w-6 border-t-2 border-b-2 border-red-500" />
                      </div>
                    ) : !versionData ? (
                      <p className="text-content-subtle text-center py-2 text-sm">
                        No version data available
                      </p>
                    ) : (
                      <>
                        <div className="text-xs text-content-subtle mb-2">
                          Created: {formatDate(versionData.created_time)}
                        </div>
                        <div className="bg-surface-sunken/50 border border-border rounded overflow-hidden">
                          <table className="w-full text-sm">
                            <thead>
                              <tr className="border-b border-border bg-white/[0.02]">
                                <th scope="col" className="text-left px-3 py-2 text-content-subtle font-medium text-xs uppercase tracking-wider">
                                  Key
                                </th>
                                <th scope="col" className="text-left px-3 py-2 text-content-subtle font-medium text-xs uppercase tracking-wider">
                                  Value
                                </th>
                              </tr>
                            </thead>
                            <tbody>
                              {Object.entries(versionData.data).map(([key, value]) => {
                                const isPassword = key.toLowerCase().includes('password');
                                const revealed = revealedPasswords.has(key);
                                return (
                                  <tr key={key} className="border-b border-border/50 last:border-0">
                                    <td className="px-3 py-2 text-content font-mono align-top whitespace-nowrap">
                                      {key}
                                    </td>
                                    <td className="px-3 py-2 text-content break-all">
                                      {isPassword ? (
                                        <div className="flex items-center gap-2 flex-wrap">
                                          <span className="bg-surface-overlay px-2 py-0.5 rounded text-xs font-mono">
                                            {revealed ? String(value) : '••••••••'}
                                          </span>
                                          <button
                                            onClick={() => togglePasswordReveal(key)}
                                            className="text-content-subtle hover:text-red-400 transition-colors"
                                            title={revealed ? 'Hide' : 'Reveal'}
                                          >
                                            {revealed ? <EyeOff size={14} /> : <Eye size={14} />}
                                          </button>
                                          {canWrite && (
                                            <button
                                              onClick={() => {
                                                setPasswordUpdateData({
                                                  username:
                                                    key === 'password' &&
                                                    'username' in versionData.data
                                                      ? String(versionData.data.username)
                                                      : key,
                                                  newPassword: '',
                                                });
                                                setShowPasswordUpdateModal(true);
                                              }}
                                              className="text-content-subtle hover:text-red-400 transition-colors"
                                              aria-label="Update Password" title="Update Password"
                                            >
                                              <Edit size={14} />
                                            </button>
                                          )}
                                        </div>
                                      ) : (
                                        String(value)
                                      )}
                                    </td>
                                  </tr>
                                );
                              })}
                            </tbody>
                          </table>
                        </div>
                      </>
                    )}
                  </div>

                  {/* Metadata */}
                  <div>
                    <h3 className="text-xs font-semibold text-content-muted uppercase tracking-wider mb-2">
                      Metadata
                    </h3>
                    <div className="bg-surface-sunken/50 border border-border p-3 rounded text-sm">
                      <div className="grid grid-cols-[auto_1fr] gap-x-3 gap-y-1.5">
                        <div className="text-content-subtle">Created:</div>
                        <div className="text-content">
                          {formatDate(secretData.metadata.created_time)}
                        </div>
                        <div className="text-content-subtle">Current version:</div>
                        <div className="text-content">{secretData.metadata.current_version}</div>
                        <div className="text-content-subtle">Total versions:</div>
                        <div className="text-content">
                          {Object.keys(secretData.metadata.versions || {}).length}
                        </div>
                      </div>
                    </div>
                  </div>
                </div>
              )}
            </div>
          </div>
        )}
      </div>

      {/* New Secret Modal */}
      <Modal
        open={showNewSecretModal}
        onClose={() => setShowNewSecretModal(false)}
        title="New Secret"
        maxWidth="max-w-2xl"
      >
        <div className="space-y-4">
          <div>
            <label className="block text-xs font-medium text-content-muted uppercase tracking-wider mb-1">
              Secret Path
            </label>
            <div className="flex items-center gap-1">
              <code className="text-sm text-content-subtle font-mono shrink-0 max-w-[40%] truncate" title={currentPath}>
                {currentPath}/
              </code>
              <input
                type="text"
                value={newSecretPath}
                onChange={(e) => setNewSecretPath(e.target.value)}
                placeholder="my-secret"
                className="flex-1 min-w-0 bg-surface-sunken/50 text-content px-3 py-2 rounded-md border border-border-strong text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
              />
            </div>
          </div>

          <div>
            <label className="block text-xs font-medium text-content-muted uppercase tracking-wider mb-2">
              Fields
            </label>
            <div className="space-y-2">
              {Object.entries(newSecretData).map(([key, value]) => (
                <div key={key} className="flex items-center gap-2">
                  <input
                    type="text"
                    value={key}
                    onChange={(e) => {
                      const newKey = e.target.value;
                      const { [key]: oldValue, ...rest } = newSecretData;
                      setNewSecretData({ ...rest, [newKey]: oldValue });
                    }}
                    placeholder="Key"
                    className="w-1/3 bg-surface-sunken/50 text-content px-3 py-2 rounded-md border border-border-strong text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  />
                  <input
                    type={key.toLowerCase().includes('password') ? 'password' : 'text'}
                    value={value}
                    onChange={(e) => handleNewSecretDataChange(key, e.target.value)}
                    placeholder="Value"
                    className="flex-1 min-w-0 bg-surface-sunken/50 text-content px-3 py-2 rounded-md border border-border-strong text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
                  />
                  {Object.keys(newSecretData).length > 1 && (
                    <button
                      onClick={() => removeNewSecretField(key)}
                      className="p-2 bg-surface-sunken/50 text-content-subtle rounded-md hover:bg-red-700 hover:text-white transition-colors"
                      aria-label="Remove Field" title="Remove Field"
                    >
                      <Trash2 size={14} />
                    </button>
                  )}
                </div>
              ))}
            </div>
            <button
              onClick={addNewSecretField}
              className="mt-3 text-xs text-content-muted hover:text-red-400 transition-colors flex items-center gap-1"
            >
              <Plus size={14} /> Add Field
            </button>
          </div>

          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" onClick={() => setShowNewSecretModal(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              icon={<Save size={14} />}
              onClick={handleCreateSecret}
              disabled={loading || !newSecretPath}
              loading={loading}
            >
              Save
            </Button>
          </div>
        </div>
      </Modal>

      {/* Password Update Modal */}
      <Modal
        open={showPasswordUpdateModal}
        onClose={() => setShowPasswordUpdateModal(false)}
        title="Update Password"
        maxWidth="max-w-md"
      >
        <div className="space-y-4">
          <Input
            label="Username"
            value={passwordUpdateData.username}
            readOnly
          />
          <Input
            label="New Password"
            type="password"
            value={passwordUpdateData.newPassword}
            onChange={(e) =>
              setPasswordUpdateData((prev) => ({ ...prev, newPassword: e.target.value }))
            }
            autoComplete="new-password"
          />
          <div className="flex justify-end gap-2 pt-2">
            <Button variant="ghost" onClick={() => setShowPasswordUpdateModal(false)}>
              Cancel
            </Button>
            <Button
              variant="primary"
              icon={<Save size={14} />}
              onClick={handleUpdatePassword}
              disabled={loading || !passwordUpdateData.newPassword}
              loading={loading}
            >
              Update
            </Button>
          </div>
        </div>
      </Modal>

      {/* Create Credential Modal */}
      <Modal
        open={showCreateCredentialModal}
        onClose={() => {
          setShowCreateCredentialModal(false);
          setCredentialName('');
          setCredentialCreated(false);
        }}
        title="Create Credential from Secret"
        maxWidth="max-w-md"
      >
        {credentialCreated ? (
          <div className="space-y-4">
            <div className="bg-green-900/30 border border-green-800/40 text-green-300 rounded p-3 text-sm">
              Credential created successfully.
            </div>
            <div className="flex justify-end gap-2">
              <Button
                variant="ghost"
                onClick={() => {
                  setShowCreateCredentialModal(false);
                  setCredentialName('');
                  setCredentialCreated(false);
                }}
              >
                Close
              </Button>
              <Button variant="primary" onClick={() => router.push('/credentials/all')}>
                Go to Credentials
              </Button>
            </div>
          </div>
        ) : (
          <div className="space-y-4">
            <Input
              label="Credential Name *"
              value={credentialName}
              onChange={(e) => setCredentialName(e.target.value)}
              placeholder="Enter credential name"
            />
            <div>
              <label className="block text-xs font-medium text-content-muted uppercase tracking-wider mb-1">
                Vault Path
              </label>
              <code className="block bg-surface-sunken/50 text-content px-3 py-2 rounded-md border border-border-strong text-sm break-all font-mono">
                {selectedSecret}
              </code>
              <p className="text-xs text-content-subtle mt-1">
                The credential will read username and password from this Vault path at use time.
              </p>
            </div>
            <div className="flex justify-end gap-2 pt-2">
              <Button
                variant="ghost"
                onClick={() => {
                  setShowCreateCredentialModal(false);
                  setCredentialName('');
                }}
              >
                Cancel
              </Button>
              <Button
                variant="primary"
                icon={<LinkIcon size={14} />}
                onClick={handleCreateCredentialFromSecret}
                disabled={loading || !credentialName}
                loading={loading}
              >
                Create
              </Button>
            </div>
          </div>
        )}
      </Modal>

      {/* Delete confirmation */}
      <ConfirmModal
        open={!!deleteTarget}
        onClose={() => setDeleteTarget(null)}
        onConfirm={handleDeleteSecret}
        title="Delete Secret"
        message={`Permanently delete the secret at ${deleteTarget}? This soft-deletes the latest version in Vault.`}
        confirmLabel="Delete"
        variant="danger"
        loading={loading}
      />
    </MainLayout>
  );
};

export default VaultManagementPage;
