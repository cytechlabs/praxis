import React, { useState, useEffect } from 'react';
import { toast } from 'sonner';
import { useAuth } from '../../../context/AuthContext';
import { useRouter } from 'next/router';
import MainLayout from '@/components/MainLayout';
import { fetchCredentialDetails, updateCredential, deleteCredential } from '@/services/systemService';
import { PageHeader, Button, Card, CardBody, ConfirmModal, SkeletonCards, Input, Select } from '@/components/ui';
import { Key, Lock, Database, Save, Trash2, ExternalLink } from 'lucide-react';
import Link from 'next/link';
import Head from 'next/head';

type AuthMethod = 'password' | 'ssh_key';

const EditCredentialPage: React.FC = () => {
  const { user, canWrite } = useAuth();
  const router = useRouter();
  const { id } = router.query;
  const [loading, setLoading] = useState<boolean>(true);
  const [saving, setSaving] = useState<boolean>(false);
  const [deleting, setDeleting] = useState<boolean>(false);
  const [error, setError] = useState<string | null>(null);
  const [fieldErrors, setFieldErrors] = useState<Record<string, string>>({});
  const [deleteConfirmOpen, setDeleteConfirmOpen] = useState<boolean>(false);
  const [attachedSystemNames, setAttachedSystemNames] = useState<string[]>([]);
  const [authMethod, setAuthMethod] = useState<AuthMethod>('password');
  const [vaultPath, setVaultPath] = useState<string>('');

  const [formData, setFormData] = useState<{
    name: string;
    username: string;
    password: string;
    ssh_key: string;
    sudo_method: string;
    sudo_password: string;
  }>({
    name: '',
    username: '',
    password: '',
    ssh_key: '',
    sudo_method: 'none',
    sudo_password: '',
  });

  useEffect(() => {
    const loadCredential = async () => {
      if (!user || !id) return;
      try {
        setLoading(true);
        setError(null);
        const data = await fetchCredentialDetails(Number(id));
        setFormData({
          name: data.name,
          username: data.username || '',
          password: '',
          ssh_key: '',
          sudo_method: data.sudo_method || 'none',
          sudo_password: '',
        });
        setAuthMethod(data.auth_method === 'ssh_key' ? 'ssh_key' : 'password');
        setVaultPath(data.vault_path || '');
        setAttachedSystemNames(data.systems?.map((s) => s.hostname) || []);
      } catch (err) {
        setError(err instanceof Error ? err.message : 'Failed to load credential');
      } finally {
        setLoading(false);
      }
    };
    loadCredential();
  }, [user, id]);

  const handleChange = (
    e: React.ChangeEvent<HTMLInputElement | HTMLSelectElement | HTMLTextAreaElement>
  ) => {
    const { name, value } = e.target;
    setFormData((prev) => ({ ...prev, [name]: value }));
  };

  const handleSubmit = async (e: React.FormEvent) => {
    e.preventDefault();
    setSaving(true);
    setError(null);
    setFieldErrors({});

    const errors: Record<string, string> = {};
    if (!formData.name.trim()) errors.name = 'Name is required';
    if (authMethod === 'password' && !formData.username.trim()) {
      errors.username = 'Username is required';
    }
    if (Object.keys(errors).length > 0) {
      setFieldErrors(errors);
      setError('Please fix the errors below');
      setSaving(false);
      return;
    }

    // Build payload - only include secret fields if they were filled
    const payload = {
      name: formData.name,
      auth_method: authMethod,
      username: formData.username,
      sudo_method: formData.sudo_method,
      ...(formData.password ? { password: formData.password } : {}),
      ...(formData.ssh_key ? { ssh_key: formData.ssh_key } : {}),
      ...(formData.sudo_method === 'password' && formData.sudo_password
        ? { sudo_password: formData.sudo_password }
        : {}),
    };

    try {
      await updateCredential(Number(id), payload);
      toast.success('Credential updated');
      router.push('/credentials/all');
    } catch (err) {
      const msg = err instanceof Error ? err.message : 'Failed to update credential';
      setError(msg);
      toast.error(msg);
    } finally {
      setSaving(false);
    }
  };

  const handleDelete = async () => {
    if (!user || !id) return;
    try {
      setDeleting(true);
      setError(null);
      await deleteCredential(Number(id));
      toast.success('Credential deleted');
      router.push('/credentials/all');
    } catch (err) {
      let msg = err instanceof Error ? err.message : 'Failed to delete credential';
      if (msg.includes('used by systems')) {
        msg = 'This credential cannot be deleted because it is in use by one or more systems. Detach it first.';
      }
      setError(msg);
      toast.error(msg);
      setDeleteConfirmOpen(false);
    } finally {
      setDeleting(false);
    }
  };

  const hasAttachedSystems = attachedSystemNames.length > 0;

  return (
    <MainLayout>
      <Head>
        <title>Edit Credential | Praxis</title>
      </Head>
      <PageHeader
        title="Edit Credential"
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

      {loading && !formData.name ? (
        <SkeletonCards count={2} />
      ) : (
        <form onSubmit={handleSubmit} className="space-y-6">
          {/* Header card: identity + linked vault path */}
          <Card>
            <CardBody>
              <div className="flex items-start justify-between gap-4 mb-4">
                <div className="flex items-center gap-3">
                  <div className="p-2 rounded-md bg-red-900/30 border border-red-800/40">
                    {authMethod === 'ssh_key' ? (
                      <Key size={18} className="text-red-400" />
                    ) : (
                      <Lock size={18} className="text-red-400" />
                    )}
                  </div>
                  <div>
                    <div className="text-xs uppercase tracking-wider text-gray-500">
                      {authMethod === 'ssh_key' ? 'SSH Key Credential' : 'Password Credential'}
                    </div>
                    <div className="text-lg font-semibold text-gray-100">
                      {formData.name || '-'}
                    </div>
                  </div>
                </div>
              </div>

              {vaultPath && (
                <div className="bg-gray-900/50 border border-gray-800 rounded-md px-3 py-2.5 flex items-center gap-2">
                  <Database size={14} className="text-slate-300 shrink-0" />
                  <div className="min-w-0 flex-1">
                    <div className="text-xs text-gray-500 mb-0.5">Vault Path</div>
                    <code className="text-sm text-gray-200 break-all font-mono">{vaultPath}</code>
                  </div>
                  <Link
                    href="/system-management/vault-management"
                    className="shrink-0 inline-flex items-center gap-1 text-xs text-gray-400 hover:text-red-400 transition-colors"
                    title="Open Vault Management"
                  >
                    <ExternalLink size={14} />
                    <span className="hidden sm:inline">Manage</span>
                  </Link>
                </div>
              )}
            </CardBody>
          </Card>

          {/* Identity + secret rotation */}
          <Card>
            <CardBody>
              <h2 className="text-sm font-semibold text-gray-200 uppercase tracking-wider mb-4">
                Identity & Secret
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

                {authMethod === 'password' ? (
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
                      label="New Password"
                      type="password"
                      name="password"
                      value={formData.password}
                      onChange={handleChange}
                      placeholder="Leave blank to keep current password"
                      autoComplete="new-password"
                    />
                  </>
                ) : (
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
                        New SSH Key
                      </label>
                      <textarea
                        name="ssh_key"
                        value={formData.ssh_key}
                        onChange={handleChange}
                        rows={8}
                        placeholder="Leave blank to keep current key. Paste a new private key to rotate."
                        className="w-full px-3 py-2 bg-gray-900/50 border border-gray-700 rounded-md text-sm text-gray-200 font-mono placeholder:text-gray-600 focus:outline-none focus:ring-2 focus:ring-red-500/30 focus:border-red-600"
                      />
                    </div>
                  </>
                )}
              </div>
              <p className="text-xs text-gray-500 mt-3">
                Updating the secret writes a new version to Vault. Previous versions remain accessible
                via Vault Management.
              </p>
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

                {formData.sudo_method === 'password' && (
                  <Input
                    label="New Sudo Password"
                    type="password"
                    name="sudo_password"
                    value={formData.sudo_password}
                    onChange={handleChange}
                    placeholder="Leave blank to keep current sudo password"
                    autoComplete="new-password"
                  />
                )}
              </div>
            </CardBody>
          </Card>

          {/* Actions */}
          <div className="flex justify-end gap-3">
            <Link href="/credentials/all">
              <Button variant="outline" type="button">
                Cancel
              </Button>
            </Link>
            {canWrite && (
              <Button type="submit" variant="primary" icon={<Save size={16} />} loading={saving}>
                Save Changes
              </Button>
            )}
          </div>

          {/* Danger zone */}
          {canWrite && (
            <Card className="border-red-900/40">
              <CardBody>
                <h2 className="text-sm font-semibold text-red-400 uppercase tracking-wider mb-2">
                  Danger Zone
                </h2>
                <div className="flex items-start justify-between gap-4 flex-wrap">
                  <div className="min-w-0 flex-1">
                    <p className="text-sm text-gray-300 font-medium">Delete this credential</p>
                    <p className="text-xs text-gray-500 mt-1">
                      {hasAttachedSystems ? (
                        <>
                          This credential is in use by{' '}
                          <span className="text-gray-300">{attachedSystemNames.length}</span> system
                          {attachedSystemNames.length === 1 ? '' : 's'}. Detach it first before
                          deleting.
                        </>
                      ) : (
                        'This action permanently removes the credential metadata. The Vault secret is not deleted.'
                      )}
                    </p>
                  </div>
                  <Button
                    variant="danger"
                    type="button"
                    icon={<Trash2 size={16} />}
                    onClick={() => setDeleteConfirmOpen(true)}
                    disabled={hasAttachedSystems || deleting}
                  >
                    Delete
                  </Button>
                </div>
              </CardBody>
            </Card>
          )}
        </form>
      )}

      <ConfirmModal
        open={deleteConfirmOpen}
        onClose={() => setDeleteConfirmOpen(false)}
        onConfirm={handleDelete}
        title="Delete Credential"
        message={`Permanently delete "${formData.name}"? This cannot be undone. The Vault secret at ${vaultPath || 'the linked path'} will not be removed.`}
        confirmLabel="Delete"
        variant="danger"
        loading={deleting}
      />
    </MainLayout>
  );
};

export default EditCredentialPage;
