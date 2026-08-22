import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { fetchAllSystems } from '@/services/systemService';
import {
  fetchRepos,
  addRepo,
  removeRepo,
  syncRepos,
  fetchTemplates,
  RepoItem,
  DetectedRepo,
  RepoTemplate,
  AddRepoData,
} from '@/services/repoService';
import Head from 'next/head';
import { Trash2 } from 'lucide-react';
import { PageHeader, Button, Card, CardBody, StatCard, Badge, ConfirmModal, nativeSelectClass } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface SystemOption {
  id: number;
  hostname: string;
}

interface ConfirmState {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  variant: 'danger' | 'warning';
  onConfirm: () => void;
}

const RepositoryStatus = () => {
  const [systems, setSystems] = useState<SystemOption[]>([]);
  const [selectedSystem, setSelectedSystem] = useState<number | null>(null);
  const [repos, setRepos] = useState<RepoItem[]>([]);
  const [detectedRepos, setDetectedRepos] = useState<DetectedRepo[]>([]);
  const [packageManager, setPackageManager] = useState('');
  const [templates, setTemplates] = useState<RepoTemplate[]>([]);
  const [loading, setLoading] = useState(false);
  const [syncing, setSyncing] = useState(false);
  const [removing, setRemoving] = useState<number | null>(null);
  const [showAddForm, setShowAddForm] = useState(false);
  const [showTemplates, setShowTemplates] = useState(false);
  const [adding, setAdding] = useState(false);
  const [formData, setFormData] = useState<AddRepoData>({
    name: '',
    url: '',
    components: '',
    distribution: '',
    gpg_key_url: '',
  });
  const [confirm, setConfirm] = useState<ConfirmState>({
    open: false, title: '', message: '', confirmLabel: 'Confirm', variant: 'danger', onConfirm: () => {},
  });

  const closeConfirm = () => setConfirm((prev) => ({ ...prev, open: false }));

  useEffect(() => {
    fetchAllSystems()
      .then((data) => {
        const opts = data.map((s) => ({ id: s.id, hostname: s.hostname }));
        setSystems(opts);
        if (opts.length > 0) setSelectedSystem(opts[0].id);
      })
      .catch(() => toast.error('Failed to load systems'));
  }, []);

  const loadRepos = useCallback(async () => {
    if (!selectedSystem) return;
    setLoading(true);
    try {
      const data = await fetchRepos(selectedSystem);
      setRepos(data.repos);
      setDetectedRepos(data.detected_repos);
      setPackageManager(data.package_manager);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load repos');
    } finally {
      setLoading(false);
    }
  }, [selectedSystem]);

  useEffect(() => {
    loadRepos();
  }, [loadRepos]);

  useEffect(() => {
    if (!selectedSystem) return;
    fetchTemplates(selectedSystem)
      .then((data) => {
        setTemplates(Array.isArray(data.templates) ? data.templates : []);
      })
      .catch(() => setTemplates([]));
  }, [selectedSystem]);

  const handleSync = async () => {
    if (!selectedSystem) return;
    setSyncing(true);
    try {
      const result = await syncRepos(selectedSystem);
      if (result.status === 'success') {
        toast.success('Repository sync complete');
        loadRepos();
      } else {
        toast.error(result.error || 'Sync failed');
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Sync failed');
    } finally {
      setSyncing(false);
    }
  };

  const handleRemove = async (repoId: number, repoName: string) => {
    if (!selectedSystem) return;
    setConfirm({
      open: true,
      title: 'Remove Repository',
      message: `Remove repository "${repoName}"? This will delete the repo file from the system.`,
      confirmLabel: 'Remove',
      variant: 'danger',
      onConfirm: async () => {
        closeConfirm();
        setRemoving(repoId);
        try {
          await removeRepo(selectedSystem, repoId);
          toast.success(`Removed ${repoName}`);
          loadRepos();
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Failed to remove repo');
        } finally {
          setRemoving(null);
        }
      },
    });
  };

  const handleAdd = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!selectedSystem) return;
    setAdding(true);
    try {
      await addRepo(selectedSystem, formData);
      toast.success(`Added repository "${formData.name}"`);
      setShowAddForm(false);
      setFormData({ name: '', url: '', components: '', distribution: '', gpg_key_url: '' });
      loadRepos();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to add repo');
    } finally {
      setAdding(false);
    }
  };

  const applyTemplate = (template: RepoTemplate) => {
    setFormData({
      name: template.name,
      url: template.url,
      components: template.components || '',
      distribution: '',
      gpg_key_url: '',
    });
    setShowTemplates(false);
    setShowAddForm(true);
  };

  return (
    <MainLayout>
        <Head>
          <title>Repository Status | Praxis</title>
        </Head>
      <PageHeader title="Repository Management" actions={<HelpLink slug="packages" />} />
      <Card>
        <CardBody>
          <div className="mb-6">
            <div className="flex justify-between items-center">
              <div className="flex items-center space-x-3">
                <select
                  className={`px-4 py-2 border border-border rounded-md ${nativeSelectClass}`}
                  value={selectedSystem ?? ''}
                  onChange={(e) => setSelectedSystem(Number(e.target.value))}
                >
                  {systems.map((s) => (
                    <option key={s.id} value={s.id}>
                      {s.hostname}
                    </option>
                  ))}
                </select>
                {packageManager && (
                  <span className="px-3 py-1 bg-surface-overlay text-content rounded text-sm">
                    {packageManager}
                  </span>
                )}
              </div>
              <div className="flex space-x-3">
                <Button
                  variant="outline"
                  onClick={() => setShowTemplates(!showTemplates)}
                  disabled={!selectedSystem}
                >
                  Templates
                </Button>
                <Button
                  variant="outline"
                  onClick={() => setShowAddForm(!showAddForm)}
                  disabled={!selectedSystem}
                >
                  {showAddForm ? 'Cancel' : 'Add Repo'}
                </Button>
                <Button
                  variant="primary"
                  onClick={handleSync}
                  disabled={syncing || !selectedSystem}
                  loading={syncing}
                >
                  {syncing ? 'Syncing...' : 'Sync Repos'}
                </Button>
              </div>
            </div>
          </div>

          {showTemplates && templates.length > 0 && (
            <div className="mb-6 border border-border rounded-lg p-4">
              <h3 className="text-lg font-medium text-content mb-3">Available Templates</h3>
              <div className="grid grid-cols-1 md:grid-cols-2 lg:grid-cols-3 gap-3">
                {templates.map((t) => (
                  <div
                    key={t.name}
                    className="bg-surface-sunken border border-border rounded-lg p-3 flex flex-col justify-between"
                  >
                    <div>
                      <h4 className="font-medium text-content">{t.name}</h4>
                      <p className="text-sm text-content-muted mt-1">{t.description}</p>
                      <p className="text-xs text-content-subtle mt-1 truncate">{t.url}</p>
                    </div>
                    <Button
                      variant="outline"
                      size="sm"
                      onClick={() => applyTemplate(t)}
                      className="mt-2"
                    >
                      Use Template
                    </Button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {showAddForm && (
            <div className="mb-6 border border-border rounded-lg p-4">
              <h3 className="text-lg font-medium text-content mb-3">Add Repository</h3>
              <form onSubmit={handleAdd} className="space-y-3">
                <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Name *</label>
                    <input
                      type="text"
                      required
                      value={formData.name}
                      onChange={(e) => setFormData({ ...formData, name: e.target.value })}
                      className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                      placeholder="e.g. Ubuntu Universe"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-content-muted mb-1">URL *</label>
                    <input
                      type="text"
                      required
                      value={formData.url}
                      onChange={(e) => setFormData({ ...formData, url: e.target.value })}
                      className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                      placeholder="e.g. http://archive.ubuntu.com/ubuntu"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Components</label>
                    <input
                      type="text"
                      value={formData.components}
                      onChange={(e) => setFormData({ ...formData, components: e.target.value })}
                      className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                      placeholder="e.g. main restricted universe"
                    />
                  </div>
                  <div>
                    <label className="block text-sm text-content-muted mb-1">Distribution</label>
                    <input
                      type="text"
                      value={formData.distribution}
                      onChange={(e) => setFormData({ ...formData, distribution: e.target.value })}
                      className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                      placeholder="e.g. noble, jammy"
                    />
                  </div>
                </div>
                <div>
                  <label className="block text-sm text-content-muted mb-1">GPG Key URL</label>
                  <input
                    type="text"
                    value={formData.gpg_key_url}
                    onChange={(e) => setFormData({ ...formData, gpg_key_url: e.target.value })}
                    className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                    placeholder="https://..."
                  />
                </div>
                <div className="flex justify-end">
                  <Button
                    variant="primary"
                    type="submit"
                    disabled={adding}
                    loading={adding}
                  >
                    {adding ? 'Adding...' : 'Add Repository'}
                  </Button>
                </div>
              </form>
            </div>
          )}

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <StatCard label="Managed Repos" value={repos.length} subtitle="Added via Praxis" />
            <StatCard label="Detected Repos" value={detectedRepos.length} subtitle="Found on system" />
            {/* Package Manager is a categorical value, not a count - render it as a
                labelled badge so it doesn't read like a numeric stat tile. */}
            <div className="bg-surface-raised border border-border rounded-lg px-5 py-4 stat-accent">
              <div className="text-content-subtle text-xs font-medium uppercase tracking-wider mb-2">
                Package Manager
              </div>
              <div>
                {packageManager ? (
                  <Badge variant="neutral">{packageManager.toUpperCase()}</Badge>
                ) : (
                  <span className="text-sm text-content-subtle">Unknown</span>
                )}
              </div>
              <div className="text-xs text-content-subtle mt-1">System package manager</div>
            </div>
          </div>

          <div className="mb-6">
            <h3 className="text-lg font-medium text-content mb-3">Managed Repositories</h3>
            <div className="border border-border rounded-lg">
              <div className="grid grid-cols-6 gap-4 p-4 bg-surface-sunken border-b border-border font-medium text-content">
                <div>Name</div>
                <div>URL</div>
                <div>Type</div>
                <div>Components</div>
                <div>Status</div>
                <div>Actions</div>
              </div>
              {loading ? (
                <div className="p-4 text-content-muted">Loading repositories...</div>
              ) : repos.length === 0 ? (
                <div className="p-4 text-content-muted">
                  No managed repositories. Add one using the button above or use a template.
                </div>
              ) : (
                repos.map((repo) => (
                  <div
                    key={repo.id}
                    className="grid grid-cols-6 gap-4 p-4 border-b border-border last:border-b-0 hover:bg-surface-overlay"
                  >
                    <div className="font-medium text-content">{repo.name}</div>
                    <div className="text-content-muted text-sm truncate" title={repo.url}>
                      {repo.url}
                    </div>
                    <div>
                      <span className="px-2 py-1 bg-surface-overlay text-content rounded text-sm">
                        {repo.repo_type}
                      </span>
                    </div>
                    <div className="text-content-muted text-sm">{repo.components || '-'}</div>
                    <div>
                      <span
                        className={`px-2 py-1 rounded text-sm ${
                          repo.enabled
                            ? 'bg-green-900 text-green-300'
                            : 'bg-red-900 text-red-300'
                        }`}
                      >
                        {repo.enabled ? 'Enabled' : 'Disabled'}
                      </span>
                    </div>
                    <div>
                      <Button
                        variant="ghost"
                        size="sm"
                        iconOnly
                        icon={<Trash2 size={16} />}
                        aria-label={`Remove ${repo.name}`}
                        title="Remove repository"
                        onClick={() => handleRemove(repo.id, repo.name)}
                        disabled={removing === repo.id}
                        loading={removing === repo.id}
                      />
                    </div>
                  </div>
                ))
              )}
            </div>
          </div>

          <div>
            <h3 className="text-lg font-medium text-content mb-3">Detected System Repositories</h3>
            <div className="border border-border rounded-lg">
              <div className="grid grid-cols-4 gap-4 p-4 bg-surface-sunken border-b border-border font-medium text-content">
                <div>Source</div>
                <div>URL</div>
                <div>Distribution</div>
                <div>Components</div>
              </div>
              {loading ? (
                <div className="p-4 text-content-muted">Loading...</div>
              ) : detectedRepos.length === 0 ? (
                <div className="p-4 text-content-muted">
                  No repositories detected. Sync to scan the system.
                </div>
              ) : (
                detectedRepos.map((repo, idx) => (
                  <div
                    key={idx}
                    className="grid grid-cols-4 gap-4 p-4 border-b border-border last:border-b-0 hover:bg-surface-overlay"
                  >
                    <div className="text-content">{repo.type || repo.name || repo.section || '-'}</div>
                    <div className="text-content-muted text-sm truncate" title={repo.url}>
                      {repo.url || '-'}
                    </div>
                    <div className="text-content-muted text-sm">{repo.distribution || '-'}</div>
                    <div className="text-content-muted text-sm">{repo.components || '-'}</div>
                  </div>
                ))
              )}
            </div>
          </div>
        </CardBody>
      </Card>

      <ConfirmModal
        open={confirm.open}
        onClose={closeConfirm}
        onConfirm={confirm.onConfirm}
        title={confirm.title}
        message={confirm.message}
        confirmLabel={confirm.confirmLabel}
        variant={confirm.variant}
      />
    </MainLayout>
  );
};

export default RepositoryStatus;
