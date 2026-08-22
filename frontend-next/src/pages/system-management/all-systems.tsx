import React, { useState, useEffect, useRef } from 'react';
import { toast } from 'sonner';
import { useAuth } from '../../context/AuthContext';
import { useRouter } from 'next/router';
import { useUrlState } from '@/hooks/useUrlState';
import MainLayout from '../../components/MainLayout';
import {
  fetchAllSystems,
  deleteSystem,
  fetchGroups,
  fetchCredentials,
  fetchAllAgentHealth,
  SystemAgentHealth,
} from '../../services/systemService';
import TransportBadge from '../../components/transport/TransportBadge';
import { fetchTags, Tag } from '../../services/tagService';
import {
  bulkUpdateStatus,
  bulkUpdateGroup,
  bulkDeleteSystems,
  bulkAssignCredential,
  bulkImport,
  BulkImportSystem,
  BulkImportResult,
} from '../../services/bulkService';
import { apiFetch, formatApiError } from '../../utils/api';
import ExportButton from '../../components/ExportButton';
import Pagination from '../../components/Pagination';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, StatusBadge, Card, CardBody, ConfirmModal, EmptyState, SkeletonTable, SearchInput, Select, DetailDrawer, nativeSelectClass } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';

interface SystemListItem {
  id: number;
  hostname: string;
  ip_address: string;
  status: string;
  os_version: string;
  registered_at: string;
  environment_type?: string;
  group_name: string;
  distro_name: string;
  ca_trust_deployed?: boolean;
  tags?: { id: number; name: string; color: string }[];
}

interface ApiError {
  message: string;
}

const AllSystems = () => {
  const formatTimestamp = useFormatTimestamp();
  const { user, canWrite } = useAuth();
  const router = useRouter();
  const [systems, setSystems] = useState<SystemListItem[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState('');
  const [searchTerm, setSearchTerm] = useUrlState('search', '');
  const [statusFilter, setStatusFilter] = useUrlState('status', 'all');
  const [caTrustFilter, setCaTrustFilter] = useUrlState<'all' | 'enabled' | 'off'>('ca', 'all');
  const [environmentFilter, setEnvironmentFilter] = useUrlState('env', 'all');
  // Lifecycle filter chip. Backed by the server-side
  // /lifecycle/systems endpoint (which rides the smart-group predicate
  // compile path) so fleet-list truth never diverges from smart-group
  // truth. The locked PRA-155 #2d / PRA-156 #3c rule forbids client-
  // side computation of derived predicates here.
  const [lifecycleFilter, setLifecycleFilter] = useUrlState('lifecycle', 'all');
  // ``null`` means "no lifecycle filter active or still loading"; an
  // empty Set is a real "filter active and matched zero hosts" result.
  const [lifecycleSystemIds, setLifecycleSystemIds] = useState<Set<number> | null>(null);
  const [showDeleteConfirm, setShowDeleteConfirm] = useState(false);
  const [systemToDelete, setSystemToDelete] = useState<SystemListItem | null>(null);
  const [deleteLoading, setDeleteLoading] = useState(false);
  const [deleteError, setDeleteError] = useState('');
  const [allTags, setAllTags] = useState<Tag[]>([]);
  const [tagFilter, setTagFilter] = useState<number[]>([]);
  const [showTagDropdown, setShowTagDropdown] = useState(false);
  const [pageOffset, setPageOffset] = useState(0);
  const pageLimit = 25;

  // Bulk operations state
  const [selectedSystems, setSelectedSystems] = useState<number[]>([]);
  const [showBulkAction, setShowBulkAction] = useState<string | null>(null);
  const [bulkLoading, setBulkLoading] = useState(false);
  const [groups, setGroups] = useState<{ id: number; name: string }[]>([]);
  const [credentials, setCredentials] = useState<{ id: number; name: string; auth_method: string }[]>([]);
  const [bulkStatusValue, setBulkStatusValue] = useState('Active');
  const [bulkGroupValue, setBulkGroupValue] = useState<number>(0);
  const [bulkCredentialValue, setBulkCredentialValue] = useState<number>(0);

  // Import state
  const [importText, setImportText] = useState('');
  const [importParsed, setImportParsed] = useState<BulkImportSystem[]>([]);
  const [importParseError, setImportParseError] = useState('');
  const [importResults, setImportResults] = useState<BulkImportResult[] | null>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // EOL data: map system_id -> days_until_eol
  const [eolMap, setEolMap] = useState<Record<number, number>>({});

  // Saved views state
  interface SavedViewItem {
    id: number;
    name: string;
    filters: { groups?: number[]; tags?: number[]; status?: string; search?: string; environment?: string; lifecycle?: string };
    is_default: boolean;
    is_shared: boolean;
    user_id: number;
  }
  const [savedViews, setSavedViews] = useState<SavedViewItem[]>([]);
  const [drawerSystem, setDrawerSystem] = useState<SystemListItem | null>(null);
  // Per-system agent-health snapshot keyed by id. Loaded
  // best-effort alongside the inventory; missing entries render as
  // a neutral "-" placeholder so the broker outage doesn't block the
  // list from rendering.
  const [agentHealth, setAgentHealth] = useState<Record<number, SystemAgentHealth>>({});
  const [showSaveViewPrompt, setShowSaveViewPrompt] = useState(false);
  const [saveViewName, setSaveViewName] = useState('');
  const [showViewSelector, setShowViewSelector] = useState(false);
  const [activeViewId, setActiveViewId] = useState<number | null>(null);
  const [showManageViews, setShowManageViews] = useState(false);

  const loadData = async () => {
    if (user) {
      try {
        setLoading(true);
        const [systemsData, tagsData, groupsData, credentialsData] = await Promise.all([
          fetchAllSystems(),
          fetchTags(),
          fetchGroups(),
          fetchCredentials(),
        ]);
        setSystems(systemsData);
        setAllTags(tagsData);
        setGroups(groupsData.map((g: { id: number; name: string }) => ({ id: g.id, name: g.name })));
        setCredentials(
          credentialsData.map((c: { id: number; name: string; auth_method: string }) => ({
            id: c.id,
            name: c.name,
            auth_method: c.auth_method,
          }))
        );

        // Fetch EOL data (non-critical)
        try {
          const eolRes = await apiFetch('/api/backend/systems/eol-status');
          if (eolRes.ok) {
            const eolData = await eolRes.json();
            const map: Record<number, number> = {};
            for (const e of [...eolData.eol_systems, ...eolData.warning_systems]) {
              map[e.system_id] = e.days_until_eol;
            }
            setEolMap(map);
          }
        } catch { /* EOL is non-critical */ }

        // Fetch agent health in parallel - non-critical;
        // failures leave the badge column empty rather than blocking
        // the list. Bulk endpoint already degrades per-host broker
        // failures to badge_state="unknown".
        try {
          const healthRows = await fetchAllAgentHealth();
          const map: Record<number, SystemAgentHealth> = {};
          for (const row of healthRows) {
            map[row.system_id] = row;
          }
          setAgentHealth(map);
        } catch { /* agent-health is non-critical */ }
      } catch (err: unknown) {
        const error = err as ApiError;
        setError(error.message || 'Failed to fetch systems');
      } finally {
        setLoading(false);
      }
    }
  };

  const loadViews = async () => {
    try {
      const res = await apiFetch('/api/backend/views');
      if (res.ok) {
        const data = await res.json();
        setSavedViews(data.views || []);
        // Auto-apply default view on first load
        const defaultView = (data.views || []).find((v: SavedViewItem) => v.is_default);
        if (defaultView && !activeViewId) {
          applyView(defaultView);
        }
      }
    } catch { /* non-critical */ }
  };

  const applyView = (view: SavedViewItem) => {
    const f = view.filters;
    if (f.search !== undefined) setSearchTerm(f.search);
    if (f.status !== undefined) setStatusFilter(f.status || 'all');
    if (f.environment !== undefined) setEnvironmentFilter(f.environment || 'all');
    if (f.tags !== undefined) setTagFilter(f.tags || []);
    if (f.lifecycle !== undefined) setLifecycleFilter(f.lifecycle || 'all');
    setActiveViewId(view.id);
    setShowViewSelector(false);
  };

  const handleSaveView = async () => {
    if (!saveViewName.trim()) {
      toast.error('View name is required');
      return;
    }
    try {
      const filters = {
        search: searchTerm,
        status: statusFilter,
        environment: environmentFilter,
        tags: tagFilter,
        lifecycle: lifecycleFilter,
      };
      const res = await apiFetch('/api/backend/views', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ name: saveViewName.trim(), filters }),
      });
      if (res.ok) {
        toast.success('View saved');
        setShowSaveViewPrompt(false);
        setSaveViewName('');
        loadViews();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to save view'));
      }
    } catch { toast.error('Failed to save view'); }
  };

  const handleDeleteView = async (viewId: number) => {
    try {
      const res = await apiFetch(`/api/backend/views/${viewId}`, { method: 'DELETE' });
      if (res.ok) {
        toast.success('View deleted');
        if (activeViewId === viewId) setActiveViewId(null);
        loadViews();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to delete view'));
      }
    } catch { toast.error('Failed to delete view'); }
  };

  const handleSetDefaultView = async (viewId: number) => {
    try {
      const res = await apiFetch(`/api/backend/views/${viewId}/default`, { method: 'PUT' });
      if (res.ok) {
        toast.success('Default view updated');
        loadViews();
      } else {
        const err = await res.json();
        toast.error(formatApiError(err, 'Failed to set default'));
      }
    } catch { toast.error('Failed to set default'); }
  };

  useEffect(() => {
    loadData();
    loadViews();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [user]);

  // When the lifecycle filter is active, fetch the
  // matching system_ids from the server-side endpoint that rides the
  // smart-group predicate. Membership is the authoritative source -
  // we intersect with the rendered list rather than recomputing
  // lifecycle in the browser.
  //
  // Stale-bucket guard: clear the existing IDs at the start of each
  // non-'all' fetch so the loading-state matchesLifecycle check
  // (which excludes everything when lifecycleSystemIds is null)
  // kicks in during the transition. Without this, switching from
  // ``supported`` to ``unsupported`` would briefly render the old
  // supported list while the new fetch is in flight.
  useEffect(() => {
    if (lifecycleFilter === 'all') {
      setLifecycleSystemIds(null);
      return;
    }
    setLifecycleSystemIds(null);
    let cancelled = false;
    (async () => {
      try {
        const res = await apiFetch(
          `/api/backend/lifecycle/systems?status=${encodeURIComponent(lifecycleFilter)}`,
        );
        if (cancelled) return;
        if (!res.ok) {
          // Non-200 means the server-side truth source is unhappy
          // (validation / auth / 5xx). Fall back to "no matches" so
          // the list doesn't silently include hosts the predicate
          // would have excluded.
          setLifecycleSystemIds(new Set());
          return;
        }
        const body = await res.json();
        setLifecycleSystemIds(new Set<number>(body.system_ids ?? []));
      } catch {
        if (!cancelled) setLifecycleSystemIds(new Set());
      }
    })();
    return () => {
      cancelled = true;
    };
  }, [lifecycleFilter]);


  // Filter systems based on search term and filters
  const filteredSystems = systems.filter(system => {
    const matchesSearch =
      searchTerm === '' ||
      system.hostname.toLowerCase().includes(searchTerm.toLowerCase()) ||
      system.ip_address.toLowerCase().includes(searchTerm.toLowerCase()) ||
      system.distro_name.toLowerCase().includes(searchTerm.toLowerCase()) ||
      system.group_name.toLowerCase().includes(searchTerm.toLowerCase());

    const matchesStatus =
      statusFilter === 'all' ||
      system.status === statusFilter;

    const matchesEnvironment =
      environmentFilter === 'all' ||
      system.environment_type === environmentFilter;

    const matchesTags =
      tagFilter.length === 0 ||
      (system.tags && system.tags.some(t => tagFilter.includes(t.id)));

    const matchesCaTrust =
      caTrustFilter === 'all' ||
      (caTrustFilter === 'enabled' && system.ca_trust_deployed) ||
      (caTrustFilter === 'off' && !system.ca_trust_deployed);

    // Lifecycle filter rides /lifecycle/systems. While
    // the IDs are still loading (lifecycleFilter !== 'all' and
    // lifecycleSystemIds === null) we exclude everything to avoid a
    // flash of unfiltered list before the server response lands.
    const matchesLifecycle =
      lifecycleFilter === 'all' ||
      (lifecycleSystemIds !== null && lifecycleSystemIds.has(system.id));

    return matchesSearch && matchesStatus && matchesEnvironment && matchesTags && matchesCaTrust && matchesLifecycle;
  });

  // Reset page when filters change
  useEffect(() => {
    setPageOffset(0);
  }, [searchTerm, statusFilter, environmentFilter, tagFilter, caTrustFilter, lifecycleFilter, lifecycleSystemIds]);

  const paginatedSystems = filteredSystems.slice(pageOffset, pageOffset + pageLimit);

  // Get unique environment types for filter dropdown
  const environmentTypes = Array.from(
    new Set(systems.map(system => system.environment_type).filter(Boolean))
  );

  const handleViewDetails = (id: number) => {
    router.push(`/system-management/system/${id}`);
  };

  const handleConnect = (id: number) => {
    router.push(`/hosts/${id}/session`);
  };

  const handleDeleteClick = (system: SystemListItem) => {
    setSystemToDelete(system);
    setShowDeleteConfirm(true);
    setDeleteError('');
  };

  const handleDeleteConfirm = async () => {
    if (!systemToDelete || !user) return;

    setDeleteLoading(true);
    try {
      await deleteSystem(systemToDelete.id);

      setSystems(prevSystems =>
        prevSystems.filter(system => system.id !== systemToDelete.id)
      );

      setShowDeleteConfirm(false);
      setSystemToDelete(null);
      toast.success('System deleted');
    } catch (err: unknown) {
      const error = err as ApiError;
      const errorMsg = error.message || 'Failed to delete system';
      setDeleteError(errorMsg);
      toast.error(errorMsg);
    } finally {
      setDeleteLoading(false);
    }
  };

  const handleDeleteCancel = () => {
    setShowDeleteConfirm(false);
    setSystemToDelete(null);
    setDeleteError('');
  };

  const toggleTagFilter = (tagId: number) => {
    setTagFilter(prev =>
      prev.includes(tagId) ? prev.filter(id => id !== tagId) : [...prev, tagId]
    );
  };

  // Bulk selection handlers
  const toggleSelectAll = () => {
    if (selectedSystems.length === filteredSystems.length && filteredSystems.length > 0) {
      setSelectedSystems([]);
    } else {
      setSelectedSystems(filteredSystems.map(s => s.id));
    }
  };

  const toggleSelect = (id: number) => {
    setSelectedSystems(prev =>
      prev.includes(id) ? prev.filter(i => i !== id) : [...prev, id]
    );
  };

  // Bulk action handlers
  const handleBulkStatusChange = async () => {
    setBulkLoading(true);
    try {
      const result = await bulkUpdateStatus(selectedSystems, bulkStatusValue);
      toast.success(`${result.updated} system${result.updated !== 1 ? 's' : ''} updated to ${bulkStatusValue}`);
      setShowBulkAction(null);
      setSelectedSystems([]);
      await loadData();
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to update status');
    } finally {
      setBulkLoading(false);
    }
  };

  const handleBulkGroupChange = async () => {
    if (!bulkGroupValue) return;
    setBulkLoading(true);
    try {
      const result = await bulkUpdateGroup(selectedSystems, bulkGroupValue);
      const groupName = groups.find(g => g.id === bulkGroupValue)?.name || 'selected group';
      toast.success(`${result.updated} system${result.updated !== 1 ? 's' : ''} moved to ${groupName}`);
      setShowBulkAction(null);
      setSelectedSystems([]);
      await loadData();
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to update group');
    } finally {
      setBulkLoading(false);
    }
  };

  const handleBulkCredentialAssign = async () => {
    if (!bulkCredentialValue) return;
    setBulkLoading(true);
    try {
      const result = await bulkAssignCredential(selectedSystems, bulkCredentialValue);
      toast.success(`Credential assigned to ${result.updated} system${result.updated !== 1 ? 's' : ''}`);
      setShowBulkAction(null);
      setSelectedSystems([]);
      await loadData();
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to assign credential');
    } finally {
      setBulkLoading(false);
    }
  };

  const handleBulkDeployCA = async () => {
    setBulkLoading(true);
    try {
      const res = await apiFetch('/api/backend/ssh-identity/deploy-bulk', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ system_ids: selectedSystems }),
      });
      if (!res.ok) {
        const err = await res.json();
        throw new Error(formatApiError(err, 'Failed'));
      }
      const data = await res.json();
      toast.success(`CA trust deployed: ${data.success} succeeded, ${data.failed} failed`);
      setShowBulkAction(null);
      setSelectedSystems([]);
      await loadData();
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to deploy CA trust');
    } finally {
      setBulkLoading(false);
    }
  };

  const handleBulkDelete = async () => {
    setBulkLoading(true);
    try {
      const result = await bulkDeleteSystems(selectedSystems);
      toast.success(`${result.deleted} system${result.deleted !== 1 ? 's' : ''} deleted`);
      setShowBulkAction(null);
      setSelectedSystems([]);
      await loadData();
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Failed to delete systems');
    } finally {
      setBulkLoading(false);
    }
  };

  // Import handlers
  const handleImportFileUpload = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    const reader = new FileReader();
    reader.onload = (event) => {
      const text = event.target?.result as string;
      setImportText(text);
      parseImportJson(text);
    };
    reader.readAsText(file);
  };

  const parseImportJson = (text: string) => {
    setImportParseError('');
    setImportParsed([]);
    setImportResults(null);
    try {
      const parsed = JSON.parse(text);
      const arr = Array.isArray(parsed) ? parsed : [parsed];
      for (const item of arr) {
        if (!item.hostname || !item.ip_address) {
          setImportParseError('Each system must have at minimum: hostname, ip_address');
          return;
        }
        const hasDistro = item.distro || item.distro_id;
        const hasGroup = item.group || item.group_id;
        const hasCred = item.credential || item.credentials_id;
        if (!hasDistro || !hasGroup || !hasCred) {
          setImportParseError('Each system needs: distro (or distro_id), group (or group_id), credential (or credentials_id)');
          return;
        }
      }
      setImportParsed(arr);
    } catch {
      setImportParseError('Invalid JSON format');
    }
  };

  const handleImportDryRun = async () => {
    if (importParsed.length === 0) return;
    setBulkLoading(true);
    try {
      const result = await bulkImport(importParsed, true);
      setImportResults(result.results);
      const valid = result.results.filter((r: BulkImportResult) => r.status === 'validated').length;
      const errors = result.results.filter((r: BulkImportResult) => r.status === 'error').length;
      if (errors > 0) {
        toast.error(`Dry run: ${errors} error${errors !== 1 ? 's' : ''}, ${valid} valid`);
      } else {
        toast.success(`Dry run: all ${valid} system${valid !== 1 ? 's' : ''} valid`);
      }
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Dry run failed');
    } finally {
      setBulkLoading(false);
    }
  };

  const handleImportConfirm = async () => {
    if (importParsed.length === 0) return;
    setBulkLoading(true);
    try {
      const result = await bulkImport(importParsed, false);
      setImportResults(result.results);
      const created = result.results.filter((r: BulkImportResult) => r.status === 'created').length;
      const errors = result.results.filter((r: BulkImportResult) => r.status === 'error').length;
      if (errors > 0) {
        toast.error(`Import: ${created} created, ${errors} error${errors !== 1 ? 's' : ''}`);
      } else {
        toast.success(`Imported ${created} system${created !== 1 ? 's' : ''} successfully`);
      }
      await loadData();
    } catch (err: unknown) {
      const error = err as ApiError;
      toast.error(error.message || 'Import failed');
    } finally {
      setBulkLoading(false);
    }
  };

  const closeImportModal = () => {
    setShowBulkAction(null);
    setImportText('');
    setImportParsed([]);
    setImportParseError('');
    setImportResults(null);
    if (fileInputRef.current) fileInputRef.current.value = '';
  };

  return (
    <MainLayout>
        <Head>
          <title>All Systems | Praxis</title>
        </Head>
        <PageHeader
          title="All Systems"
          actions={
            <>
              <ExportButton endpoint="/api/backend/export/systems" filename="systems-export" />
              {canWrite && (
                <Button variant="outline" onClick={() => setShowBulkAction('import')}>
                  Import Systems
                </Button>
              )}
              <Button variant="primary" onClick={() => router.push('/system-management/register')}>
                Register New System
              </Button>
              <HelpLink slug="fleet-and-hosts" />
            </>
          }
        />

        {error && (
          <div className="mb-4 p-4 bg-red-900/40 border border-red-700 text-red-200 rounded" role="alert">
            {error}
          </div>
        )}

        <Card>
          <CardBody>
          {/* Saved Views Bar */}
          {savedViews.length > 0 && (
            <div className="flex items-center gap-3 mb-4 pb-4 border-b border-border/50">
              <span className="text-sm text-content-muted">Views:</span>
              <div className="relative">
                <button
                  onClick={() => setShowViewSelector(!showViewSelector)}
                  className="px-3 py-1.5 bg-surface-sunken border border-border rounded text-sm text-content hover:bg-surface-overlay"
                >
                  {activeViewId ? savedViews.find(v => v.id === activeViewId)?.name || 'Select View' : 'Select View'}
                </button>
                {showViewSelector && (
                  <div className="absolute left-0 mt-1 w-64 bg-surface-overlay border border-border rounded-lg shadow-lg z-20 p-2">
                    {savedViews.filter(v => !v.is_shared).length > 0 && (
                      <>
                        <div className="text-xs text-content-subtle px-2 py-1 font-medium uppercase">My Views</div>
                        {savedViews.filter(v => !v.is_shared).map(v => (
                          <button
                            key={v.id}
                            onClick={() => applyView(v)}
                            className={`w-full text-left px-2 py-1.5 text-sm rounded hover:bg-border ${activeViewId === v.id ? 'text-red-400 bg-border' : 'text-content'}`}
                          >
                            {v.name} {v.is_default && <span className="text-xs text-content-subtle">(default)</span>}
                          </button>
                        ))}
                      </>
                    )}
                    {savedViews.filter(v => v.is_shared).length > 0 && (
                      <>
                        <div className="text-xs text-content-subtle px-2 py-1 mt-1 font-medium uppercase border-t border-border-strong pt-2">Shared Views</div>
                        {savedViews.filter(v => v.is_shared).map(v => (
                          <button
                            key={v.id}
                            onClick={() => applyView(v)}
                            className={`w-full text-left px-2 py-1.5 text-sm rounded hover:bg-border ${activeViewId === v.id ? 'text-red-400 bg-border' : 'text-content'}`}
                          >
                            {v.name}
                          </button>
                        ))}
                      </>
                    )}
                    <button
                      onClick={() => { setActiveViewId(null); setSearchTerm(''); setStatusFilter('all'); setEnvironmentFilter('all'); setTagFilter([]); setLifecycleFilter('all'); setShowViewSelector(false); }}
                      className="w-full text-left px-2 py-1.5 text-sm text-content-muted hover:text-content border-t border-border-strong mt-1 pt-1"
                    >
                      Clear view
                    </button>
                  </div>
                )}
              </div>
              <button
                onClick={() => setShowSaveViewPrompt(true)}
                className="px-3 py-1.5 bg-border hover:bg-border-strong text-content rounded text-sm"
              >
                Save Current Filters
              </button>
              <button
                onClick={() => setShowManageViews(!showManageViews)}
                className="px-3 py-1.5 text-content-muted hover:text-content text-sm"
              >
                Manage
              </button>
            </div>
          )}

          {/* Save View Prompt */}
          {showSaveViewPrompt && (
            <div className="flex items-center gap-3 mb-4 p-3 bg-surface-raised border border-border/60 rounded-lg">
              <input
                type="text"
                placeholder="View name..."
                value={saveViewName}
                onChange={(e) => setSaveViewName(e.target.value)}
                className="px-3 py-1.5 bg-white/[0.02] border border-border-strong rounded text-sm text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring flex-1 max-w-xs"
                onKeyDown={(e) => e.key === 'Enter' && handleSaveView()}
              />
              <button onClick={handleSaveView} className="px-3 py-1.5 bg-red-600 hover:bg-red-700 text-white rounded text-sm">Save</button>
              <button onClick={() => { setShowSaveViewPrompt(false); setSaveViewName(''); }} className="px-3 py-1.5 text-content-muted hover:text-content text-sm">Cancel</button>
            </div>
          )}

          {/* Manage Views */}
          {showManageViews && savedViews.length > 0 && (
            <div className="mb-4 p-3 bg-surface-raised border border-border/60 rounded-lg">
              <div className="text-sm font-medium text-content mb-2">Manage Saved Views</div>
              <div className="space-y-1">
                {savedViews.map(v => (
                  <div key={v.id} className="flex items-center gap-3 py-1">
                    <span className="text-sm text-content flex-1">{v.name} {v.is_default && <span className="text-xs text-content-subtle">(default)</span>} {v.is_shared && <span className="text-xs text-content">(shared)</span>}</span>
                    {!v.is_default && (
                      <button onClick={() => handleSetDefaultView(v.id)} className="text-xs text-content-muted hover:text-content">Set Default</button>
                    )}
                    <button onClick={() => handleDeleteView(v.id)} className="text-xs text-red-400 hover:text-red-300">Delete</button>
                  </div>
                ))}
              </div>
            </div>
          )}

          {/* No saved views yet - show save button inline */}
          {savedViews.length === 0 && (searchTerm || statusFilter !== 'all' || environmentFilter !== 'all' || tagFilter.length > 0 || lifecycleFilter !== 'all') && !showSaveViewPrompt && (
            <div className="mb-4">
              <button
                onClick={() => setShowSaveViewPrompt(true)}
                className="px-3 py-1.5 bg-border hover:bg-border-strong text-content rounded text-sm"
              >
                Save Current Filters as View
              </button>
            </div>
          )}

          {/* Filters */}
          <div className="flex flex-col md:flex-row gap-4 mb-6">
            <div className="flex-1">
              <SearchInput
                placeholder="Search systems..."
                value={searchTerm}
                onChange={(e) => setSearchTerm(e.target.value)}
              />
            </div>
            <div className="flex gap-4">
              <Select
                value={statusFilter}
                onChange={(e) => setStatusFilter(e.target.value)}
              >
                <option value="all">All Statuses</option>
                <option value="Active">Active</option>
                <option value="Inactive">Inactive</option>
                <option value="Maintenance">Maintenance</option>
                <option value="Decommissioned">Decommissioned</option>
              </Select>
              <Select
                value={caTrustFilter}
                onChange={(e) => setCaTrustFilter(e.target.value as 'all' | 'enabled' | 'off')}
                title="Zero-trust CA filter"
              >
                <option value="all">All Zero-Trust</option>
                <option value="enabled">Zero-Trust Enabled</option>
                <option value="off">Zero-Trust Off</option>
              </Select>
              <Select
                value={environmentFilter}
                onChange={(e) => setEnvironmentFilter(e.target.value)}
              >
                <option value="all">All Environments</option>
                {environmentTypes.map((env) => (
                  <option key={env} value={env}>
                    {env}
                  </option>
                ))}
              </Select>
              <Select
                value={lifecycleFilter}
                onChange={(e) => setLifecycleFilter(e.target.value)}
                title="Distro lifecycle filter (server-side via /lifecycle/systems)"
              >
                <option value="all">All Lifecycle</option>
                <option value="supported">Supported</option>
                <option value="approaching-eol">Approaching EOL</option>
                <option value="unsupported">Unsupported</option>
                <option value="unknown">Unknown</option>
              </Select>
              <div className="relative">
                <button
                  onClick={() => setShowTagDropdown(!showTagDropdown)}
                  className="px-3 py-2 bg-white/[0.02] border border-border-strong rounded-md text-sm text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring whitespace-nowrap"
                >
                  Tags{tagFilter.length > 0 ? ` (${tagFilter.length})` : ''}
                </button>
                {showTagDropdown && (
                  <div className="absolute right-0 mt-1 w-56 bg-surface-overlay border border-border rounded-lg shadow-lg z-20 p-2">
                    {allTags.length === 0 ? (
                      <p className="text-content-subtle text-sm p-2">No tags available</p>
                    ) : (
                      allTags.map(tag => (
                        <label key={tag.id} className="flex items-center gap-2 py-1.5 px-2 cursor-pointer hover:bg-border rounded">
                          <input
                            type="checkbox"
                            checked={tagFilter.includes(tag.id)}
                            onChange={() => toggleTagFilter(tag.id)}
                            className="accent-red-600"
                          />
                          <span className="w-3 h-3 rounded-full inline-block flex-shrink-0" style={{ backgroundColor: tag.color }} />
                          <span className="text-content text-sm">{tag.name}</span>
                        </label>
                      ))
                    )}
                    {tagFilter.length > 0 && (
                      <button
                        onClick={() => setTagFilter([])}
                        className="w-full mt-1 px-2 py-1.5 text-xs text-content-muted hover:text-content border-t border-border-strong"
                      >
                        Clear tag filter
                      </button>
                    )}
                  </div>
                )}
              </div>
            </div>
          </div>

          {/* Bulk Action Toolbar */}
          {selectedSystems.length > 0 && canWrite && (
            <div className="flex items-center gap-3 mb-4 p-3 bg-surface-raised border border-border/60 rounded-lg">
              <span className="text-content text-sm font-medium">
                {selectedSystems.length} selected
              </span>
              <div className="flex gap-2 ml-auto">
                <button
                  onClick={() => setShowBulkAction('status')}
                  className="px-3 py-1.5 bg-border hover:bg-border-strong text-content rounded text-sm"
                >
                  Change Status
                </button>
                <button
                  onClick={() => setShowBulkAction('group')}
                  className="px-3 py-1.5 bg-border hover:bg-border-strong text-content rounded text-sm"
                >
                  Change Group
                </button>
                <button
                  onClick={() => setShowBulkAction('credential')}
                  className="px-3 py-1.5 bg-border hover:bg-border-strong text-content rounded text-sm"
                >
                  Assign Credential
                </button>
                <button
                  onClick={() => setShowBulkAction('deploy-ca')}
                  className="px-3 py-1.5 bg-border hover:bg-border-strong text-content rounded text-sm"
                >
                  Deploy CA Trust
                </button>
                <button
                  onClick={() => setShowBulkAction('delete')}
                  className="px-3 py-1.5 bg-red-700 hover:bg-red-600 text-white rounded text-sm"
                >
                  Delete Selected
                </button>
                <button
                  onClick={() => setSelectedSystems([])}
                  className="px-3 py-1.5 text-content-muted hover:text-content text-sm"
                >
                  Clear
                </button>
              </div>
            </div>
          )}

          {loading ? (
            <SkeletonTable rows={8} cols={6} />
          ) : filteredSystems.length === 0 ? (
            <EmptyState
              title={searchTerm || statusFilter !== 'all' || environmentFilter !== 'all' || tagFilter.length > 0
                ? 'No systems match your filters'
                : 'No systems registered yet'}
              description={searchTerm || statusFilter !== 'all' || environmentFilter !== 'all' || tagFilter.length > 0
                ? 'Try adjusting your search or filters'
                : 'Register your first system to get started'}
            />
          ) : (
            <div className="overflow-x-auto">
              <table className="min-w-full divide-y divide-border">
                <thead className="bg-surface-raised">
                  <tr>
                    {canWrite && (
                      <th scope="col" className="px-4 py-3 text-left">
                        <input
                          type="checkbox"
                          checked={selectedSystems.length === filteredSystems.length && filteredSystems.length > 0}
                          onChange={toggleSelectAll}
                          className="accent-red-600"
                        />
                      </th>
                    )}
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      Hostname
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      IP Address
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      Status
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      Distribution
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      Group
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      Tags
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      Environment
                    </th>
                    <th scope="col" className="px-6 py-3 text-center text-xs font-medium text-content uppercase tracking-wider whitespace-nowrap" title="Vault SSH CA trust deployed">
                      Zero-Trust
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider" title="Effective transport per host">
                      Transport
                    </th>
                    <th scope="col" className="px-6 py-3 text-left text-xs font-medium text-content uppercase tracking-wider">
                      Registered
                    </th>
                    <th scope="col" className="px-6 py-3 text-right text-xs font-medium text-content uppercase tracking-wider">
                      Actions
                    </th>
                  </tr>
                </thead>
                <tbody className="bg-surface-raised divide-y divide-border">
                  {paginatedSystems.map((system) => {
                    const isUnreachable = system.status === 'Unreachable';
                    return (
                    <tr key={system.id} className={`hover:bg-white/[0.03] even:bg-white/[0.012] ${selectedSystems.includes(system.id) ? 'bg-white/[0.02]' : ''} ${isUnreachable ? 'border-l-2 border-l-red-600/70' : 'border-l-2 border-l-transparent'}`}>
                      {canWrite && (
                        <td className="px-4 py-4">
                          <input
                            type="checkbox"
                            checked={selectedSystems.includes(system.id)}
                            onChange={() => toggleSelect(system.id)}
                            className="accent-red-600"
                          />
                        </td>
                      )}
                      <td className="px-6 py-4 whitespace-nowrap text-sm font-medium text-content">
                        <button
                          onClick={() => setDrawerSystem(system)}
                          className="text-content hover:text-red-400 transition-colors text-left focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring rounded"
                          title="Open quick view"
                        >
                          {system.hostname}
                        </button>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-content">
                        {system.ip_address}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <StatusBadge status={system.status} />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-content">
                        <span className="font-medium">{system.distro_name}</span>
                        <span className="ml-1 text-content-muted">{system.os_version}</span>
                        {eolMap[system.id] !== undefined && eolMap[system.id] < 0 && (
                          <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-red-900 text-red-300 border border-red-700">EOL</span>
                        )}
                        {eolMap[system.id] !== undefined && eolMap[system.id] >= 0 && (
                          <span className="ml-2 px-1.5 py-0.5 text-xs rounded bg-yellow-900 text-yellow-300 border border-yellow-700">EOL Soon</span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-content">
                        {system.group_name}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <div className="flex flex-wrap gap-1">
                          {system.tags && system.tags.length > 0 ? (
                            system.tags.map(tag => (
                              <span
                                key={tag.id}
                                className="px-2 py-0.5 rounded-full text-xs text-white"
                                style={{ backgroundColor: tag.color }}
                              >
                                {tag.name}
                              </span>
                            ))
                          ) : (
                            <span className="text-content-subtle text-xs">-</span>
                          )}
                        </div>
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-content">
                        {system.environment_type || 'N/A'}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-center">
                        {system.ca_trust_deployed ? (
                          <span className="inline-block px-2 py-0.5 text-xs rounded bg-green-900/50 text-green-400 border border-green-700" title="Vault SSH CA deployed">
                            enabled
                          </span>
                        ) : (
                          <span className="inline-block px-2 py-0.5 text-xs rounded bg-surface-overlay text-content-subtle border border-border-strong" title="Not yet deployed">
                            off
                          </span>
                        )}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap">
                        <TransportBadge
                          compact
                          badgeState={agentHealth[system.id]?.badge_state}
                        />
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-sm text-content">
                        {formatTimestamp(system.registered_at, { dateOnly: true })}
                      </td>
                      <td className="px-6 py-4 whitespace-nowrap text-right text-sm font-medium">
                        <div className="flex justify-end space-x-4">
                          <button
                            onClick={() => handleConnect(system.id)}
                            className="text-green-500 hover:text-green-400"
                            title="Open SSH session"
                          >
                            Connect
                          </button>
                          <button
                            onClick={() => handleViewDetails(system.id)}
                            className="text-red-500 hover:text-red-400"
                          >
                            View
                          </button>
                          {canWrite && (
                            <button
                              onClick={() => handleDeleteClick(system)}
                              className="text-content-muted hover:text-red-400"
                            >
                              Delete
                            </button>
                          )}
                        </div>
                      </td>
                    </tr>
                    );
                  })}
                </tbody>
              </table>
            </div>
          )}
          {filteredSystems.length > pageLimit && (
            <Pagination
              offset={pageOffset}
              limit={pageLimit}
              total={filteredSystems.length}
              onPageChange={setPageOffset}
            />
          )}
          </CardBody>
        </Card>

      {/* Delete Confirmation Dialog */}
      <ConfirmModal
        open={showDeleteConfirm && !!systemToDelete}
        onClose={handleDeleteCancel}
        onConfirm={handleDeleteConfirm}
        title="Confirm Delete"
        message={`Are you sure you want to delete the system ${systemToDelete?.hostname || ''}? This action cannot be undone.`}
        confirmLabel={deleteLoading ? 'Deleting...' : 'Delete System'}
        variant="danger"
        loading={deleteLoading}
      />

      {/* Bulk Change Status Modal */}
      {showBulkAction === 'status' && (
        <div className="fixed inset-0 bg-surface/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 max-w-lg w-full">
            <h3 className="text-xl font-semibold text-content mb-4">Change Status</h3>
            <p className="text-content mb-4">
              Update the status of <span className="font-semibold text-white">{selectedSystems.length}</span> selected system{selectedSystems.length !== 1 ? 's' : ''}.
            </p>
            <select
              value={bulkStatusValue}
              onChange={(e) => setBulkStatusValue(e.target.value)}
              className={`w-full mb-6 px-3 py-2 border border-border rounded-md ${nativeSelectClass}`}
            >
              <option value="Active">Active</option>
              <option value="Inactive">Inactive</option>
              <option value="Maintenance">Maintenance</option>
              <option value="Decommissioned">Decommissioned</option>
            </select>
            <div className="flex justify-end space-x-4">
              <button
                onClick={() => setShowBulkAction(null)}
                disabled={bulkLoading}
                className="px-4 py-2 bg-border hover:bg-border-strong text-content rounded-md"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkStatusChange}
                disabled={bulkLoading}
                className={`px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md ${bulkLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {bulkLoading ? 'Updating...' : 'Update Status'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Change Group Modal */}
      {showBulkAction === 'group' && (
        <div className="fixed inset-0 bg-surface/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 max-w-lg w-full">
            <h3 className="text-xl font-semibold text-content mb-4">Change Group</h3>
            <p className="text-content mb-4">
              Move <span className="font-semibold text-white">{selectedSystems.length}</span> selected system{selectedSystems.length !== 1 ? 's' : ''} to a new group.
            </p>
            <select
              value={bulkGroupValue}
              onChange={(e) => setBulkGroupValue(Number(e.target.value))}
              className={`w-full mb-6 px-3 py-2 border border-border rounded-md ${nativeSelectClass}`}
            >
              <option value={0}>Select a group...</option>
              {groups.map(g => (
                <option key={g.id} value={g.id}>{g.name}</option>
              ))}
            </select>
            <div className="flex justify-end space-x-4">
              <button
                onClick={() => setShowBulkAction(null)}
                disabled={bulkLoading}
                className="px-4 py-2 bg-border hover:bg-border-strong text-content rounded-md"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkGroupChange}
                disabled={bulkLoading || !bulkGroupValue}
                className={`px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md ${bulkLoading || !bulkGroupValue ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {bulkLoading ? 'Updating...' : 'Update Group'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Assign Credential Modal */}
      {showBulkAction === 'credential' && (
        <div className="fixed inset-0 bg-surface/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 max-w-lg w-full">
            <h3 className="text-xl font-semibold text-content mb-4">Assign Credential</h3>
            <p className="text-content mb-4">
              Assign a credential to <span className="font-semibold text-white">{selectedSystems.length}</span> selected system{selectedSystems.length !== 1 ? 's' : ''}.
            </p>
            <select
              value={bulkCredentialValue}
              onChange={(e) => setBulkCredentialValue(Number(e.target.value))}
              className={`w-full mb-6 px-3 py-2 border border-border rounded-md ${nativeSelectClass}`}
            >
              <option value={0}>Select a credential...</option>
              {credentials.map(c => (
                <option key={c.id} value={c.id}>{c.name} ({c.auth_method})</option>
              ))}
            </select>
            <div className="flex justify-end space-x-4">
              <button
                onClick={() => setShowBulkAction(null)}
                disabled={bulkLoading}
                className="px-4 py-2 bg-border hover:bg-border-strong text-content rounded-md"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkCredentialAssign}
                disabled={bulkLoading || !bulkCredentialValue}
                className={`px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md ${bulkLoading || !bulkCredentialValue ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {bulkLoading ? 'Assigning...' : 'Assign Credential'}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Deploy CA Trust Confirmation Modal */}
      {showBulkAction === 'deploy-ca' && (
        <div className="fixed inset-0 bg-surface/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 max-w-lg w-full">
            <h3 className="text-xl font-semibold text-content mb-4">Deploy CA Trust</h3>
            <div className="mb-6 p-3 bg-surface-sunken border border-border-strong rounded text-sm text-content">
              Deploy the Vault SSH CA public key to <span className="font-semibold text-white">{selectedSystems.length}</span> system{selectedSystems.length !== 1 ? 's' : ''}. Each system will have its sshd_config updated and reloaded. Systems already deployed will be skipped silently.
            </div>
            <div className="flex justify-end space-x-4">
              <button onClick={() => setShowBulkAction(null)} disabled={bulkLoading}
                className="px-4 py-2 bg-border hover:bg-border-strong text-content rounded-md">
                Cancel
              </button>
              <button onClick={handleBulkDeployCA} disabled={bulkLoading}
                className={`px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-md ${bulkLoading ? 'opacity-50 cursor-not-allowed' : ''}`}>
                {bulkLoading ? 'Deploying...' : `Deploy to ${selectedSystems.length} System${selectedSystems.length !== 1 ? 's' : ''}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Bulk Delete Confirmation Modal */}
      {showBulkAction === 'delete' && (
        <div className="fixed inset-0 bg-surface/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 max-w-lg w-full">
            <h3 className="text-xl font-semibold text-content mb-4">Delete Systems</h3>
            <div className="mb-6 p-3 bg-red-900/30 border border-red-700 rounded text-sm text-red-300">
              You are about to permanently delete <span className="font-semibold text-white">{selectedSystems.length}</span> system{selectedSystems.length !== 1 ? 's' : ''}. This action cannot be undone.
            </div>
            <div className="flex justify-end space-x-4">
              <button
                onClick={() => setShowBulkAction(null)}
                disabled={bulkLoading}
                className="px-4 py-2 bg-border hover:bg-border-strong text-content rounded-md"
              >
                Cancel
              </button>
              <button
                onClick={handleBulkDelete}
                disabled={bulkLoading}
                className={`px-4 py-2 bg-red-700 hover:bg-red-600 text-white rounded-md ${bulkLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                {bulkLoading ? 'Deleting...' : `Delete ${selectedSystems.length} System${selectedSystems.length !== 1 ? 's' : ''}`}
              </button>
            </div>
          </div>
        </div>
      )}

      {/* Import Systems Modal */}
      {showBulkAction === 'import' && (
        <div className="fixed inset-0 bg-surface/70 backdrop-blur-sm flex items-center justify-center z-50">
          <div className="bg-surface-overlay border border-border rounded-lg p-6 max-w-3xl w-full max-h-[90vh] overflow-y-auto">
            <h3 className="text-xl font-semibold text-content mb-4">Import Systems</h3>
            <p className="text-content-muted text-sm mb-4">
              Provide a JSON array of systems. Required: <code className="text-red-400">hostname</code>, <code className="text-red-400">ip_address</code>, <code className="text-red-400">distro</code>, <code className="text-red-400">group</code>, <code className="text-red-400">credential</code>. Optional: <code className="text-content-subtle">status</code>, <code className="text-content-subtle">environment</code>, <code className="text-content-subtle">tags</code>. You can also use IDs (distro_id, group_id, credentials_id) instead of names.
            </p>

            <div className="mb-4">
              <label className="block text-content text-sm font-medium mb-2">Upload JSON file</label>
              <input
                ref={fileInputRef}
                type="file"
                accept=".json"
                onChange={handleImportFileUpload}
                className="block w-full text-sm text-content-muted file:mr-4 file:py-2 file:px-4 file:rounded file:border-0 file:text-sm file:bg-border file:text-content hover:file:bg-border-strong"
              />
            </div>

            <div className="mb-4">
              <label className="block text-content text-sm font-medium mb-2">Or paste JSON</label>
              <textarea
                value={importText}
                onChange={(e) => setImportText(e.target.value)}
                rows={8}
                placeholder='[{"hostname": "web-01", "ip_address": "10.0.0.1", "distro": "Ubuntu", "group": "All Systems", "credential": "default"}]'
                className="w-full px-3 py-2 bg-surface-sunken border border-border rounded-md text-content font-mono text-sm focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
              />
              <button
                onClick={() => parseImportJson(importText)}
                disabled={!importText.trim()}
                className={`mt-2 px-3 py-1.5 bg-border hover:bg-border-strong text-content rounded text-sm ${!importText.trim() ? 'opacity-50 cursor-not-allowed' : ''}`}
              >
                Parse JSON
              </button>
            </div>

            {importParseError && (
              <div className="mb-4 p-3 bg-red-900/30 border border-red-700 rounded text-sm text-red-300">
                {importParseError}
              </div>
            )}

            {importParsed.length > 0 && !importResults && (
              <div className="mb-4">
                <h4 className="text-content text-sm font-medium mb-2">Preview ({importParsed.length} system{importParsed.length !== 1 ? 's' : ''})</h4>
                <div className="overflow-x-auto max-h-48 overflow-y-auto border border-border-strong rounded">
                  <table className="min-w-full text-sm">
                    <thead className="bg-surface-sunken">
                      <tr>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Hostname</th>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">IP Address</th>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Distro</th>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Group</th>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Credential</th>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Status</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-strong">
                      {importParsed.map((sys, idx) => (
                        <tr key={idx} className="text-content">
                          <td className="px-3 py-2">{sys.hostname}</td>
                          <td className="px-3 py-2">{sys.ip_address}</td>
                          <td className="px-3 py-2">{sys.distro || sys.distro_id}</td>
                          <td className="px-3 py-2">{sys.group || sys.group_id}</td>
                          <td className="px-3 py-2">{sys.credential || sys.credentials_id}</td>
                          <td className="px-3 py-2">{sys.status || 'Active'}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            {importResults && (
              <div className="mb-4">
                <h4 className="text-content text-sm font-medium mb-2">Results</h4>
                <div className="overflow-x-auto max-h-48 overflow-y-auto border border-border-strong rounded">
                  <table className="min-w-full text-sm">
                    <thead className="bg-surface-sunken">
                      <tr>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Hostname</th>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Status</th>
                        <th scope="col" className="px-3 py-2 text-left text-xs text-content-muted">Message</th>
                      </tr>
                    </thead>
                    <tbody className="divide-y divide-border-strong">
                      {importResults.map((r, idx) => (
                        <tr key={idx} className="text-content">
                          <td className="px-3 py-2">{r.hostname}</td>
                          <td className="px-3 py-2">
                            <StatusBadge status={r.status} />
                          </td>
                          <td className="px-3 py-2 text-content-muted">{r.message}</td>
                        </tr>
                      ))}
                    </tbody>
                  </table>
                </div>
              </div>
            )}

            <div className="flex justify-end space-x-3">
              <button
                onClick={closeImportModal}
                disabled={bulkLoading}
                className="px-4 py-2 bg-border hover:bg-border-strong text-content rounded-md"
              >
                {importResults ? 'Close' : 'Cancel'}
              </button>
              {importParsed.length > 0 && !importResults && (
                <>
                  <button
                    onClick={handleImportDryRun}
                    disabled={bulkLoading}
                    className={`px-4 py-2 bg-border hover:bg-border-strong text-content rounded-md ${bulkLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    {bulkLoading ? 'Running...' : 'Dry Run'}
                  </button>
                  <button
                    onClick={handleImportConfirm}
                    disabled={bulkLoading}
                    className={`px-4 py-2 bg-red-600 hover:bg-red-700 text-white rounded-md ${bulkLoading ? 'opacity-50 cursor-not-allowed' : ''}`}
                  >
                    {bulkLoading ? 'Importing...' : `Import ${importParsed.length} System${importParsed.length !== 1 ? 's' : ''}`}
                  </button>
                </>
              )}
            </div>
          </div>
        </div>
      )}

      <DetailDrawer
        open={drawerSystem !== null}
        onClose={() => setDrawerSystem(null)}
        title={drawerSystem?.hostname || ''}
        subtitle={drawerSystem ? `${drawerSystem.ip_address} · ${drawerSystem.distro_name} ${drawerSystem.os_version}` : undefined}
        actions={
          drawerSystem ? (
            <>
              <Button variant="outline" onClick={() => setDrawerSystem(null)}>Close</Button>
              <Button
                variant="primary"
                onClick={() => {
                  router.push(`/system-management/system/${drawerSystem.id}`);
                  setDrawerSystem(null);
                }}
              >
                Open full page
              </Button>
            </>
          ) : null
        }
      >
        {drawerSystem && (
          <div className="space-y-5">
            <div className="grid grid-cols-2 gap-x-4 gap-y-3 text-sm">
              <div>
                <div className="text-xs text-content-subtle uppercase tracking-wider">Status</div>
                <div className="mt-1"><StatusBadge status={drawerSystem.status} /></div>
              </div>
              <div>
                <div className="text-xs text-content-subtle uppercase tracking-wider">Group</div>
                <div className="mt-1 text-content">{drawerSystem.group_name}</div>
              </div>
              <div>
                <div className="text-xs text-content-subtle uppercase tracking-wider">Environment</div>
                <div className="mt-1 text-content">{drawerSystem.environment_type || '-'}</div>
              </div>
              <div>
                <div className="text-xs text-content-subtle uppercase tracking-wider">Registered</div>
                <div className="mt-1 text-content">{formatTimestamp(drawerSystem.registered_at)}</div>
              </div>
              <div>
                <div className="text-xs text-content-subtle uppercase tracking-wider">CA Trust</div>
                <div className="mt-1 text-content">
                  {drawerSystem.ca_trust_deployed ? (
                    <span className="text-emerald-400">Deployed</span>
                  ) : (
                    <span className="text-content-subtle">Off</span>
                  )}
                </div>
              </div>
              {eolMap[drawerSystem.id] !== undefined && (
                <div>
                  <div className="text-xs text-content-subtle uppercase tracking-wider">EOL Status</div>
                  <div className="mt-1">
                    {eolMap[drawerSystem.id] < 0 ? (
                      <span className="text-red-400">EOL ({Math.abs(eolMap[drawerSystem.id])} days ago)</span>
                    ) : (
                      <span className="text-yellow-400">EOL in {eolMap[drawerSystem.id]} days</span>
                    )}
                  </div>
                </div>
              )}
            </div>

            {drawerSystem.tags && drawerSystem.tags.length > 0 && (
              <div>
                <div className="text-xs text-content-subtle uppercase tracking-wider mb-2">Tags</div>
                <div className="flex flex-wrap gap-1.5">
                  {drawerSystem.tags.map((t) => (
                    <span
                      key={t.id}
                      className="px-2 py-0.5 rounded-full text-xs border"
                      style={{ borderColor: t.color, color: t.color }}
                    >
                      {t.name}
                    </span>
                  ))}
                </div>
              </div>
            )}
          </div>
        )}
      </DetailDrawer>
    </MainLayout>
  );
};

export default AllSystems;
