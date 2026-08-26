import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import Pagination from '@/components/Pagination';
import { fetchAllSystems } from '@/services/systemService';
import { useLatestRequest } from '@/hooks/useLatestRequest';
import {
  fetchAllUpdates,
  fetchSystemUpdates,
  applyUpdates,
  scanPackages,
  fetchPackages,
  PackageUpdateItem,
  ApplyUpdatesResult,
} from '@/services/packageService';
import { notifyRebootStatus } from '@/utils/rebootStatus';
import { ChevronUp, ChevronDown, Search, CheckCircle2, Download } from 'lucide-react';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, Card, CardBody, StatCard, ConfirmModal, EmptyState } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { useUrlState } from '@/hooks/useUrlState';
import Link from 'next/link';
import { usePackageScope } from '@/hooks/usePackageScope';
import PackageScopeControl from '@/components/packages/PackageScopeControl';
import CohortScanButton from '@/components/packages/CohortScanButton';
import { isScopeReady } from '@/services/packageScope';
import { deriveLastChecked } from '@/utils/lastChecked';

interface SystemOption {
  id: number;
  hostname: string;
  // PRA-348: durable last-scan timestamp from the backend, used to rehydrate
  // "Last checked" across navigation/reload.
  last_audited?: string | null;
}

interface ConfirmState {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  variant: 'danger' | 'warning';
  onConfirm: () => void;
}

const AvailableUpdates = () => {
  const formatTimestamp = useFormatTimestamp();
  const [systems, setSystems] = useState<SystemOption[]>([]);
  // Cohort scope (all / system / group / smart group). A single-system
  // scope preserves the original per-system behavior; every other scope is an
  // aggregate that funnels through the scoped `/updates/all` endpoint.
  const { scope, setScope, systems: scopeSystems, groups, smartGroups, ready } = usePackageScope();
  const selectedSystem: number | 'all' =
    scope.type === 'system' && scope.id != null ? scope.id : 'all';
  const scopeReady = isScopeReady(scope);
  const cohort =
    scope.type === 'group'
      ? groups.find((g) => g.id === scope.id)
      : scope.type === 'smart_group'
        ? smartGroups.find((g) => g.id === scope.id)
        : null;
  const [updates, setUpdates] = useState<PackageUpdateItem[]>([]);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [updating, setUpdating] = useState(false);
  const [updatingPackage, setUpdatingPackage] = useState<number | null>(null);
  const [heldPackageNames, setHeldPackageNames] = useState<Set<string>>(new Set());
  const [search, setSearch] = useUrlState('search', '');
  const [sortKey, setSortKey] = useState<'package_name' | 'update_type' | 'system_id' | 'discovered_on'>('package_name');
  const [sortDir, setSortDir] = useState<'asc' | 'desc'>('asc');
  const [pageOffset, setPageOffset] = useState(0);
  const pageLimit = 25;
  const [confirm, setConfirm] = useState<ConfirmState>({
    open: false, title: '', message: '', confirmLabel: 'Confirm', variant: 'danger', onConfirm: () => {},
  });

  const closeConfirm = () => setConfirm((prev) => ({ ...prev, open: false }));

  useEffect(() => {
    fetchAllSystems()
      .then((data) => {
        setSystems(
          data.map((s) => ({ id: s.id, hostname: s.hostname, last_audited: s.last_audited })),
        );
      })
      .catch(() => toast.error('Failed to load systems'));
  }, []);

  // PRA-348: "Last checked" is derived from the durable backend `last_audited`,
  // not local-only state, so it survives navigation/reload.
  const lastChecked = useMemo(
    () => deriveLastChecked(systems, selectedSystem),
    [systems, selectedSystem],
  );

  // PRA-256: independent request streams (updates list vs held-package set) each
  // get their own latest-request guard so a stale response can't clobber current
  // state, and so the two streams don't invalidate each other.
  const beginUpdatesRequest = useLatestRequest();
  const beginHeldRequest = useLatestRequest();

  const loadUpdates = useCallback(async () => {
    // A cohort scope with no target selected must never fall back to a fleet-wide
    // query - hold until a target exists and show the select-a-target prompt.
    if (!ready || !isScopeReady(scope)) {
      setUpdates([]);
      setLoading(false);
      return;
    }
    const isCurrent = beginUpdatesRequest();
    setLoading(true);
    try {
      const data =
        scope.type === 'system' && scope.id != null
          ? await fetchSystemUpdates(scope.id)
          : await fetchAllUpdates(scope);
      if (!isCurrent()) return;
      setUpdates(data);
    } catch (err) {
      if (!isCurrent()) return;
      toast.error(err instanceof Error ? err.message : 'Failed to load updates');
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [scope, ready, beginUpdatesRequest]);

  useEffect(() => {
    loadUpdates();
  }, [loadUpdates]);

  useEffect(() => {
    if (selectedSystem === 'all') {
      setHeldPackageNames(new Set());
      return;
    }
    const isCurrent = beginHeldRequest();
    fetchPackages(selectedSystem, undefined, 10000, 0)
      .then((data) => {
        if (!isCurrent()) return;
        const held = new Set(data.packages.filter((p) => p.is_held).map((p) => p.name));
        setHeldPackageNames(held);
      })
      .catch(() => {
        if (!isCurrent()) return;
        setHeldPackageNames(new Set());
      });
  }, [selectedSystem, beginHeldRequest]);

  const handleScan = async () => {
    if (selectedSystem === 'all') return;
    setScanning(true);
    try {
      const result = await scanPackages(selectedSystem);
      if (result.status === 'success') {
        toast.success(
          `Scan complete: ${result.packages_found} packages found, ${result.updates_available} updates available`
        );
        // PRA-348: reflect the new scan time on the matching system so the derived
        // "Last checked" updates immediately (and stays consistent with a reload).
        setSystems((prev) =>
          prev.map((s) =>
            s.id === selectedSystem ? { ...s, last_audited: result.scanned_at } : s,
          ),
        );
        loadUpdates();
      } else if (result.status === 'already_running') {
        toast.info(result.message || 'A scan is already running for this host');
      } else {
        toast.error(result.message || 'Scan failed');
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Scan failed');
    } finally {
      setScanning(false);
    }
  };

  const reportRebootStatus = (result: ApplyUpdatesResult) => {
    notifyRebootStatus(result, toast);
  };

  const handleUpdateAll = () => {
    if (selectedSystem === 'all') return;
    const hostname = getSystemHostname(selectedSystem);
    const unheldUpdates = updates.filter((u) => !heldPackageNames.has(u.package_name));
    const heldCount = updates.length - unheldUpdates.length;
    if (unheldUpdates.length === 0) {
      toast.error('All packages are held. Unhold packages before updating.');
      return;
    }
    setConfirm({
      open: true,
      title: 'Update All Packages',
      message: `Update ${unheldUpdates.length} packages on ${hostname}?${heldCount > 0 ? ` ${heldCount} held package(s) will be skipped.` : ''} This will run the update command on the remote system.`,
      confirmLabel: 'Update All',
      variant: 'danger',
      onConfirm: async () => {
        closeConfirm();
        setUpdating(true);
        try {
          const packageNames = unheldUpdates.map((u) => u.package_name);
          const result = await applyUpdates(selectedSystem, packageNames);
          if (result.status === 'success') {
            toast.success(`Updated ${result.packages_updated} package(s) on ${result.hostname}`);
            reportRebootStatus(result);
            if (heldCount > 0) {
              toast.info(`${heldCount} held package(s) skipped`);
            }
            loadUpdates();
          } else {
            toast.error(result.message || 'Update failed');
          }
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Update failed');
        } finally {
          setUpdating(false);
        }
      },
    });
  };

  const handleUpdateSingle = (updateId: number, systemId: number, packageName: string) => {
    if (heldPackageNames.has(packageName)) {
      toast.error(`${packageName} is held. Unhold it before updating.`);
      return;
    }
    const hostname = getSystemHostname(systemId);
    setConfirm({
      open: true,
      title: 'Update Package',
      message: `Update ${packageName} on ${hostname}? This will run the update command on the remote system.`,
      confirmLabel: 'Update',
      variant: 'danger',
      onConfirm: async () => {
        closeConfirm();
        setUpdatingPackage(updateId);
        try {
          const result = await applyUpdates(systemId, [packageName]);
          if (result.status === 'success' && result.packages_updated > 0) {
            toast.success(`Updated ${packageName} on ${result.hostname}`);
            reportRebootStatus(result);
            loadUpdates();
          } else if (result.message) {
            toast.error(result.message);
          } else {
            toast.error(`Failed to update ${packageName}`);
          }
        } catch (err) {
          toast.error(err instanceof Error ? err.message : `Failed to update ${packageName}`);
        } finally {
          setUpdatingPackage(null);
        }
      },
    });
  };

  const getSystemHostname = useCallback((systemId: number) => {
    const sys = systems.find((s) => s.id === systemId);
    return sys ? sys.hostname : String(systemId);
  }, [systems]);

  const filteredUpdates = useMemo(() => {
    let result = updates;
    if (search.trim()) {
      const q = search.toLowerCase();
      result = result.filter(
        (u) =>
          u.package_name.toLowerCase().includes(q) ||
          getSystemHostname(u.system_id).toLowerCase().includes(q) ||
          u.update_type.toLowerCase().includes(q)
      );
    }
    result = [...result].sort((a, b) => {
      // Always pin security updates to the top regardless of user sort - they need attention first.
      const aSec = a.update_type === 'security' ? 0 : 1;
      const bSec = b.update_type === 'security' ? 0 : 1;
      if (aSec !== bSec) return aSec - bSec;

      let cmp = 0;
      switch (sortKey) {
        case 'package_name':
          cmp = a.package_name.localeCompare(b.package_name);
          break;
        case 'update_type':
          cmp = a.update_type.localeCompare(b.update_type);
          break;
        case 'system_id':
          cmp = getSystemHostname(a.system_id).localeCompare(getSystemHostname(b.system_id));
          break;
        case 'discovered_on':
          cmp = (a.discovered_on || '').localeCompare(b.discovered_on || '');
          break;
      }
      return sortDir === 'asc' ? cmp : -cmp;
    });
    return result;
  }, [updates, search, sortKey, sortDir, getSystemHostname]);

  const toggleSort = (key: typeof sortKey) => {
    if (sortKey === key) {
      setSortDir(sortDir === 'asc' ? 'desc' : 'asc');
    } else {
      setSortKey(key);
      setSortDir('asc');
    }
  };

  const SortIcon = ({ col }: { col: typeof sortKey }) => {
    if (sortKey !== col) return <ChevronUp size={14} className="opacity-30" />;
    return sortDir === 'asc' ? <ChevronUp size={14} /> : <ChevronDown size={14} />;
  };

  useEffect(() => { setPageOffset(0); }, [search, sortKey, sortDir, scope]);

  const paginatedUpdates = filteredUpdates.slice(pageOffset, pageOffset + pageLimit);

  const securityCount = updates.filter((u) => u.update_type === 'security').length;
  const uniqueSystems = new Set(updates.map((u) => u.system_id)).size;

  return (
    <MainLayout>
        <Head>
          <title>Available Updates | Praxis</title>
        </Head>
      <PageHeader title="Available Updates" actions={<HelpLink slug="packages" />} />
      <Card>
        <CardBody>
          <div className="mb-6">
            <div className="flex flex-wrap justify-between items-end gap-3">
              <PackageScopeControl
                value={scope}
                onChange={setScope}
                systems={scopeSystems}
                groups={groups}
                smartGroups={smartGroups}
              />
              <div className="flex flex-wrap items-center gap-3">
                {scope.type === 'system' && (
                  <>
                    <Button
                      variant="outline"
                      onClick={handleScan}
                      disabled={scanning}
                      loading={scanning}
                    >
                      {scanning ? 'Checking...' : 'Check for Updates'}
                    </Button>
                    <Button
                      variant="primary"
                      onClick={handleUpdateAll}
                      disabled={updating || updates.length === 0}
                      loading={updating}
                    >
                      {updating ? 'Updating...' : 'Update All'}
                    </Button>
                  </>
                )}
                {cohort && (
                  <>
                    <CohortScanButton
                      scope={scope}
                      scopeName={cohort.name}
                      hostCount={cohort.member_count}
                      label="Check for updates"
                      onComplete={loadUpdates}
                    />
                    <Link
                      href="/patch-update-plans/all"
                      className="text-sm text-link hover:text-link-hover"
                    >
                      Apply updates for this cohort in Update Plans &rarr;
                    </Link>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <StatCard label="Available Updates" value={updates.length} subtitle={`across ${uniqueSystems} ${uniqueSystems === 1 ? 'system' : 'systems'}`} />
            <StatCard label="Security Updates" value={securityCount} subtitle="Critical security patches" />
            <StatCard label="Systems to Update" value={uniqueSystems} subtitle="Systems needing updates" />
          </div>

          {/* Search */}
          <div className="mb-4 relative">
            <Search size={16} className="absolute left-3 top-1/2 -translate-y-1/2 text-content-subtle" />
            <input
              type="text"
              placeholder="Search by package name, system, or type..."
              value={search}
              onChange={(e) => setSearch(e.target.value)}
              className="w-full pl-9 pr-3 py-2 bg-surface-sunken border border-border-strong rounded text-sm text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring focus-visible:border-border-strong"
            />
          </div>

          <div className="border border-border rounded-lg">
            <div className="grid grid-cols-[1.4fr_1.6fr_1.6fr_0.7fr_1fr_0.9fr_0.7fr] gap-3 p-4 bg-surface-sunken border-b border-border font-medium text-content">
              <button onClick={() => toggleSort('package_name')} className="flex items-center gap-1 hover:text-white">
                Package Name <SortIcon col="package_name" />
              </button>
              <div>Current Version</div>
              <div>New Version</div>
              <button onClick={() => toggleSort('update_type')} className="flex items-center gap-1 hover:text-white">
                Type <SortIcon col="update_type" />
              </button>
              <button onClick={() => toggleSort('system_id')} className="flex items-center gap-1 hover:text-white">
                System <SortIcon col="system_id" />
              </button>
              <button onClick={() => toggleSort('discovered_on')} className="flex items-center gap-1 hover:text-white">
                Discovered <SortIcon col="discovered_on" />
              </button>
              <div>Actions</div>
            </div>
            {!scopeReady ? (
              <EmptyState
                title="Select a scope target"
                description="Choose a group or smart group above to view its available updates."
              />
            ) : loading ? (
              <div className="p-4 text-content-muted">Loading updates...</div>
            ) : filteredUpdates.length === 0 ? (
              <EmptyState
                icon={<CheckCircle2 size={24} className="text-emerald-400" />}
                title={search ? 'No matching updates' : 'All packages are up to date'}
                description={
                  search
                    ? 'Try a different search term, or clear the search to see all available updates.'
                    : 'Praxis will surface new updates here when they appear. Run a scan from a system page to refresh now.'
                }
              />
            ) : (
              paginatedUpdates.map((update) => {
                const isHeld = heldPackageNames.has(update.package_name);
                const isSecurity = update.update_type === 'security';
                return (
                  <div
                    key={update.id}
                    className={`grid grid-cols-[1.4fr_1.6fr_1.6fr_0.7fr_1fr_0.9fr_0.7fr] gap-3 p-4 border-b border-border last:border-b-0 hover:bg-surface-overlay even:bg-white/[0.012] ${isSecurity ? 'border-l-2 border-l-red-600/70' : 'border-l-2 border-l-transparent'}`}
                  >
                    <div className="font-medium text-content break-words">
                      {update.package_name}
                      {isHeld && (
                        <span className="ml-2 px-1.5 py-0.5 bg-yellow-900 text-yellow-300 rounded text-xs align-middle">Held</span>
                      )}
                    </div>
                    <div className="text-content-muted font-mono text-xs break-all">{update.installed_version}</div>
                    <div className="text-content font-mono text-xs break-all">{update.available_version}</div>
                    <div>
                      <span
                        className={`px-2 py-1 rounded text-sm ${
                          update.update_type === 'security'
                            ? 'bg-red-900 text-red-300'
                            : 'bg-surface-overlay text-content'
                        }`}
                      >
                        {update.update_type}
                      </span>
                    </div>
                    <div className="text-content-muted">{getSystemHostname(update.system_id)}</div>
                    <div className="text-content-muted text-sm">
                      {formatTimestamp(update.discovered_on, { dateOnly: true })}
                    </div>
                    <div>
                      {/* PRA-270: quiet icon action per row; the primary emphasis
                          lives on the single page-level "Update All", and the
                          confirmation modal carries the danger treatment. */}
                      <Button
                        variant="ghost"
                        size="sm"
                        iconOnly
                        icon={<Download size={16} />}
                        aria-label={`Update ${update.package_name}`}
                        title={isHeld ? 'Held - unhold before updating' : 'Update package'}
                        onClick={() => handleUpdateSingle(update.id, update.system_id, update.package_name)}
                        disabled={updatingPackage === update.id || isHeld}
                        loading={updatingPackage === update.id}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {filteredUpdates.length > pageLimit && (
            <Pagination
              offset={pageOffset}
              limit={pageLimit}
              total={filteredUpdates.length}
              onPageChange={setPageOffset}
            />
          )}

          <div className="mt-4 flex justify-between text-sm text-content-muted">
            <span>
              {search.trim() && filteredUpdates.length !== updates.length
                ? `${filteredUpdates.length} of ${updates.length} updates match "${search.trim()}"`
                : ''}
            </span>
            <span>Last checked: {lastChecked ? formatTimestamp(lastChecked) : 'Never'}</span>
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

export default AvailableUpdates;
