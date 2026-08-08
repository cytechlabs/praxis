import React, { useState, useEffect, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { fetchAllSystems } from '@/services/systemService';
import { fetchPackages, fetchScopedInventory, scanPackages, holdPackages, unholdPackages, removePackages, PackageItem, ScopedPackageRow } from '@/services/packageService';
import ExportButton from '@/components/ExportButton';
import { Box, Trash2, Lock, Unlock } from 'lucide-react';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, Card, CardBody, StatCard, ConfirmModal, EmptyState, Badge } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { useLatestRequest } from '@/hooks/useLatestRequest';
import { useDebouncedValue } from '@/hooks/useDebouncedValue';
import { usePackageScope } from '@/hooks/usePackageScope';
import PackageScopeControl from '@/components/packages/PackageScopeControl';
import CohortScanButton from '@/components/packages/CohortScanButton';
import { isAggregateScope, isScopeReady } from '@/services/packageScope';

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

const PackageInventory = () => {
  const formatTimestamp = useFormatTimestamp();
  const [systems, setSystems] = useState<SystemOption[]>([]);
  // Cohort scope. A single-system scope keeps the full per-host
  // inventory with hold/unhold/remove/scan actions; every other scope is an
  // aggregate, read-only view whose rows identify the host each package is on.
  const { scope, setScope, systems: scopeSystems, groups, smartGroups, ready } = usePackageScope();
  const selectedSystem: number | null =
    scope.type === 'system' && scope.id != null ? scope.id : null;
  const aggregate = isAggregateScope(scope);
  const scopeReady = isScopeReady(scope);
  const cohort =
    scope.type === 'group'
      ? groups.find((g) => g.id === scope.id)
      : scope.type === 'smart_group'
        ? smartGroups.find((g) => g.id === scope.id)
        : null;
  const [packages, setPackages] = useState<PackageItem[]>([]);
  const [aggRows, setAggRows] = useState<ScopedPackageRow[]>([]);
  const [total, setTotal] = useState(0);
  const [search, setSearch] = useState('');
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [scanning, setScanning] = useState(false);
  const [holdingPackage, setHoldingPackage] = useState<string | null>(null);
  const [removingPackage, setRemovingPackage] = useState<string | null>(null);
  const [lastScan, setLastScan] = useState<string | null>(null);
  const [confirm, setConfirm] = useState<ConfirmState>({
    open: false, title: '', message: '', confirmLabel: 'Confirm', variant: 'danger', onConfirm: () => {},
  });
  const limit = 50;

  const closeConfirm = () => setConfirm((prev) => ({ ...prev, open: false }));

  // PRA-256: debounce the search box so fast typing doesn't flood the backend,
  // and guard package fetches so an older response can't clobber newer state.
  const debouncedSearch = useDebouncedValue(search, 300);
  const beginPackagesRequest = useLatestRequest();

  useEffect(() => {
    fetchAllSystems()
      .then((data) => {
        setSystems(data.map((s) => ({ id: s.id, hostname: s.hostname })));
      })
      .catch(() => toast.error('Failed to load systems'));
  }, []);

  const loadPackages = useCallback(async () => {
    // A cohort scope with no target must never widen to a fleet-wide query.
    if (!ready || !isScopeReady(scope)) {
      setPackages([]);
      setAggRows([]);
      setTotal(0);
      setLoading(false);
      return;
    }
    // PRA-256: this fetch is superseded the moment the user changes scope/
    // search/page. Gate EVERY state write below on isCurrent() so a stale
    // response cannot overwrite newer data, clear a newer loading state, or
    // show a stale error.
    const isCurrent = beginPackagesRequest();
    setLoading(true);
    try {
      if (scope.type === 'system' && scope.id != null) {
        const data = await fetchPackages(scope.id, debouncedSearch || undefined, limit, offset);
        if (!isCurrent()) return;
        setPackages(data.packages);
        setAggRows([]);
        setTotal(data.total);
      } else {
        // Aggregate (fleet / group / smart group) inventory with hostnames.
        const data = await fetchScopedInventory(scope, debouncedSearch || undefined, limit, offset);
        if (!isCurrent()) return;
        setAggRows(data.packages);
        setPackages([]);
        setTotal(data.total);
      }
    } catch (err) {
      if (!isCurrent()) return;
      toast.error(err instanceof Error ? err.message : 'Failed to load packages');
    } finally {
      if (isCurrent()) setLoading(false);
    }
  }, [scope, ready, debouncedSearch, offset, beginPackagesRequest]);

  useEffect(() => {
    loadPackages();
  }, [loadPackages]);

  useEffect(() => {
    setOffset(0);
  }, [scope, debouncedSearch]);

  const handleScan = async () => {
    if (!selectedSystem) return;
    setScanning(true);
    try {
      const result = await scanPackages(selectedSystem);
      if (result.status === 'success') {
        toast.success(
          `Scan complete: ${result.packages_found} packages found, ${result.updates_available} updates available`
        );
        setLastScan(result.scanned_at);
        loadPackages();
      } else if (result.status === 'already_running') {
        // PRA-322: a scan is already in flight for this host (single-flight).
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

  const handleHold = async (packageName: string) => {
    if (!selectedSystem) return;
    setConfirm({
      open: true,
      title: 'Hold Package',
      message: `Hold ${packageName}? This will prevent it from being updated.`,
      confirmLabel: 'Hold',
      variant: 'warning',
      onConfirm: async () => {
        closeConfirm();
        setHoldingPackage(packageName);
        try {
          await holdPackages(selectedSystem, [packageName]);
          toast.success(`${packageName} is now held`);
          loadPackages();
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Failed to hold package');
        } finally {
          setHoldingPackage(null);
        }
      },
    });
  };

  const handleUnhold = async (packageName: string) => {
    if (!selectedSystem) return;
    setConfirm({
      open: true,
      title: 'Unhold Package',
      message: `Unhold ${packageName}? This will allow it to be updated again.`,
      confirmLabel: 'Unhold',
      variant: 'warning',
      onConfirm: async () => {
        closeConfirm();
        setHoldingPackage(packageName);
        try {
          await unholdPackages(selectedSystem, [packageName]);
          toast.success(`${packageName} is no longer held`);
          loadPackages();
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Failed to unhold package');
        } finally {
          setHoldingPackage(null);
        }
      },
    });
  };

  const handleRemove = async (packageName: string) => {
    if (!selectedSystem) return;
    const pkg = packages.find((p) => p.name === packageName);
    if (pkg?.is_held) {
      toast.error(`${packageName} is held and cannot be removed`);
      return;
    }
    const hostname = systems.find((s) => s.id === selectedSystem)?.hostname || 'this system';
    setConfirm({
      open: true,
      title: 'Remove Package',
      message: `Remove ${packageName} from ${hostname}? This will uninstall the package.`,
      confirmLabel: 'Remove',
      variant: 'danger',
      onConfirm: async () => {
        closeConfirm();
        setRemovingPackage(packageName);
        try {
          const result = await removePackages(selectedSystem, [packageName]);
          if (result.status === 'success') {
            toast.success(`${packageName} removed (${result.packages_removed} removed, ${result.packages_skipped} skipped)`);
          } else {
            toast.error(`Failed to remove ${packageName}`);
          }
          loadPackages();
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Failed to remove package');
        } finally {
          setRemovingPackage(null);
        }
      },
    });
  };

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;

  return (
    <MainLayout>
        <Head>
          <title>Package Inventory | Praxis</title>
        </Head>
      <PageHeader
        title="Package Inventory"
        actions={
          <div className="flex items-center gap-2">
            {selectedSystem && (
              <ExportButton
                endpoint="/api/backend/export/packages"
                filename={`packages-system-${selectedSystem}`}
                params={{ system_id: String(selectedSystem) }}
              />
            )}
            <HelpLink slug="packages" />
          </div>
        }
      />
      <Card>
        <CardBody>
          <div className="mb-6">
            <div className="flex flex-wrap justify-between items-end gap-3">
              <div className="flex flex-wrap items-end gap-3">
                <PackageScopeControl
                  value={scope}
                  onChange={setScope}
                  systems={scopeSystems}
                  groups={groups}
                  smartGroups={smartGroups}
                />
                <input
                  type="text"
                  placeholder="Search packages..."
                  value={search}
                  onChange={(e) => setSearch(e.target.value)}
                  className="px-4 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                />
              </div>
              {!aggregate ? (
                <Button
                  variant="primary"
                  onClick={handleScan}
                  disabled={scanning || !selectedSystem}
                  loading={scanning}
                >
                  {scanning ? 'Scanning...' : 'Scan System'}
                </Button>
              ) : (
                cohort && (
                  <CohortScanButton
                    scope={scope}
                    scopeName={cohort.name}
                    hostCount={cohort.member_count}
                    label="Refresh inventory"
                    onComplete={loadPackages}
                  />
                )
              )}
            </div>
          </div>

          {!scopeReady ? (
            <EmptyState
              icon={<Box size={24} className="text-content-muted" />}
              title="Select a scope target"
              description="Choose a group or smart group above to view its package inventory."
            />
          ) : aggregate ? (
            <div className="border border-border rounded-lg overflow-x-auto">
              <div className="min-w-[52rem]">
                <div className="grid grid-cols-[1.2fr_1.6fr_1.3fr_0.8fr_1fr] gap-3 p-4 bg-surface-sunken border-b border-border font-medium text-content">
                  <div>Host</div>
                  <div>Package Name</div>
                  <div>Version</div>
                  <div>Type</div>
                  <div>Last Scanned</div>
                </div>
                {loading ? (
                  <div className="p-4 text-content-muted">Loading packages...</div>
                ) : aggRows.length === 0 ? (
                  <EmptyState
                    icon={<Box size={24} className="text-content-muted" />}
                    title={search ? 'No matching packages' : 'No packages in this scope'}
                    description={
                      search
                        ? 'No packages in the selected scope match your search. Clear the search or pick a different scope.'
                        : 'No package inventory for the selected scope. Its systems may have no scans yet - run a scan on them, or choose a different scope.'
                    }
                  />
                ) : (
                  aggRows.map((pkg) => (
                    <div
                      key={`${pkg.system_id}-${pkg.id}`}
                      className="grid grid-cols-[1.2fr_1.6fr_1.3fr_0.8fr_1fr] gap-3 p-4 border-b border-border last:border-b-0 hover:bg-surface-overlay"
                    >
                      <div className="text-content break-words">{pkg.hostname}</div>
                      <div className="font-medium text-content break-words">
                        {pkg.name}
                        {pkg.is_security_critical && (
                          <Badge variant="danger" className="ml-2 align-middle">Critical</Badge>
                        )}
                        {pkg.is_held && (
                          <Badge variant="warning" className="ml-2 align-middle">Held</Badge>
                        )}
                      </div>
                      <div className="text-content-muted font-mono text-xs break-all">{pkg.installed_version}</div>
                      <div>
                        <span className="px-2 py-1 bg-surface-overlay text-content rounded text-sm">
                          {pkg.package_type || 'unknown'}
                        </span>
                      </div>
                      <div className="text-content-muted text-sm">
                        {pkg.last_audited ? formatTimestamp(pkg.last_audited, { dateOnly: true }) : 'Never'}
                      </div>
                    </div>
                  ))
                )}
              </div>
            </div>
          ) : (
          <div className="border border-border rounded-lg">
            <div className="grid grid-cols-[1.5fr_1.4fr_0.7fr_1.2fr_0.7fr_1fr] gap-3 p-4 bg-surface-sunken border-b border-border font-medium text-content">
              <div>Package Name</div>
              <div>Version</div>
              <div>Type</div>
              <div>Hold</div>
              <div>Remove</div>
              <div>Last Scanned</div>
            </div>
            {loading ? (
              <div className="p-4 text-content-muted">Loading packages...</div>
            ) : packages.length === 0 ? (
              <EmptyState
                icon={<Box size={24} className="text-content-muted" />}
                title="No package inventory yet"
                description="Run a scan from a registered system to populate this view. Inventory updates automatically after each scheduled or manual scan."
              />
            ) : (
              packages.map((pkg) => (
                <div
                  key={pkg.id}
                  className="grid grid-cols-[1.5fr_1.4fr_0.7fr_1.2fr_0.7fr_1fr] gap-3 p-4 border-b border-border last:border-b-0 hover:bg-surface-overlay"
                >
                  <div className="font-medium text-content break-words">
                    {pkg.name}
                    {/* PRA-271: security-critical is a sparse signal - surface it
                        inline only when true, instead of a mostly-"No" column. */}
                    {pkg.is_security_critical && (
                      <Badge variant="danger" className="ml-2 align-middle">Critical</Badge>
                    )}
                  </div>
                  <div className="text-content-muted font-mono text-xs break-all">{pkg.installed_version}</div>
                  <div>
                    <span className="px-2 py-1 bg-surface-overlay text-content rounded text-sm">
                      {pkg.package_type || 'unknown'}
                    </span>
                  </div>
                  <div>
                    {pkg.is_held ? (
                      <div className="flex items-center space-x-2">
                        <span className="px-2 py-1 bg-yellow-900 text-yellow-300 rounded text-sm">Held</span>
                        <Button
                          variant="ghost"
                          size="sm"
                          iconOnly
                          icon={<Unlock size={16} />}
                          aria-label={`Unhold ${pkg.name}`}
                          title="Unhold package"
                          onClick={() => handleUnhold(pkg.name)}
                          disabled={holdingPackage === pkg.name}
                          loading={holdingPackage === pkg.name}
                        />
                      </div>
                    ) : (
                      <Button
                        variant="ghost"
                        size="sm"
                        iconOnly
                        icon={<Lock size={16} />}
                        aria-label={`Hold ${pkg.name}`}
                        title="Hold package (skip during updates)"
                        onClick={() => handleHold(pkg.name)}
                        disabled={holdingPackage === pkg.name}
                        loading={holdingPackage === pkg.name}
                      />
                    )}
                  </div>
                  <div>
                    {/* PRA-270: quiet icon action; Signal Red is reserved for the
                        ConfirmModal danger step, not the repeated row button. */}
                    <Button
                      variant="ghost"
                      size="sm"
                      iconOnly
                      icon={<Trash2 size={16} />}
                      aria-label={`Remove ${pkg.name}`}
                      title={pkg.is_held ? 'Held packages cannot be removed' : 'Remove package'}
                      onClick={() => handleRemove(pkg.name)}
                      disabled={pkg.is_held || removingPackage === pkg.name}
                      loading={removingPackage === pkg.name}
                    />
                  </div>
                  <div className="text-content-muted text-sm">
                    {pkg.last_audited
                      ? formatTimestamp(pkg.last_audited, { dateOnly: true })
                      : 'Never'}
                  </div>
                </div>
              ))
            )}
          </div>
          )}

          {totalPages > 1 && (
            <div className="mt-4 flex justify-between items-center text-sm text-content-muted">
              <div>
                Showing {offset + 1}-{Math.min(offset + limit, total)} of {total} packages
              </div>
              <div className="flex space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset === 0}
                  onClick={() => setOffset(Math.max(0, offset - limit))}
                >
                  Previous
                </Button>
                <span className="px-3 py-1 text-content">
                  Page {currentPage} of {totalPages}
                </span>
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset + limit >= total}
                  onClick={() => setOffset(offset + limit)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}

          <div className="mt-6 grid grid-cols-1 md:grid-cols-3 gap-4">
            <StatCard
              label="Total Packages"
              value={total}
              subtitle={aggregate ? 'Across scope' : 'On selected system'}
            />
            {aggregate ? (
              <StatCard
                label="Hosts in Scope"
                value={new Set(aggRows.map((r) => r.system_id)).size}
                subtitle="Systems with packages shown"
              />
            ) : (
              <StatCard
                label="Package Type"
                value={packages.length > 0 ? packages[0].package_type?.toUpperCase() || '-' : '-'}
                subtitle="Package manager format"
              />
            )}
            <StatCard
              label="Last Scan"
              value={!aggregate && lastScan ? formatTimestamp(lastScan, { timeOnly: true }) : '-'}
              subtitle={aggregate ? 'Per-host in aggregate view' : 'Time of last scan'}
            />
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

export default PackageInventory;
