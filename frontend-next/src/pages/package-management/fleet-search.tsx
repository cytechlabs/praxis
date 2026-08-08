import React, { useState, useCallback } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import {
  searchFleetPackages,
  bulkHoldPackages,
  bulkUnholdPackages,
  bulkUpdatePackages,
  FleetSearchResult,
} from '@/services/packageService';
import Head from 'next/head';
import { PageHeader, Button, Card, CardBody, StatCard, ConfirmModal } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { usePackageScope } from '@/hooks/usePackageScope';
import PackageScopeControl from '@/components/packages/PackageScopeControl';
import { isScopeReady } from '@/services/packageScope';

interface ConfirmState {
  open: boolean;
  title: string;
  message: string;
  confirmLabel: string;
  variant: 'danger' | 'warning';
  onConfirm: () => void;
}

const FleetSearch = () => {
  const [query, setQuery] = useState('');
  const [versionFilter, setVersionFilter] = useState('');
  const [heldFilter, setHeldFilter] = useState<'' | 'true' | 'false'>('');
  const [updateFilter, setUpdateFilter] = useState<'' | 'true' | 'false'>('');
  const [results, setResults] = useState<FleetSearchResult[]>([]);
  const [total, setTotal] = useState(0);
  const [offset, setOffset] = useState(0);
  const [loading, setLoading] = useState(false);
  const [searched, setSearched] = useState(false);
  const [selected, setSelected] = useState<Set<number>>(new Set());
  const [bulkAction, setBulkAction] = useState(false);
  // Narrow the fleet search to a cohort (all / system / group / smart
  // group). Bulk hold/unhold/update still post explicit in-scope system_ids.
  const { scope, setScope, systems, groups, smartGroups } = usePackageScope();
  const limit = 50;
  const [confirm, setConfirm] = useState<ConfirmState>({
    open: false, title: '', message: '', confirmLabel: 'Confirm', variant: 'danger', onConfirm: () => {},
  });

  const closeConfirm = () => setConfirm((prev) => ({ ...prev, open: false }));

  const doSearch = useCallback(
    async (newOffset = 0) => {
      if (!query.trim()) {
        toast.error('Enter a package name to search');
        return;
      }
      // A cohort scope with no target must never widen to a fleet-wide search.
      if (!isScopeReady(scope)) {
        toast.error('Select a scope target, or choose All systems');
        return;
      }
      setLoading(true);
      setSearched(true);
      try {
        const isHeld = heldFilter === '' ? undefined : heldFilter === 'true';
        const hasUpdate = updateFilter === '' ? undefined : updateFilter === 'true';
        const data = await searchFleetPackages(
          query.trim(),
          versionFilter.trim() || undefined,
          isHeld,
          hasUpdate,
          limit,
          newOffset,
          scope
        );
        setResults(data.results);
        setTotal(data.total);
        setOffset(newOffset);
        setSelected(new Set());
      } catch (err) {
        toast.error(err instanceof Error ? err.message : 'Search failed');
      } finally {
        setLoading(false);
      }
    },
    [query, versionFilter, heldFilter, updateFilter, scope]
  );

  const handleSearch = (e: React.FormEvent) => {
    e.preventDefault();
    doSearch(0);
  };

  const toggleSelect = (packageId: number) => {
    setSelected((prev) => {
      const next = new Set(prev);
      if (next.has(packageId)) next.delete(packageId);
      else next.add(packageId);
      return next;
    });
  };

  const toggleSelectAll = () => {
    if (selected.size === results.length) {
      setSelected(new Set());
    } else {
      setSelected(new Set(results.map((r) => r.package_id)));
    }
  };

  const getSelectedItems = () => results.filter((r) => selected.has(r.package_id));

  const handleBulkHold = async () => {
    const items = getSelectedItems();
    if (items.length === 0) return;

    const systemIds = [...new Set(items.map((i) => i.system_id))];
    const packageNames = [...new Set(items.map((i) => i.name))];

    setConfirm({
      open: true,
      title: 'Hold Packages',
      message: `Hold ${packageNames.length} package(s) on ${systemIds.length} system(s)?`,
      confirmLabel: 'Hold',
      variant: 'warning',
      onConfirm: async () => {
        closeConfirm();
        setBulkAction(true);
        try {
          const result = await bulkHoldPackages(systemIds, packageNames);
          const errors = result.results.filter((r) => r.status === 'error');
          if (errors.length > 0) {
            toast.error(
              `${result.total_held} held, ${errors.length} system(s) had errors`
            );
          } else {
            toast.success(
              `${result.total_held} package(s) held across ${result.total_systems} system(s)`
            );
          }
          doSearch(offset);
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Bulk hold failed');
        } finally {
          setBulkAction(false);
        }
      },
    });
  };

  const handleBulkUnhold = async () => {
    const items = getSelectedItems();
    if (items.length === 0) return;

    const systemIds = [...new Set(items.map((i) => i.system_id))];
    const packageNames = [...new Set(items.map((i) => i.name))];

    setConfirm({
      open: true,
      title: 'Unhold Packages',
      message: `Unhold ${packageNames.length} package(s) on ${systemIds.length} system(s)?`,
      confirmLabel: 'Unhold',
      variant: 'warning',
      onConfirm: async () => {
        closeConfirm();
        setBulkAction(true);
        try {
          const result = await bulkUnholdPackages(systemIds, packageNames);
          const errors = result.results.filter((r) => r.status === 'error');
          if (errors.length > 0) {
            toast.error(
              `${result.total_unheld} unheld, ${errors.length} system(s) had errors`
            );
          } else {
            toast.success(
              `${result.total_unheld} package(s) unheld across ${result.total_systems} system(s)`
            );
          }
          doSearch(offset);
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Bulk unhold failed');
        } finally {
          setBulkAction(false);
        }
      },
    });
  };

  const handleBulkUpdate = async () => {
    const allItems = getSelectedItems();
    const items = allItems.filter((i) => i.has_update);
    if (items.length === 0) {
      toast.error('No selected packages have updates available');
      return;
    }
    const skippedUpToDate = allItems.length - items.length;

    const systemIds = [...new Set(items.map((i) => i.system_id))];
    const packageNames = [...new Set(items.map((i) => i.name))];

    setConfirm({
      open: true,
      title: 'Update Packages',
      message: `Update ${packageNames.length} package(s) on ${systemIds.length} system(s)?${skippedUpToDate > 0 ? ` (${skippedUpToDate} already up to date will be skipped)` : ''} This will run update commands on remote systems.`,
      confirmLabel: 'Update',
      variant: 'danger',
      onConfirm: async () => {
        closeConfirm();
        setBulkAction(true);
        try {
          const result = await bulkUpdatePackages(systemIds, packageNames);
          const errors = result.results.filter((r) => r.status === 'error');
          if (errors.length > 0) {
            toast.error(
              `${result.total_updated} updated, ${result.total_skipped} skipped, ${errors.length} system(s) had errors`
            );
          } else {
            toast.success(
              `${result.total_updated} package(s) updated across ${result.total_systems} system(s)${result.total_skipped > 0 ? `, ${result.total_skipped} skipped (held)` : ''}`
            );
          }
          doSearch(offset);
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Bulk update failed');
        } finally {
          setBulkAction(false);
        }
      },
    });
  };

  const handleInlineHold = async (pkg: FleetSearchResult) => {
    setConfirm({
      open: true,
      title: 'Hold Package',
      message: `Hold ${pkg.name} on ${pkg.hostname}?`,
      confirmLabel: 'Hold',
      variant: 'warning',
      onConfirm: async () => {
        closeConfirm();
        setBulkAction(true);
        try {
          await bulkHoldPackages([pkg.system_id], [pkg.name]);
          toast.success(`${pkg.name} held on ${pkg.hostname}`);
          doSearch(offset);
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Hold failed');
        } finally {
          setBulkAction(false);
        }
      },
    });
  };

  const handleInlineUnhold = async (pkg: FleetSearchResult) => {
    setConfirm({
      open: true,
      title: 'Unhold Package',
      message: `Unhold ${pkg.name} on ${pkg.hostname}?`,
      confirmLabel: 'Unhold',
      variant: 'warning',
      onConfirm: async () => {
        closeConfirm();
        setBulkAction(true);
        try {
          await bulkUnholdPackages([pkg.system_id], [pkg.name]);
          toast.success(`${pkg.name} unheld on ${pkg.hostname}`);
          doSearch(offset);
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Unhold failed');
        } finally {
          setBulkAction(false);
        }
      },
    });
  };

  const totalPages = Math.ceil(total / limit);
  const currentPage = Math.floor(offset / limit) + 1;
  const uniqueSystems = new Set(results.map((r) => r.hostname)).size;

  return (
    <MainLayout>
        <Head>
          <title>Fleet Search | Praxis</title>
        </Head>
      <PageHeader title="Fleet Package Search" actions={<HelpLink slug="packages" />} />
      <Card>
        <CardBody>
          {/* Search Form */}
          <form onSubmit={handleSearch} className="mb-6">
            <div className="mb-3">
              <PackageScopeControl
                value={scope}
                onChange={setScope}
                systems={systems}
                groups={groups}
                smartGroups={smartGroups}
              />
            </div>
            <div className="flex flex-wrap items-end gap-3">
              <div className="flex-1 min-w-[200px]">
                <label className="block text-sm text-content-muted mb-1">Package Name</label>
                <input
                  type="text"
                  placeholder="e.g. openssl, nginx, curl..."
                  value={query}
                  onChange={(e) => setQuery(e.target.value)}
                  className="w-full px-4 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                />
              </div>
              <div className="w-48">
                <label className="block text-sm text-content-muted mb-1">Version Filter</label>
                <input
                  type="text"
                  placeholder="e.g. 3.0, 1.18"
                  value={versionFilter}
                  onChange={(e) => setVersionFilter(e.target.value)}
                  className="w-full px-4 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                />
              </div>
              <div className="w-40">
                <label className="block text-sm text-content-muted mb-1">Held Status</label>
                <select
                  value={heldFilter}
                  onChange={(e) => setHeldFilter(e.target.value as '' | 'true' | 'false')}
                  className="w-full px-4 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                >
                  <option value="">All</option>
                  <option value="true">Held Only</option>
                  <option value="false">Not Held</option>
                </select>
              </div>
              <div className="w-44">
                <label className="block text-sm text-content-muted mb-1">Update Status</label>
                <select
                  value={updateFilter}
                  onChange={(e) => setUpdateFilter(e.target.value as '' | 'true' | 'false')}
                  className="w-full px-4 py-2 bg-surface-sunken border border-border rounded-md text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
                >
                  <option value="">All</option>
                  <option value="true">Out of Date</option>
                  <option value="false">Up to Date</option>
                </select>
              </div>
              <Button
                variant="primary"
                type="submit"
                disabled={loading}
                loading={loading}
              >
                {loading ? 'Searching...' : 'Search Fleet'}
              </Button>
            </div>
          </form>

          {/* Stats Cards */}
          {searched && (
            <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
              <StatCard label="Results Found" value={total} subtitle="Package instances across fleet" />
              <StatCard label="Systems" value={uniqueSystems} subtitle="Systems with matching packages" />
              <StatCard
                label="Out of Date"
                value={results.filter((r) => r.has_update).length}
                subtitle="Packages with updates available"
              />
            </div>
          )}

          {/* Bulk Action Toolbar */}
          {selected.size > 0 && (
            <div className="mb-4 flex items-center gap-3 bg-surface-sunken border border-border rounded-lg p-3">
              <span className="text-content text-sm font-medium">
                {selected.size} selected
              </span>
              <Button
                variant="outline"
                size="sm"
                onClick={handleBulkHold}
                disabled={bulkAction}
              >
                Hold
              </Button>
              <Button
                variant="outline"
                size="sm"
                onClick={handleBulkUnhold}
                disabled={bulkAction}
              >
                Unhold
              </Button>
              <Button
                variant="primary"
                size="sm"
                onClick={handleBulkUpdate}
                disabled={bulkAction || !getSelectedItems().some((i) => i.has_update)}
              >
                Update
              </Button>
              {bulkAction && (
                <span className="text-content-muted text-sm">Processing...</span>
              )}
            </div>
          )}

          {/* Results Table */}
          {searched && (
            <div className="border border-border rounded-lg">
              <div className="grid grid-cols-[1.4fr_1.4fr_1.4fr_0.7fr_1fr_0.6fr_0.7fr_0.7fr] gap-3 p-4 bg-surface-sunken border-b border-border font-medium text-content">
                <div className="flex items-center">
                  <input
                    type="checkbox"
                    checked={results.length > 0 && selected.size === results.length}
                    onChange={toggleSelectAll}
                    className="mr-2 accent-red-600"
                  />
                  Package Name
                </div>
                <div>Installed</div>
                <div>Available</div>
                <div>Type</div>
                <div>System</div>
                <div>Security</div>
                <div>Status</div>
                <div>Actions</div>
              </div>
              {loading ? (
                <div className="p-4 text-content-muted">Searching...</div>
              ) : results.length === 0 ? (
                <div className="p-4 text-content-muted">
                  No packages found matching your search criteria.
                </div>
              ) : (
                results.map((pkg) => (
                  <div
                    key={`${pkg.system_id}-${pkg.package_id}`}
                    className="grid grid-cols-[1.4fr_1.4fr_1.4fr_0.7fr_1fr_0.6fr_0.7fr_0.7fr] gap-3 p-4 border-b border-border last:border-b-0 hover:bg-surface-overlay"
                  >
                    <div className="flex items-center">
                      <input
                        type="checkbox"
                        checked={selected.has(pkg.package_id)}
                        onChange={() => toggleSelect(pkg.package_id)}
                        className="mr-2 accent-red-600"
                      />
                      <span className="font-medium text-content">{pkg.name}</span>
                    </div>
                    <div className="text-content-muted font-mono text-xs break-all">{pkg.installed_version}</div>
                    <div>
                      {pkg.has_update ? (
                        <span
                          className={`inline-block px-2 py-1 rounded font-mono text-xs break-all ${
                            pkg.update_type === 'security'
                              ? 'bg-red-900 text-red-300'
                              : 'bg-orange-900 text-orange-300'
                          }`}
                        >
                          {pkg.available_version}
                        </span>
                      ) : (
                        <span className="text-green-500 text-sm">Up to date</span>
                      )}
                    </div>
                    <div>
                      <span className="px-2 py-1 bg-surface-overlay text-content rounded text-sm">
                        {pkg.package_type || 'unknown'}
                      </span>
                    </div>
                    <div className="text-content-muted">{pkg.hostname}</div>
                    <div>
                      {pkg.is_security_critical ? (
                        <span className="px-2 py-1 bg-red-900 text-red-300 rounded text-sm">
                          Critical
                        </span>
                      ) : (
                        <span className="text-content-subtle text-sm">No</span>
                      )}
                    </div>
                    <div>
                      {pkg.is_held ? (
                        <span className="px-2 py-1 bg-yellow-900 text-yellow-300 rounded text-sm">
                          Held
                        </span>
                      ) : (
                        <span className="px-2 py-1 bg-green-900 text-green-300 rounded text-sm">
                          Active
                        </span>
                      )}
                    </div>
                    <div className="flex gap-1">
                      {pkg.is_held ? (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleInlineUnhold(pkg)}
                          disabled={bulkAction}
                        >
                          Unhold
                        </Button>
                      ) : (
                        <Button
                          variant="outline"
                          size="sm"
                          onClick={() => handleInlineHold(pkg)}
                          disabled={bulkAction}
                        >
                          Hold
                        </Button>
                      )}
                    </div>
                  </div>
                ))
              )}
            </div>
          )}

          {/* Pagination */}
          {totalPages > 1 && (
            <div className="mt-4 flex justify-between items-center text-sm text-content-muted">
              <div>
                Showing {offset + 1}-{Math.min(offset + limit, total)} of {total} results
              </div>
              <div className="flex space-x-2">
                <Button
                  variant="outline"
                  size="sm"
                  disabled={offset === 0}
                  onClick={() => doSearch(Math.max(0, offset - limit))}
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
                  onClick={() => doSearch(offset + limit)}
                >
                  Next
                </Button>
              </div>
            </div>
          )}

          {/* Use Cases */}
          {!searched && (
            <div className="mt-4 text-content-muted">
              <p className="mb-2 text-content font-medium">Use cases:</p>
              <ul className="list-disc list-inside space-y-1 text-sm">
                <li>CVE response: &quot;Which systems have openssl installed?&quot;</li>
                <li>Compliance: &quot;What version of nginx is on every server?&quot;</li>
                <li>Bulk hold: Select results and hold a package across all affected systems</li>
                <li>Audit: Filter by held status to see which packages are pinned fleet-wide</li>
              </ul>
            </div>
          )}
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

export default FleetSearch;
