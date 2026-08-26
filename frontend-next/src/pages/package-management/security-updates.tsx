import React, { useState, useEffect, useCallback, useMemo } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import Pagination from '@/components/Pagination';
import { fetchAllSystems } from '@/services/systemService';
import { useLatestRequest } from '@/hooks/useLatestRequest';
import {
  fetchAllSecurityUpdates,
  fetchSystemSecurityUpdates,
  scanSecurityUpdates,
  applyUpdates,
  fetchPackages,
  PackageUpdateItem,
  ApplyUpdatesResult,
} from '@/services/packageService';
import { notifyRebootStatus } from '@/utils/rebootStatus';
import { ShieldCheck, Download } from 'lucide-react';
import Head from 'next/head';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';
import { PageHeader, Button, Card, CardBody, StatCard, ConfirmModal, EmptyState } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import Link from 'next/link';
import { usePackageScope } from '@/hooks/usePackageScope';
import PackageScopeControl from '@/components/packages/PackageScopeControl';
import CohortScanButton from '@/components/packages/CohortScanButton';
import { isScopeReady } from '@/services/packageScope';

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

const SecurityUpdates = () => {
  const formatTimestamp = useFormatTimestamp();
  const [systems, setSystems] = useState<SystemOption[]>([]);
  // Cohort scope (all / system / group / smart group). Single-system
  // keeps the original per-host behavior; other scopes aggregate through the
  // scoped `/security/all` endpoint.
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
  const [applying, setApplying] = useState(false);
  const [applyingPackage, setApplyingPackage] = useState<number | null>(null);
  const [lastScanned, setLastScanned] = useState<string | null>(null);
  const [heldPackageNames, setHeldPackageNames] = useState<Set<string>>(new Set());
  const [pageOffset, setPageOffset] = useState(0);
  const pageLimit = 25;
  const [confirm, setConfirm] = useState<ConfirmState>({
    open: false, title: '', message: '', confirmLabel: 'Confirm', variant: 'danger', onConfirm: () => {},
  });

  const closeConfirm = () => setConfirm((prev) => ({ ...prev, open: false }));

  useEffect(() => {
    fetchAllSystems()
      .then((data) => {
        setSystems(data.map((s) => ({ id: s.id, hostname: s.hostname })));
      })
      .catch(() => toast.error('Failed to load systems'));
  }, []);

  // PRA-256: independent request streams (security-updates list vs held-package
  // set) each get their own latest-request guard so a stale response can't
  // clobber current state, and so the two streams don't invalidate each other.
  const beginUpdatesRequest = useLatestRequest();
  const beginHeldRequest = useLatestRequest();

  const loadUpdates = useCallback(async () => {
    // A cohort scope with no target must never widen to a fleet-wide query.
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
          ? await fetchSystemSecurityUpdates(scope.id)
          : await fetchAllSecurityUpdates(scope);
      if (!isCurrent()) return;
      setUpdates(data);
    } catch (err) {
      if (!isCurrent()) return;
      toast.error(err instanceof Error ? err.message : 'Failed to load security updates');
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
      const result = await scanSecurityUpdates(selectedSystem);
      if (result.status === 'success') {
        toast.success(`Security scan complete: ${result.updates_available} security updates found`);
        setLastScanned(result.scanned_at);
        loadUpdates();
      } else if (result.status === 'already_running') {
        toast.info(result.message || 'A scan is already running for this host');
      } else {
        toast.error(result.message || 'Security scan failed');
      }
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Security scan failed');
    } finally {
      setScanning(false);
    }
  };

  const reportRebootStatus = (result: ApplyUpdatesResult) => {
    notifyRebootStatus(result, toast);
  };

  const handleApplyAll = async () => {
    if (selectedSystem === 'all') return;
    const hostname = getSystemHostname(selectedSystem);
    const unheldUpdates = updates.filter((u) => !heldPackageNames.has(u.package_name));
    const heldCount = updates.length - unheldUpdates.length;
    if (unheldUpdates.length === 0) {
      toast.error('All packages are held. Unhold packages before applying updates.');
      return;
    }
    setConfirm({
      open: true,
      title: 'Apply All Security Updates',
      message: `Apply ${unheldUpdates.length} security updates on ${hostname}?${heldCount > 0 ? ` ${heldCount} held package(s) will be skipped.` : ''} This will run the security update command on the remote system.`,
      confirmLabel: 'Apply All',
      variant: 'danger',
      onConfirm: async () => {
        closeConfirm();
        setApplying(true);
        try {
          const packageNames = unheldUpdates.map((u) => u.package_name);
          const result = await applyUpdates(selectedSystem, packageNames);
          if (result.status === 'success') {
            toast.success(
              `Applied ${result.packages_updated} security update(s) on ${result.hostname}`
            );
            reportRebootStatus(result);
            if (heldCount > 0) {
              toast.info(`${heldCount} held package(s) skipped`);
            }
            loadUpdates();
          } else {
            toast.error(result.message || 'Security update failed');
          }
        } catch (err) {
          toast.error(err instanceof Error ? err.message : 'Security update failed');
        } finally {
          setApplying(false);
        }
      },
    });
  };

  const handleApplySingle = async (
    updateId: number,
    systemId: number,
    packageName: string
  ) => {
    const hostname = getSystemHostname(systemId);
    setConfirm({
      open: true,
      title: 'Apply Security Update',
      message: `Apply security update for ${packageName} on ${hostname}?`,
      confirmLabel: 'Apply',
      variant: 'danger',
      onConfirm: async () => {
        closeConfirm();
        setApplyingPackage(updateId);
        try {
          const result = await applyUpdates(systemId, [packageName]);
          if (result.status === 'success') {
            toast.success(`Updated ${packageName} on ${result.hostname}`);
            reportRebootStatus(result);
            loadUpdates();
          } else {
            toast.error(result.message || `Failed to update ${packageName}`);
          }
        } catch (err) {
          toast.error(err instanceof Error ? err.message : `Failed to update ${packageName}`);
        } finally {
          setApplyingPackage(null);
        }
      },
    });
  };

  const uniqueSystems = new Set(updates.map((u) => u.system_id)).size;

  useEffect(() => { setPageOffset(0); }, [scope]);

  const paginatedUpdates = useMemo(
    () => updates.slice(pageOffset, pageOffset + pageLimit),
    [updates, pageOffset]
  );

  const getSystemHostname = (systemId: number) => {
    const sys = systems.find((s) => s.id === systemId);
    return sys ? sys.hostname : String(systemId);
  };

  return (
    <MainLayout>
        <Head>
          <title>Security Updates | Praxis</title>
        </Head>
      <PageHeader title="Security Updates" actions={<HelpLink slug="packages" />} />
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
                      {scanning ? 'Scanning...' : 'Scan for Security Updates'}
                    </Button>
                    <Button
                      variant="primary"
                      onClick={handleApplyAll}
                      disabled={applying || updates.length === 0}
                      loading={applying}
                    >
                      {applying ? 'Applying...' : 'Apply All Security Updates'}
                    </Button>
                  </>
                )}
                {cohort && (
                  <>
                    <CohortScanButton
                      scope={scope}
                      scopeName={cohort.name}
                      hostCount={cohort.member_count}
                      label="Scan for security updates"
                      security
                      onComplete={loadUpdates}
                    />
                    <Link
                      href="/patch-update-plans/all"
                      className="text-sm text-link hover:text-link-hover"
                    >
                      Apply security updates for this cohort in Update Plans &rarr;
                    </Link>
                  </>
                )}
              </div>
            </div>
          </div>

          <div className="grid grid-cols-1 md:grid-cols-3 gap-4 mb-6">
            <StatCard label="Total Security Updates" value={updates.length} subtitle={`across ${uniqueSystems} ${uniqueSystems === 1 ? 'system' : 'systems'}`} />
            <StatCard label="Systems Affected" value={uniqueSystems} subtitle="Systems needing security updates" />
            <StatCard
              label="Last Scanned"
              value={lastScanned ? formatTimestamp(lastScanned) : 'Never'}
              subtitle="Last security scan time"
            />
          </div>

          <div className="border border-border rounded-lg">
            <div className="grid grid-cols-[1.4fr_1.6fr_1.6fr_1fr_0.9fr_0.7fr] gap-3 p-4 bg-surface-sunken border-b border-border font-medium text-content">
              <div>Package Name</div>
              <div>Current Version</div>
              <div>New Version</div>
              <div>System</div>
              <div>Discovered</div>
              <div>Actions</div>
            </div>
            {!scopeReady ? (
              <EmptyState
                title="Select a scope target"
                description="Choose a group or smart group above to view its security updates."
              />
            ) : loading ? (
              <div className="p-4 text-content-muted">Loading security updates...</div>
            ) : updates.length === 0 ? (
              <EmptyState
                icon={<ShieldCheck size={24} className="text-emerald-400" />}
                title="No security updates pending"
                description="Every system in your fleet is patched against known vulnerabilities. Praxis will surface new security advisories here as they appear."
              />
            ) : (
              paginatedUpdates.map((update) => {
                const isHeld = heldPackageNames.has(update.package_name);
                return (
                  <div
                    key={update.id}
                    className="grid grid-cols-[1.4fr_1.6fr_1.6fr_1fr_0.9fr_0.7fr] gap-3 p-4 border-b border-border last:border-b-0 hover:bg-surface-overlay"
                  >
                    <div className="font-medium text-content break-words">
                      {update.package_name}
                      {isHeld && (
                        <span className="ml-2 px-1.5 py-0.5 bg-yellow-900 text-yellow-300 rounded text-xs align-middle">Held</span>
                      )}
                    </div>
                    <div className="text-content-muted font-mono text-xs break-all">{update.installed_version}</div>
                    <div className="text-content font-mono text-xs break-all">{update.available_version}</div>
                    <div className="text-content-muted">{getSystemHostname(update.system_id)}</div>
                    <div className="text-content-muted text-sm">
                      {formatTimestamp(update.discovered_on, { dateOnly: true })}
                    </div>
                    <div>
                      {/* PRA-270: quiet icon action; page-level "Apply All" keeps
                          the single primary, confirmation carries the emphasis. */}
                      <Button
                        variant="ghost"
                        size="sm"
                        iconOnly
                        icon={<Download size={16} />}
                        aria-label={`Apply security update for ${update.package_name}`}
                        title={isHeld ? 'Held - unhold before applying' : 'Apply security update'}
                        onClick={() =>
                          handleApplySingle(update.id, update.system_id, update.package_name)
                        }
                        disabled={applyingPackage === update.id || isHeld}
                        loading={applyingPackage === update.id}
                      />
                    </div>
                  </div>
                );
              })
            )}
          </div>

          {updates.length > pageLimit && (
            <Pagination
              offset={pageOffset}
              limit={pageLimit}
              total={updates.length}
              onPageChange={setPageOffset}
            />
          )}

          <div className="mt-4 text-sm text-content-muted">
            Last scanned: {lastScanned ? formatTimestamp(lastScanned) : 'Never'}
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

export default SecurityUpdates;
