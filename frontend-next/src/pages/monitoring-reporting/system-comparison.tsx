import React, { useCallback, useEffect, useState } from 'react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, Card, CardBody, StatCard, Badge } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { Download, Search } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import { fetchAllSystems } from '@/services/systemService';
import SystemPicker from '@/components/monitoring/SystemPicker';
import Head from 'next/head';

interface SystemOption {
  id: number;
  hostname: string;
}

interface DriftSummary {
  total_packages: number;
  common_count: number;
  missing_count: number;
  version_drift_count: number;
}

interface PackageEntry {
  name: string;
  versions: Record<string, string | null>;
  has_drift: boolean;
  missing_from?: { id: number; hostname: string }[];
}

interface ComparisonResult {
  systems: { id: number; hostname: string }[];
  common_packages: PackageEntry[];
  missing_packages: PackageEntry[];
  drift_summary: DriftSummary;
}

type ViewMode = 'all_diff' | 'drift' | 'missing' | 'all';

const SystemComparison: React.FC = () => {
  const [allSystems, setAllSystems] = useState<SystemOption[]>([]);
  const [selectedIds, setSelectedIds] = useState<number[]>([]);
  const [loading, setLoading] = useState(false);
  const [result, setResult] = useState<ComparisonResult | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('all_diff');
  const [nameFilter, setNameFilter] = useState('');
  const [securityOnly, setSecurityOnly] = useState(false);

  const loadSystems = useCallback(async () => {
    try {
      // PRA-352: use the shared fetch path so the "Select systems" list inherits
      // the natural hostname ordering instead of raw backend order.
      const data = await fetchAllSystems();
      setAllSystems(data.map((s) => ({ id: s.id, hostname: s.hostname })));
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to load systems');
    }
  }, []);

  useEffect(() => { loadSystems(); }, [loadSystems]);

  const toggleSystem = (id: number) => {
    setSelectedIds(prev => {
      if (prev.includes(id)) return prev.filter(x => x !== id);
      if (prev.length >= 10) {
        toast.error('Maximum 10 systems can be compared');
        return prev;
      }
      return [...prev, id];
    });
  };

  const runComparison = async () => {
    if (selectedIds.length < 2) {
      toast.error('Select at least 2 systems to compare');
      return;
    }
    setLoading(true);
    try {
      const params = new URLSearchParams();
      params.set('system_ids', selectedIds.join(','));
      if (securityOnly) params.set('security_only', 'true');
      if (nameFilter) params.set('name_filter', nameFilter);

      const res = await apiFetch(`/api/backend/systems/compare?${params.toString()}`);
      if (!res.ok) throw new Error('Comparison failed');
      setResult(await res.json());
      setViewMode('all_diff');
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Comparison failed');
    } finally {
      setLoading(false);
    }
  };

  const exportData = async (format: 'csv' | 'json') => {
    if (selectedIds.length < 2) return;
    try {
      const params = new URLSearchParams();
      params.set('system_ids', selectedIds.join(','));
      params.set('format', format);
      if (securityOnly) params.set('security_only', 'true');
      if (nameFilter) params.set('name_filter', nameFilter);

      const res = await apiFetch(`/api/backend/systems/compare/export?${params.toString()}`);
      if (!res.ok) throw new Error('Export failed');

      if (format === 'csv') {
        const blob = await res.blob();
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'system-comparison.csv';
        a.click();
        URL.revokeObjectURL(url);
      } else {
        const data = await res.json();
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = 'system-comparison.json';
        a.click();
        URL.revokeObjectURL(url);
      }
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Export failed');
    }
  };

  const getVisiblePackages = (): PackageEntry[] => {
    if (!result) return [];
    switch (viewMode) {
      case 'drift':
        return [
          ...result.common_packages.filter(p => p.has_drift),
          ...result.missing_packages.filter(p => p.has_drift),
        ];
      case 'missing':
        return result.missing_packages;
      case 'all':
        return [...result.common_packages, ...result.missing_packages];
      case 'all_diff':
      default:
        return [
          ...result.common_packages.filter(p => p.has_drift),
          ...result.missing_packages,
        ];
    }
  };

  const versionCell = (pkg: PackageEntry, systemId: number) => {
    const version = pkg.versions[String(systemId)];
    if (!version) {
      return <span className="text-red-400">-</span>;
    }
    if (!pkg.has_drift) {
      return <span className="text-green-400">{version}</span>;
    }
    // Check if this version differs from any other
    const allVersions = Object.values(pkg.versions).filter(Boolean);
    const uniqueVersions = new Set(allVersions);
    if (uniqueVersions.size <= 1) {
      return <span className="text-green-400">{version}</span>;
    }
    return <span className="text-yellow-400">{version}</span>;
  };

  const visiblePkgs = getVisiblePackages();

  return (
    <MainLayout>
        <Head>
          <title>System Comparison | Praxis</title>
        </Head>
        <PageHeader title="System Comparison" actions={<HelpLink slug="monitoring-and-alerts" />} />

        {/* System selector */}
        <Card className="mb-6">
          <CardBody>
            <div className="flex items-center justify-between mb-4">
              <h2 className="text-lg text-content font-medium">Select Systems to Compare</h2>
              <span className="text-sm text-content-muted">{selectedIds.length} selected (2-10 required)</span>
            </div>

            <div className="mb-4">
              <SystemPicker
                systems={allSystems}
                selectedIds={selectedIds}
                onToggle={toggleSystem}
              />
            </div>

            <div className="flex flex-wrap items-end gap-4">
              <div>
                <label className="block text-xs text-content-muted mb-1">Package name filter</label>
                <div className="relative">
                  <Search className="absolute left-2 top-1/2 -translate-y-1/2 w-4 h-4 text-content-subtle" />
                  <input
                    type="text"
                    value={nameFilter}
                    onChange={(e) => setNameFilter(e.target.value)}
                    placeholder="Filter by name..."
                    className="bg-surface-sunken border border-border rounded pl-8 pr-3 py-1 text-content text-sm w-48"
                  />
                </div>
              </div>
              <label className="flex items-center gap-2 text-sm text-content-muted cursor-pointer pb-1">
                <input
                  type="checkbox"
                  checked={securityOnly}
                  onChange={(e) => setSecurityOnly(e.target.checked)}
                  className="rounded"
                />
                Security packages only
              </label>
              <Button
                variant="primary"
                size="sm"
                onClick={runComparison}
                disabled={selectedIds.length < 2 || loading}
                loading={loading}
              >
                {loading ? 'Comparing...' : 'Compare'}
              </Button>
            </div>
          </CardBody>
        </Card>

        {/* Results */}
        {result && (
          <>
            {/* Summary */}
            <div className="grid grid-cols-2 md:grid-cols-4 gap-4 mb-6">
              <StatCard label="Total Packages" value={result.drift_summary.total_packages} />
              <StatCard label="Common (no drift)" value={result.drift_summary.common_count - result.common_packages.filter(p => p.has_drift).length} />
              <StatCard label="Version Drift" value={result.drift_summary.version_drift_count} />
              <StatCard label="Missing From Some" value={result.drift_summary.missing_count} />
            </div>

            {/* View mode tabs + export */}
            <div className="flex items-center justify-between mb-4">
              <div className="flex gap-1">
                {([
                  ['all_diff', 'All Differences'],
                  ['drift', 'Version Drift'],
                  ['missing', 'Missing Packages'],
                  ['all', 'All Packages'],
                ] as [ViewMode, string][]).map(([mode, label]) => (
                  <Button
                    key={mode}
                    variant={viewMode === mode ? 'primary' : 'outline'}
                    size="sm"
                    onClick={() => setViewMode(mode)}
                  >
                    {label}
                  </Button>
                ))}
              </div>
              <div className="flex gap-2">
                <Button variant="outline" size="sm" onClick={() => exportData('csv')} icon={<Download className="w-4 h-4" />}>
                  CSV
                </Button>
                <Button variant="outline" size="sm" onClick={() => exportData('json')} icon={<Download className="w-4 h-4" />}>
                  JSON
                </Button>
              </div>
            </div>

            {/* Comparison table */}
            <Card className="overflow-x-auto">
              <table className="w-full text-sm">
                <thead>
                  <tr className="bg-surface-sunken border-b border-border text-content">
                    <th scope="col" className="px-4 py-3 text-left sticky left-0 bg-surface-sunken z-10">Package</th>
                    {result.systems.map((s) => (
                      <th scope="col" key={s.id} className="px-4 py-3 text-left">{s.hostname}</th>
                    ))}
                    <th scope="col" className="px-4 py-3 text-left">Status</th>
                  </tr>
                </thead>
                <tbody>
                  {visiblePkgs.length === 0 && (
                    <tr>
                      <td colSpan={result.systems.length + 2} className="px-4 py-8 text-center text-content-muted">
                        No packages to display for this view.
                      </td>
                    </tr>
                  )}
                  {visiblePkgs.map((pkg) => {
                    const isMissing = !!pkg.missing_from && pkg.missing_from.length > 0;
                    return (
                      <tr key={pkg.name} className="border-b border-border/30 hover:bg-surface-overlay/50">
                        <td className="px-4 py-2 text-content font-medium sticky left-0 bg-surface-sunken">{pkg.name}</td>
                        {result.systems.map((s) => (
                          <td key={s.id} className="px-4 py-2 font-mono text-xs">
                            {versionCell(pkg, s.id)}
                          </td>
                        ))}
                        <td className="px-4 py-2">
                          {isMissing ? (
                            <Badge variant="danger">missing</Badge>
                          ) : pkg.has_drift ? (
                            <Badge variant="warning">drift</Badge>
                          ) : (
                            <Badge variant="success">ok</Badge>
                          )}
                        </td>
                      </tr>
                    );
                  })}
                </tbody>
              </table>
            </Card>
          </>
        )}
    </MainLayout>
  );
};

export default SystemComparison;
