/**
 * Patch advisories list page.
 *
 * Operator-facing list of every imported native distribution advisory.
 * Filters by source, class, severity, distro family; paginates via
 * offset/limit. Admin/maintainer operators can import raw native
 * advisory payloads (Ubuntu USN / Debian security / Red Hat updateinfo)
 * and see recent import-run status inline.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { Eye, Upload } from 'lucide-react';
import { toast } from 'sonner';
import MainLayout from '@/components/MainLayout';
import { useAuth } from '@/context/AuthContext';
import { Badge, LoadingState, nativeSelectClass, PageHeader } from '@/components/ui';
import {
  ADVISORY_CLASS_LABELS,
  ADVISORY_CLASS_VALUES,
  ADVISORY_DISTRO_FAMILY_VALUES,
  ADVISORY_SEVERITY_VALUES,
  ADVISORY_SOURCE_KIND_VALUES,
  type AdvisoryClass,
  type AdvisoryDistroFamily,
  type AdvisoryImportResponse,
  type AdvisorySeverity,
  type AdvisorySourceKind,
  DISTRO_FAMILY_LABELS,
  importAdvisories,
  listAdvisoryImportRuns,
  listPatchAdvisories,
  type PatchAdvisory,
  type PatchAdvisoryApiError,
  type PatchAdvisoryImportRun,
  SEVERITY_LABELS,
  SOURCE_KIND_LABELS,
} from '@/services/patchAdvisoryService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const PAGE_SIZE = 50;

type Filters = {
  source_kind: AdvisorySourceKind | '';
  advisory_class: AdvisoryClass | '';
  severity: AdvisorySeverity | '';
  distro_family: AdvisoryDistroFamily | '';
};

const PatchAdvisoriesListPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { canWrite } = useAuth();
  const [advisories, setAdvisories] = useState<PatchAdvisory[] | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [offset, setOffset] = useState(0);
  const [filters, setFilters] = useState<Filters>({
    source_kind: '',
    advisory_class: '',
    severity: '',
    distro_family: '',
  });

  // PRA-239: operator import panel state.
  const [showImport, setShowImport] = useState(false);
  const [importSource, setImportSource] =
    useState<AdvisorySourceKind>('ubuntu_usn');
  const [importText, setImportText] = useState('');
  const [importing, setImporting] = useState(false);
  const [importError, setImportError] = useState<string | null>(null);
  const [importResult, setImportResult] =
    useState<AdvisoryImportResponse | null>(null);
  const [importRuns, setImportRuns] = useState<PatchAdvisoryImportRun[] | null>(
    null,
  );

  const loadImportRuns = useCallback(async () => {
    if (!canWrite) return;
    try {
      setImportRuns(await listAdvisoryImportRuns({ limit: 5 }));
    } catch {
      // Import-run history is non-critical; leave it unset on failure.
    }
  }, [canWrite]);

  useEffect(() => {
    loadImportRuns();
  }, [loadImportRuns]);

  // PRA-163 #4: hydrate filters from `?severity=...` etc. on first
  // mount so the dashboard tile links land on the filtered list.
  useEffect(() => {
    if (!router.isReady) return;
    const q = router.query;
    const fromQuery = (k: keyof Filters): string => {
      const v = q[k];
      if (Array.isArray(v)) return v[0] ?? '';
      return v ?? '';
    };
    setFilters({
      source_kind: fromQuery('source_kind') as AdvisorySourceKind | '',
      advisory_class: fromQuery('advisory_class') as AdvisoryClass | '',
      severity: fromQuery('severity') as AdvisorySeverity | '',
      distro_family: fromQuery('distro_family') as AdvisoryDistroFamily | '',
    });
    // Run only on initial router-ready transition, not on every
    // filter mutation (which would create an infinite loop with the
    // setFilter callback that resets offset).
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [router.isReady]);

  const refresh = useCallback(async () => {
    try {
      const data = await listPatchAdvisories({
        source_kind: filters.source_kind || undefined,
        advisory_class: filters.advisory_class || undefined,
        severity: filters.severity || undefined,
        distro_family: filters.distro_family || undefined,
        offset,
        limit: PAGE_SIZE,
      });
      setAdvisories(data);
      setError(null);
    } catch (e) {
      const apiErr = e as PatchAdvisoryApiError;
      setError(apiErr.message || String(e));
    }
  }, [filters, offset]);

  useEffect(() => {
    refresh();
  }, [refresh]);

  // Reset pagination when any filter changes (so the first page reflects
  // the new filter set rather than a possibly-empty middle slice).
  const setFilter = (patch: Partial<Filters>) => {
    setFilters((f) => ({ ...f, ...patch }));
    setOffset(0);
  };

  const handleImport = async () => {
    setImportError(null);
    setImportResult(null);
    let parsed: unknown;
    try {
      parsed = JSON.parse(importText);
    } catch {
      setImportError('Payload is not valid JSON.');
      return;
    }
    // Accept a single raw advisory object or an array of them.
    const payloads = (Array.isArray(parsed) ? parsed : [parsed]) as Record<
      string,
      unknown
    >[];
    if (payloads.length === 0) {
      setImportError('Provide at least one advisory object.');
      return;
    }
    setImporting(true);
    try {
      const result = await importAdvisories(importSource, payloads);
      setImportResult(result);
      const { imported_count, refreshed_count, unchanged_count, error_count } =
        result.run;
      if (error_count > 0) {
        toast.error(
          `Imported with ${error_count} error(s) - see details below.`,
        );
      } else {
        toast.success(
          `Import ${result.run.status}: ${imported_count} new, ${refreshed_count} updated, ${unchanged_count} unchanged.`,
        );
      }
      setOffset(0);
      await refresh();
      await loadImportRuns();
    } catch (e) {
      const apiErr = e as PatchAdvisoryApiError;
      setImportError(apiErr.message || String(e));
    } finally {
      setImporting(false);
    }
  };

  return (
    <MainLayout>
      <Head>
        <title>Patch advisories · Praxis</title>
      </Head>
      <div className="p-6">
        <PageHeader
          title="Patch advisories"
          subtitle="Native distribution advisory metadata (Ubuntu USN, Debian DSA, Red Hat updateinfo). Per-host applicability is computed from these advisories joined against host facts and installed packages."
          actions={
            canWrite ? (
              <button
                onClick={() => setShowImport((s) => !s)}
                className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500"
              >
                <Upload size={14} /> Import advisories
              </button>
            ) : undefined
          }
        />

        {error && (
          <div className="mb-4 rounded border border-red-900/40 bg-red-900/10 p-3 text-sm text-red-300">
            Something went wrong. Please try again.
          </div>
        )}

        {canWrite && showImport && (
          <div className="mb-4 rounded border border-border bg-surface-raised p-4">
            <div className="mb-3 flex items-center justify-between">
              <h2 className="text-sm font-medium text-content">
                Import native advisories
              </h2>
              {importRuns && importRuns.length > 0 && (
                <span className="text-xs text-content-subtle">
                  Last import{' '}
                  <span className="text-content">
                    {formatTimestamp(importRuns[0].started_at)}
                  </span>{' '}
                  - {importRuns[0].status}, {importRuns[0].imported_count} new /{' '}
                  {importRuns[0].refreshed_count} updated /{' '}
                  {importRuns[0].unchanged_count} unchanged /{' '}
                  {importRuns[0].error_count} error(s)
                </span>
              )}
            </div>
            <p className="mb-3 text-xs text-content-muted">
              Paste one raw advisory object or a JSON array of them for the
              selected source. Payloads are normalized and stored server-side,
              and host applicability is recomputed for affected targets.
            </p>
            <div className="flex flex-col gap-3 md:flex-row">
              <label className="text-xs text-content-muted md:w-56">
                Source
                <select
                  className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
                  value={importSource}
                  onChange={(e) =>
                    setImportSource(e.target.value as AdvisorySourceKind)
                  }
                >
                  {ADVISORY_SOURCE_KIND_VALUES.map((v) => (
                    <option key={v} value={v}>
                      {SOURCE_KIND_LABELS[v]}
                    </option>
                  ))}
                </select>
              </label>
              <label className="flex-1 text-xs text-content-muted">
                Raw payload JSON
                <textarea
                  className="mt-1 h-40 w-full rounded bg-black/40 px-2 py-1 font-mono text-xs text-content"
                  placeholder='{"id": "USN-1234-1", ...}  or  [ {...}, {...} ]'
                  value={importText}
                  onChange={(e) => setImportText(e.target.value)}
                />
              </label>
            </div>
            <div className="mt-3 flex items-center gap-3">
              <button
                onClick={handleImport}
                disabled={importing || !importText.trim()}
                className="inline-flex items-center gap-2 rounded-md bg-blue-600 px-3 py-1.5 text-sm text-white hover:bg-blue-500 disabled:opacity-50"
              >
                <Upload size={14} />
                {importing ? 'Importing…' : 'Import'}
              </button>
              {importError && (
                <span className="text-xs text-red-300">{importError}</span>
              )}
            </div>
            {importResult && importResult.run.error_count > 0 && (
              <div className="mt-3 rounded border border-red-900/40 bg-red-900/10 p-2 text-xs text-red-300">
                <div className="mb-1 font-medium">Per-payload errors:</div>
                <ul className="list-inside list-disc">
                  {importResult.outcomes
                    .filter((o) => o.action === 'error')
                    .map((o, i) => (
                      <li key={i}>
                        <span className="font-mono">{o.source_advisory_id}</span>
                        : {o.error}
                      </li>
                    ))}
                </ul>
              </div>
            )}
          </div>
        )}

        <div className="mb-4 grid grid-cols-2 gap-3 rounded border border-border bg-surface-raised p-3 md:grid-cols-4">
          <label className="text-xs text-content-muted">
            Source
            <select
              className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
              value={filters.source_kind}
              onChange={(e) =>
                setFilter({ source_kind: e.target.value as AdvisorySourceKind | '' })
              }
            >
              <option value="">All sources</option>
              {ADVISORY_SOURCE_KIND_VALUES.map((v) => (
                <option key={v} value={v}>
                  {SOURCE_KIND_LABELS[v]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-content-muted">
            Class
            <select
              className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
              value={filters.advisory_class}
              onChange={(e) =>
                setFilter({ advisory_class: e.target.value as AdvisoryClass | '' })
              }
            >
              <option value="">All classes</option>
              {ADVISORY_CLASS_VALUES.map((v) => (
                <option key={v} value={v}>
                  {ADVISORY_CLASS_LABELS[v]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-content-muted">
            Severity
            <select
              className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
              value={filters.severity}
              onChange={(e) =>
                setFilter({ severity: e.target.value as AdvisorySeverity | '' })
              }
            >
              <option value="">All severities</option>
              {ADVISORY_SEVERITY_VALUES.map((v) => (
                <option key={v} value={v}>
                  {SEVERITY_LABELS[v]}
                </option>
              ))}
            </select>
          </label>
          <label className="text-xs text-content-muted">
            Distro family
            <select
              className={`mt-1 w-full rounded px-2 py-1 text-sm ${nativeSelectClass}`}
              value={filters.distro_family}
              onChange={(e) =>
                setFilter({ distro_family: e.target.value as AdvisoryDistroFamily | '' })
              }
            >
              <option value="">All families</option>
              {ADVISORY_DISTRO_FAMILY_VALUES.map((v) => (
                <option key={v} value={v}>
                  {DISTRO_FAMILY_LABELS[v]}
                </option>
              ))}
            </select>
          </label>
        </div>

        {advisories === null && !error && <LoadingState label="Loading advisories" />}

        {advisories !== null && advisories.length === 0 && (
          <div className="rounded border border-border bg-surface-raised p-6 text-sm text-content-muted">
            {canWrite
              ? 'No advisories match these filters. Use “Import advisories” above to load native Ubuntu USN, Debian security, or Red Hat updateinfo payloads.'
              : 'No advisories match these filters. An administrator can import native distribution advisories to populate this list.'}
          </div>
        )}

        {advisories && advisories.length > 0 && (
          <div className="overflow-x-auto rounded border border-border bg-surface-raised">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-content-muted">
                <tr>
                  <th className="px-4 py-2">Source ID / title</th>
                  <th className="px-4 py-2">Severity</th>
                  <th className="px-4 py-2">Class</th>
                  <th className="px-4 py-2">Distro family</th>
                  <th className="px-4 py-2">Source</th>
                  <th className="px-4 py-2">Published</th>
                  <th className="px-4 py-2 text-right">Actions</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {advisories.map((a) => (
                  <tr key={a.id} className="hover:bg-surface-overlay/40">
                    <td className="px-4 py-2">
                      <Link
                        href={`/patch-advisories/${a.id}`}
                        className="font-mono text-blue-400 hover:text-blue-300"
                      >
                        {a.source_advisory_id}
                      </Link>
                      <div className="text-xs text-content-subtle">{a.title}</div>
                    </td>
                    <td className="px-4 py-2">
                      <Badge variant={severityBadgeVariant(a.severity)}>
                        {SEVERITY_LABELS[a.severity]}
                      </Badge>
                    </td>
                    <td className="px-4 py-2 text-content">
                      {ADVISORY_CLASS_LABELS[a.advisory_class]}
                    </td>
                    <td className="px-4 py-2 text-content">
                      {DISTRO_FAMILY_LABELS[a.distro_family]}
                    </td>
                    <td className="px-4 py-2 text-content">
                      {SOURCE_KIND_LABELS[a.source_kind]}
                    </td>
                    <td className="px-4 py-2 text-content-muted">
                      {a.published_at ? formatTimestamp(a.published_at) : '-'}
                    </td>
                    <td className="px-4 py-2 text-right">
                      <Link
                        href={`/patch-advisories/${a.id}`}
                        className="inline-flex items-center gap-1 rounded p-1 text-content-muted hover:text-blue-400"
                        title="View detail"
                      >
                        <Eye size={16} />
                      </Link>
                    </td>
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        )}

        <div className="mt-4 flex items-center justify-between text-xs text-content-subtle">
          <span>
            Showing {advisories?.length ?? 0} starting at offset {offset}
          </span>
          <div className="flex gap-2">
            <button
              onClick={() => setOffset(Math.max(0, offset - PAGE_SIZE))}
              disabled={offset === 0}
              className="rounded border border-border-strong px-3 py-1 text-content hover:bg-surface-overlay disabled:opacity-40"
            >
              Previous
            </button>
            <button
              onClick={() => setOffset(offset + PAGE_SIZE)}
              disabled={(advisories?.length ?? 0) < PAGE_SIZE}
              className="rounded border border-border-strong px-3 py-1 text-content hover:bg-surface-overlay disabled:opacity-40"
            >
              Next
            </button>
          </div>
        </div>
      </div>
    </MainLayout>
  );
};

function severityBadgeVariant(
  severity: AdvisorySeverity,
): 'success' | 'warning' | 'danger' | 'neutral' {
  if (severity === 'critical' || severity === 'high') return 'danger';
  if (severity === 'medium') return 'warning';
  if (severity === 'low' || severity === 'negligible') return 'success';
  return 'neutral';
}

export default PatchAdvisoriesListPage;
