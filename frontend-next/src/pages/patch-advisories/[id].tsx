/**
 * PRA-163 #4: patch advisory detail page.
 *
 * Single-advisory view: source identity, severity, dates, CVE list,
 * external refs, fixed-package targets, and the raw native payload
 * for forensic inspection.
 */
import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { Badge, Card, CardBody, CardHeader, ErrorState, LoadingState, PageHeader } from '@/components/ui';
import {
  ADVISORY_CLASS_LABELS,
  DISTRO_FAMILY_LABELS,
  getPatchAdvisory,
  type PatchAdvisoryDetail,
  SEVERITY_LABELS,
  SOURCE_KIND_LABELS,
} from '@/services/patchAdvisoryService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const PatchAdvisoryDetailPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const router = useRouter();
  const { id } = router.query;
  const [advisory, setAdvisory] = useState<PatchAdvisoryDetail | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [showRaw, setShowRaw] = useState(false);

  const load = useCallback(async () => {
    if (typeof id !== 'string') return;
    const advisoryId = Number.parseInt(id, 10);
    if (Number.isNaN(advisoryId)) {
      setError('invalid advisory id');
      return;
    }
    try {
      const data = await getPatchAdvisory(advisoryId);
      setAdvisory(data);
      setError(null);
    } catch (e) {
      setError(e instanceof Error ? e.message : String(e));
    }
  }, [id]);

  useEffect(() => {
    load();
  }, [load]);

  if (error) {
    return (
      <MainLayout>
        <Head>
          <title>Patch advisory · Praxis</title>
        </Head>
        <div className="p-6">
          <ErrorState
            title="Couldn’t load advisory"
            onRetry={load}
            className="mb-4"
          />
          <Link
            href="/patch-advisories/all"
            className="inline-flex items-center gap-1 text-sm text-link hover:text-link-hover"
          >
            <ArrowLeft size={14} /> Back to advisories
          </Link>
        </div>
      </MainLayout>
    );
  }

  if (!advisory) {
    return (
      <MainLayout>
        <Head>
          <title>Patch advisory · Praxis</title>
        </Head>
        <LoadingState label="Loading advisory" />
      </MainLayout>
    );
  }

  return (
    <MainLayout>
      <Head>
        <title>{advisory.source_advisory_id} · Praxis</title>
      </Head>
      <div className="p-6">
        <div className="mb-3">
          <Link
            href="/patch-advisories/all"
            className="inline-flex items-center gap-1 text-sm text-link hover:text-link-hover"
          >
            <ArrowLeft size={14} /> Back to advisories
          </Link>
        </div>
        <PageHeader
          title={advisory.source_advisory_id}
          subtitle={advisory.title}
        />

        <Card className="mb-4">
          <CardHeader>Metadata</CardHeader>
          <CardBody>
            <dl className="grid grid-cols-2 gap-x-6 gap-y-2 text-sm md:grid-cols-3">
              <div>
                <dt className="text-xs text-content-subtle">Source</dt>
                <dd className="text-content">
                  {SOURCE_KIND_LABELS[advisory.source_kind]}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-content-subtle">Class</dt>
                <dd className="text-content">
                  {ADVISORY_CLASS_LABELS[advisory.advisory_class]}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-content-subtle">Severity</dt>
                <dd>
                  <Badge>{SEVERITY_LABELS[advisory.severity]}</Badge>
                </dd>
              </div>
              <div>
                <dt className="text-xs text-content-subtle">Distro family</dt>
                <dd className="text-content">
                  {DISTRO_FAMILY_LABELS[advisory.distro_family]}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-content-subtle">Published</dt>
                <dd className="text-content">
                  {advisory.published_at
                    ? formatTimestamp(advisory.published_at)
                    : '-'}
                </dd>
              </div>
              <div>
                <dt className="text-xs text-content-subtle">Source updated</dt>
                <dd className="text-content">
                  {advisory.source_updated_at
                    ? formatTimestamp(advisory.source_updated_at)
                    : '-'}
                </dd>
              </div>
            </dl>
            {advisory.summary && (
              <div className="mt-4 text-sm text-content">
                <div className="mb-1 text-xs text-content-subtle">Summary</div>
                <p className="whitespace-pre-wrap">{advisory.summary}</p>
              </div>
            )}
            {advisory.cve_ids && advisory.cve_ids.length > 0 && (
              <div className="mt-4">
                <div className="mb-1 text-xs text-content-subtle">CVE references</div>
                <div className="flex flex-wrap gap-1">
                  {advisory.cve_ids.map((c) => (
                    <span
                      key={c}
                      className="inline-flex items-center rounded border border-border-strong bg-surface-raised/40 px-1.5 py-0.5 font-mono text-xs text-content"
                    >
                      {c}
                    </span>
                  ))}
                </div>
              </div>
            )}
            {advisory.external_refs && advisory.external_refs.length > 0 && (
              <div className="mt-4">
                <div className="mb-1 text-xs text-content-subtle">External references</div>
                <ul className="list-inside list-disc text-xs text-blue-400">
                  {advisory.external_refs.map((url) => (
                    <li key={url}>
                      <a
                        href={url}
                        target="_blank"
                        rel="noopener noreferrer"
                        className="hover:text-blue-300"
                      >
                        {url}
                      </a>
                    </li>
                  ))}
                </ul>
              </div>
            )}
          </CardBody>
        </Card>

        <Card className="mb-4">
          <CardHeader>Fixed-package targets</CardHeader>
          <CardBody>
            {advisory.fixed_packages.length === 0 ? (
              <p className="text-sm text-content-muted">
                No per-release fixed-package targets were imported with this
                advisory.
              </p>
            ) : (
              <div className="overflow-x-auto">
                <table className="w-full text-sm">
                  <thead className="border-b border-border text-left text-content-muted">
                    <tr>
                      <th className="px-2 py-2">Distro</th>
                      <th className="px-2 py-2">Release</th>
                      <th className="px-2 py-2">Package</th>
                      <th className="px-2 py-2">Fixed version</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {advisory.fixed_packages.map((fp) => (
                      <tr key={fp.id}>
                        <td className="px-2 py-1 text-content">{fp.distro_id}</td>
                        <td className="px-2 py-1 text-content">{fp.distro_release}</td>
                        <td className="px-2 py-1 font-mono text-content">
                          {fp.package_name}
                        </td>
                        <td className="px-2 py-1 font-mono text-content">
                          {fp.fixed_version ?? (
                            <span className="text-content-subtle" title="No published fix">
                              (none)
                            </span>
                          )}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            )}
          </CardBody>
        </Card>

        <Card>
          <CardHeader
            action={
              <button
                onClick={() => setShowRaw((s) => !s)}
                className="rounded border border-border-strong px-2 py-0.5 text-xs text-content hover:bg-surface-overlay"
              >
                {showRaw ? 'Hide' : 'Show'}
              </button>
            }
          >
            <div>
              <div>Raw source payload</div>
              <div className="mt-0.5 text-xs font-normal text-content-subtle">
                Native source dict as imported. Forensic only.
              </div>
            </div>
          </CardHeader>
          {showRaw && (
            <CardBody>
              <pre className="overflow-x-auto rounded bg-black/40 p-3 font-mono text-xs text-content">
                {JSON.stringify(advisory.raw, null, 2)}
              </pre>
            </CardBody>
          )}
        </Card>
      </div>
    </MainLayout>
  );
};

export default PatchAdvisoryDetailPage;
