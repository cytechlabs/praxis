import React, { useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { ErrorState, PageHeader } from '@/components/ui';
import {
  getMirrorRun,
  getMirrorRunManifest,
  type MirrorManifest,
  type MirrorSyncRun,
} from '@/services/mirrorService';

function formatBytes(bytes: number | null | undefined): string {
  if (!bytes || bytes <= 0) return '0 B';
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB'];
  let i = 0;
  let n = bytes;
  while (n >= 1024 && i < units.length - 1) {
    n /= 1024;
    i++;
  }
  return `${n.toFixed(n < 10 && i > 0 ? 1 : 0)} ${units[i]}`;
}

const ManifestSummaryPage: React.FC = () => {
  const router = useRouter();
  const idParam = router.query.id;
  const runIdParam = router.query.runId;
  const id = typeof idParam === 'string' ? Number(idParam) : NaN;
  const runId = typeof runIdParam === 'string' ? Number(runIdParam) : NaN;

  const [manifest, setManifest] = useState<MirrorManifest | null>(null);
  const [run, setRun] = useState<MirrorSyncRun | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!Number.isFinite(id) || !Number.isFinite(runId)) return;
    Promise.all([getMirrorRunManifest(id, runId), getMirrorRun(id, runId)])
      .then(([m, r]) => {
        setManifest(m);
        setRun(r);
      })
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [id, runId]);

  // Per-arch summary computed on the client.
  const archCounts = React.useMemo(() => {
    if (!manifest) return [];
    const counts = new Map<string, number>();
    for (const f of manifest.files) {
      if (f.arch) counts.set(f.arch, (counts.get(f.arch) || 0) + 1);
    }
    return [...counts.entries()].sort((a, b) => a[0].localeCompare(b[0]));
  }, [manifest]);

  return (
    <MainLayout>
      <Head>
        <title>Run {runId} manifest · Praxis</title>
      </Head>
      <div className="p-6">
        <Link
          href={`/mirrors/${id}`}
          className="mb-4 inline-flex items-center gap-1 text-sm text-content-muted hover:text-content"
        >
          <ArrowLeft size={14} /> Back to mirror
        </Link>

        <PageHeader
          title={`Run #${runId} manifest`}
          subtitle="Per-file listing recorded after the work/ → live/ promotion. The content fingerprint (sha256 of the canonical content view) is the stable identity used for repository signing and as the bundle index."
        />

        {error && <ErrorState title="Couldn’t load manifest" />}

        {!manifest && !error && (
          <div className="text-content-muted">Loading manifest…</div>
        )}

        {manifest && (
          <>
            <section className="mb-6 grid grid-cols-1 gap-4 md:grid-cols-2">
              <Field
                label="Content fingerprint (manifest_sha256)"
                value={run?.manifest_sha256 ?? '-'}
                mono
                hint="sha256 over the canonical content view; the value signed for repository trust and used as the bundle index. Stable across runs of identical bytes."
              />
              <Field
                label="Format version"
                value={manifest.praxis_mirror_manifest}
                mono
                hint="Schema version of the manifest body, NOT the content fingerprint."
              />
              <Field label="Mirror slug" value={manifest.mirror_slug} mono />
              <Field label="Run id" value={String(manifest.run_id)} />
              <Field label="Package family" value={manifest.package_family} />
              <Field label="Generated at" value={manifest.generated_at} />
              <Field label="Total bytes" value={formatBytes(manifest.byte_count)} />
              <Field label="Package count" value={String(manifest.package_count)} />
              <Field label="File count" value={String(manifest.files.length)} />
            </section>

            {archCounts.length > 0 && (
              <section className="mb-6">
                <h2 className="mb-2 text-sm font-medium uppercase text-content-muted">
                  Packages by architecture
                </h2>
                <div className="flex flex-wrap gap-2">
                  {archCounts.map(([arch, n]) => (
                    <span
                      key={arch}
                      className="rounded border border-border bg-surface-raised px-3 py-1 text-sm text-content"
                    >
                      <span className="font-mono">{arch}</span>
                      <span className="ml-2 text-content-muted">{n}</span>
                    </span>
                  ))}
                </div>
              </section>
            )}

            <section>
              <h2 className="mb-2 text-sm font-medium uppercase text-content-muted">
                Files ({manifest.files.length})
              </h2>
              <div className="overflow-x-auto rounded border border-border bg-surface-raised">
                <table className="w-full text-sm">
                  <thead className="border-b border-border text-left text-content-muted">
                    <tr>
                      <th className="px-4 py-2">Filename</th>
                      <th className="px-4 py-2">Package</th>
                      <th className="px-4 py-2">Version</th>
                      <th className="px-4 py-2">Arch</th>
                      <th className="px-4 py-2">Size</th>
                    </tr>
                  </thead>
                  <tbody className="divide-y divide-border">
                    {manifest.files.map((f) => (
                      <tr key={f.filename} className="hover:bg-surface-overlay/40">
                        <td className="px-4 py-2 font-mono text-xs text-content">
                          {f.filename}
                        </td>
                        <td className="px-4 py-2 text-content">{f.package || '-'}</td>
                        <td className="px-4 py-2 font-mono text-xs text-content-muted">
                          {f.version || '-'}
                        </td>
                        <td className="px-4 py-2 text-content-muted">{f.arch || '-'}</td>
                        <td className="px-4 py-2 text-content-muted">
                          {formatBytes(f.size)}
                        </td>
                      </tr>
                    ))}
                  </tbody>
                </table>
              </div>
            </section>
          </>
        )}
      </div>
    </MainLayout>
  );
};

const Field: React.FC<{
  label: string;
  value: string;
  mono?: boolean;
  hint?: string;
}> = ({ label, value, mono, hint }) => (
  <div className="rounded border border-border bg-surface-raised p-3">
    <div className="text-xs uppercase text-content-subtle">{label}</div>
    <div
      className={`mt-1 break-all text-sm text-content ${mono ? 'font-mono' : ''}`}
    >
      {value}
    </div>
    {hint && <div className="mt-1 text-xs text-content-subtle">{hint}</div>}
  </div>
);

export default ManifestSummaryPage;
