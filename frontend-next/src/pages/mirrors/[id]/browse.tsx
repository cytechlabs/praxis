import React, { useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { useRouter } from 'next/router';
import { ArrowLeft, ArrowUp, File, Folder } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { ErrorState, LoadingState, PageHeader } from '@/components/ui';
import {
  browseMirror,
  type MirrorBrowseResponse,
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

const BrowsePage: React.FC = () => {
  const router = useRouter();
  const idParam = router.query.id;
  const pathParam = router.query.path;
  const id = typeof idParam === 'string' ? Number(idParam) : NaN;
  const path = typeof pathParam === 'string' ? pathParam : '';

  const [data, setData] = useState<MirrorBrowseResponse | null>(null);
  const [error, setError] = useState<string | null>(null);

  useEffect(() => {
    if (!Number.isFinite(id)) return;
    setData(null);
    setError(null);
    browseMirror(id, path)
      .then(setData)
      .catch((e) => setError(e instanceof Error ? e.message : String(e)));
  }, [id, path]);

  return (
    <MainLayout>
      <Head>
        <title>Browse · Mirror {id} · Praxis</title>
      </Head>
      <div className="p-6">
        <Link
          href={`/mirrors/${id}`}
          className="mb-4 inline-flex items-center gap-1 text-sm text-content-muted hover:text-content"
        >
          <ArrowLeft size={14} /> Back to mirror
        </Link>

        <PageHeader
          title="Browse content"
          subtitle={`live/${path ? `/${path}` : ''}`}
        />

        {error && <ErrorState title="Couldn’t load content" />}

        {!data && !error && <LoadingState label="Loading content" />}

        {data && (
          <div className="overflow-x-auto rounded border border-border bg-surface-raised">
            <table className="w-full text-sm">
              <thead className="border-b border-border text-left text-content-muted">
                <tr>
                  <th className="px-4 py-2">Name</th>
                  <th className="px-4 py-2">Type</th>
                  <th className="px-4 py-2">Size</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-border">
                {data.parent !== null && (
                  <tr className="hover:bg-surface-overlay/40">
                    <td colSpan={3} className="px-4 py-2">
                      <Link
                        href={
                          data.parent
                            ? `/mirrors/${id}/browse?path=${encodeURIComponent(data.parent)}`
                            : `/mirrors/${id}/browse`
                        }
                        className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300"
                      >
                        <ArrowUp size={14} /> ..
                      </Link>
                    </td>
                  </tr>
                )}
                {data.entries.length === 0 && data.parent === null && (
                  <tr>
                    <td
                      colSpan={3}
                      className="px-4 py-4 text-center text-content-subtle"
                    >
                      Empty directory.
                    </td>
                  </tr>
                )}
                {data.entries.map((e) => {
                  const childPath = path ? `${path}/${e.name}` : e.name;
                  return (
                    <tr key={e.name} className="hover:bg-surface-overlay/40">
                      <td className="px-4 py-2 font-mono text-content">
                        {e.type === 'dir' ? (
                          <Link
                            href={`/mirrors/${id}/browse?path=${encodeURIComponent(childPath)}`}
                            className="inline-flex items-center gap-2 text-blue-400 hover:text-blue-300"
                          >
                            <Folder size={14} /> {e.name}/
                          </Link>
                        ) : (
                          <span className="inline-flex items-center gap-2 text-content">
                            <File size={14} /> {e.name}
                          </span>
                        )}
                      </td>
                      <td className="px-4 py-2 text-content-muted">{e.type}</td>
                      <td className="px-4 py-2 text-content-muted">
                        {e.type === 'file' ? formatBytes(e.size) : '-'}
                      </td>
                    </tr>
                  );
                })}
              </tbody>
            </table>
          </div>
        )}
      </div>
    </MainLayout>
  );
};

export default BrowsePage;
