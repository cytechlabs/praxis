import React, { useCallback, useEffect, useState } from 'react';
import Head from 'next/head';
import Link from 'next/link';
import { CheckCircle, XCircle, AlertTriangle, HelpCircle, X } from 'lucide-react';
import MainLayout from '@/components/MainLayout';
import { PageHeader, Button, EmptyState, LoadingState, ErrorState } from '@/components/ui';
import HelpLink from '@/components/help/HelpLink';
import { apiFetch } from '@/utils/api';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

interface Cell {
  status: 'compliant' | 'drifted' | 'error' | 'unknown';
  run_at?: string;
  drift_details?: Array<{ category: string; rule: { name: string; check: string; version?: string }; reason: string }>;
}

interface Row { system_id: number; hostname: string; cells: Cell[] }
interface MatrixBaseline { id: number; name: string }

const cellIcon = (s: Cell['status']) => {
  if (s === 'compliant') return <CheckCircle size={14} className="text-green-500" />;
  if (s === 'drifted') return <XCircle size={14} className="text-red-500" />;
  if (s === 'error') return <AlertTriangle size={14} className="text-amber-400" />;
  return <HelpCircle size={14} className="text-gray-600" />;
};

const DriftPage: React.FC = () => {
  const formatTimestamp = useFormatTimestamp();
  const [baselines, setBaselines] = useState<MatrixBaseline[]>([]);
  const [rows, setRows] = useState<Row[]>([]);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [drawer, setDrawer] = useState<{ row: Row; cell: Cell; bname: string } | null>(null);

  const fetch = useCallback(async () => {
    try {
      const res = await apiFetch('/api/backend/baselines/-/drift/by-system');
      if (!res.ok) { setError(true); return; }
      const data = await res.json();
      setBaselines(data.baselines || []);
      setRows(data.rows || []);
      setError(false);
    } catch {
      setError(true);
    } finally { setLoading(false); }
  }, []);

  // PRA-274: distinguish the states - a check failure, no baselines configured,
  // no systems enrolled, or systems present with no drift - instead of one
  // "No systems yet" message that fired for all of them.
  const hasDrift = rows.some((r) => r.cells.some((c) => c.status === 'drifted' || c.status === 'error'));

  useEffect(() => { fetch(); const t = setInterval(fetch, 15000); return () => clearInterval(t); }, [fetch]);

  const openCell = (row: Row, cell: Cell, bname: string) => {
    if (cell.status === 'drifted' || cell.status === 'error') {
      setDrawer({ row, cell, bname });
    }
  };

  return (
    <MainLayout>
      <Head><title>Drift - Praxis</title></Head>
      <PageHeader
        title="Configuration Drift"
        subtitle="Latest baseline check per system. Click a drifted cell to see offending rules."
        actions={<HelpLink slug="monitoring-and-alerts" />}
      />

      {loading ? (
        <LoadingState label="Loading drift" />
      ) : error ? (
        <ErrorState
          title="Couldn’t load drift"
          description="The drift check data couldn’t be loaded. Retry, or check back shortly."
          onRetry={fetch}
        />
      ) : baselines.length === 0 ? (
        <EmptyState
          variant="not-configured"
          title="No baselines configured"
          description="Create a baseline to start tracking configuration drift across your fleet."
          action={
            <Link href="/monitoring-reporting/baselines">
              <Button variant="secondary" size="sm">Go to baselines</Button>
            </Link>
          }
        />
      ) : rows.length === 0 ? (
        <EmptyState
          variant="no-activity"
          title="No systems enrolled"
          description="Register a system to see how it compares against your baselines."
          action={
            <Link href="/system-management/register">
              <Button variant="secondary" size="sm">Register a system</Button>
            </Link>
          }
        />
      ) : (
        <>
          {!hasDrift && (
            <div className="mb-3 rounded-md border border-success/30 bg-success/10 px-3 py-2 text-sm text-success">
              No drift detected - every system matches its baselines.
            </div>
          )}
          <div className="border border-zinc-800 rounded-lg overflow-auto">
            <table className="w-full text-sm text-gray-200">
              <thead className="bg-red-900/30 text-gray-300 text-xs uppercase">
                <tr>
                  <th className="px-4 py-3 text-left">System</th>
                  {baselines.map(b => (
                    <th key={b.id} className="px-4 py-3 text-center" title={b.name}>{b.name}</th>
                  ))}
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-800">
                {rows.map(r => (
                  <tr key={r.system_id} className="hover:bg-white/[0.03]">
                    <td className="px-4 py-3 font-medium">{r.hostname}</td>
                    {r.cells.map((c, i) => (
                      <td key={i} className="px-4 py-3 text-center">
                        <button
                          onClick={() => openCell(r, c, baselines[i].name)}
                          disabled={c.status !== 'drifted' && c.status !== 'error'}
                          className="inline-flex items-center gap-1 disabled:cursor-default"
                          title={c.run_at ? `Checked ${formatTimestamp(c.run_at)}` : 'Not yet evaluated'}
                        >
                          {cellIcon(c.status)}
                        </button>
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
          </div>
        </>
      )}

      {drawer && (
        <div className="fixed inset-0 z-40 flex justify-end bg-[#0c0c0f]/70" onClick={() => setDrawer(null)}>
          <div className="bg-[#0c0c0f] border-l border-zinc-800 w-full max-w-lg h-full overflow-y-auto p-5 space-y-3" onClick={e => e.stopPropagation()}>
            <div className="flex items-center justify-between">
              <h3 className="text-lg font-semibold text-gray-100">
                {drawer.row.hostname} · {drawer.bname}
              </h3>
              <button onClick={() => setDrawer(null)} className="text-gray-500 hover:text-gray-300"><X size={18} /></button>
            </div>
            <div className="text-xs text-gray-500">Last check {drawer.cell.run_at ? formatTimestamp(drawer.cell.run_at) : 'never'}</div>
            {drawer.cell.status === 'error' ? (
              <div className="p-3 border border-amber-900/50 rounded bg-amber-900/10 text-amber-300 text-sm">
                Check could not complete - see backend logs. A transient SSH failure will clear on next run.
              </div>
            ) : (
              <div className="space-y-2">
                {(drawer.cell.drift_details || []).map((d, i) => (
                  <div key={i} className="p-3 border border-red-900/50 rounded bg-red-900/10">
                    <div className="flex items-center justify-between">
                      <div className="font-mono text-sm text-gray-200">{d.rule.name}</div>
                      <div className="text-xs text-red-300 uppercase">{d.category} · {d.rule.check}{d.rule.version ? ` @ ${d.rule.version}` : ''}</div>
                    </div>
                    <div className="text-xs text-gray-400 mt-1">{d.reason}</div>
                  </div>
                ))}
              </div>
            )}
          </div>
        </div>
      )}
    </MainLayout>
  );
};

export default DriftPage;
