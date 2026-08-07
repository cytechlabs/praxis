import { useState } from 'react';
import { toast } from 'sonner';
import { LifeBuoy, Download, ShieldCheck } from 'lucide-react';
import { Badge, Button, Card, CardBody, CardHeader, Select } from '@/components/ui';
import {
  SupportBundleRange,
  downloadSupportBundle,
} from '../../services/diagnosticsService';
import { useFormatTimestamp } from '@/context/TimestampPreferencesContext';

const RANGES: { id: SupportBundleRange; label: string }[] = [
  { id: '24h', label: 'Last 24 hours' },
  { id: '72h', label: 'Last 72 hours' },
  { id: '7d', label: 'Last 7 days' },
];

function _fmtBytes(n: number): string {
  if (n < 1024) return `${n} B`;
  if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
  return `${(n / (1024 * 1024)).toFixed(1)} MB`;
}

const SupportDiagnosticsTab = () => {
  const formatTimestamp = useFormatTimestamp();
  const [range, setRange] = useState<SupportBundleRange>('72h');
  const [busy, setBusy] = useState(false);
  const [last, setLast] = useState<{ at: string; bytes: number } | null>(null);

  const generate = async () => {
    setBusy(true);
    try {
      const res = await downloadSupportBundle(range);
      setLast({ at: res.generatedAt, bytes: res.bytes });
      toast.success(`Support bundle generated (${_fmtBytes(res.bytes)})`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Failed to generate support bundle');
    } finally {
      setBusy(false);
    }
  };

  return (
    <div className="space-y-6">
      <Card>
        <CardHeader>
          <div>
            <div className="flex items-center gap-2"><LifeBuoy size={16} /> Support / Diagnostics</div>
            <div className="text-xs font-normal text-gray-500 mt-0.5">
              Generate a redacted diagnostic bundle to send to Cytech Labs support.
            </div>
          </div>
        </CardHeader>
        <CardBody>
          <div className="rounded-lg border border-gray-800 bg-black/30 p-3 mb-4 text-sm text-gray-400 flex items-start gap-2">
            <ShieldCheck size={16} className="mt-0.5 shrink-0 text-emerald-400" />
            <span>
              The bundle contains recent backend logs (bounded), agent-broker logs
              when the broker is reachable, app/schema version, an allowlisted config
              summary, health, reconcile/revocation state, recent failed jobs, and
              limited host metadata. Secrets are redacted - no
              passwords, Vault/root/unseal tokens, refresh/access tokens, license JWTs,
              private keys, session cookies, full environment, or command output are
              included. Generation is admin-only and audited. Review it against your
              policy before sending.
            </span>
          </div>

          <div className="flex flex-wrap items-end gap-3">
            <div className="min-w-[12rem]">
              <label className="block text-xs uppercase tracking-wide text-gray-500 mb-1">Time range</label>
              <Select value={range} onChange={(e) => setRange(e.target.value as SupportBundleRange)}>
                {RANGES.map((r) => (
                  <option key={r.id} value={r.id}>{r.label}</option>
                ))}
              </Select>
            </div>
            <Button variant="primary" onClick={generate} disabled={busy}>
              <Download size={14} className="mr-1.5" />
              {busy ? 'Generating…' : 'Generate support bundle'}
            </Button>
          </div>

          {last && (
            <div className="mt-4 text-xs text-gray-500 flex items-center gap-2">
              <Badge variant="success">downloaded</Badge>
              Last generated {formatTimestamp(last.at)} · {_fmtBytes(last.bytes)}
            </div>
          )}
        </CardBody>
      </Card>
    </div>
  );
};

export default SupportDiagnosticsTab;
