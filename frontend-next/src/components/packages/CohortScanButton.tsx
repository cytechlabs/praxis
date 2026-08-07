import React, { useState } from 'react';
import { toast } from 'sonner';
import { RefreshCw } from 'lucide-react';
import { Badge, Button, ConfirmModal, Modal } from '@/components/ui';
import { PackageScope } from '@/services/packageScope';
import { scanScope, CohortScanResult } from '@/services/packageService';

// Guarded cohort scan button: confirms scope + host count, runs the cohort scan,
// and shows per-host results. Rendered only for group/smart-group scopes.
function statusVariant(status: string): 'success' | 'warning' | 'danger' {
  if (status === 'success') return 'success';
  if (status === 'already_running') return 'warning';
  return 'danger';
}

function statusLabel(status: string): string {
  if (status === 'success') return 'Refreshed';
  if (status === 'already_running') return 'Skipped';
  return 'Failed';
}

const CohortScanButton: React.FC<{
  scope: PackageScope;
  scopeName: string;
  hostCount: number;
  label: string;
  security?: boolean;
  onComplete?: () => void;
}> = ({ scope, scopeName, hostCount, label, security, onComplete }) => {
  const [confirmOpen, setConfirmOpen] = useState(false);
  const [running, setRunning] = useState(false);
  const [result, setResult] = useState<CohortScanResult | null>(null);

  const isCohort = scope.type === 'group' || scope.type === 'smart_group';
  const scopeKind = scope.type === 'smart_group' ? 'smart group' : 'group';
  const disabled = !isCohort || hostCount === 0 || running;

  const run = async () => {
    setConfirmOpen(false);
    setRunning(true);
    try {
      const res = await scanScope(scope, { security: !!security });
      setResult(res);
      if (res.failure_count > 0) {
        toast.warning(
          `Refreshed ${res.success_count}/${res.total} host(s); ${res.failure_count} failed`,
        );
      } else {
        toast.success(
          `Refreshed ${res.success_count}/${res.total} host(s)` +
            (res.skipped_count ? `, ${res.skipped_count} skipped` : ''),
        );
      }
      onComplete?.();
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Cohort scan failed');
    } finally {
      setRunning(false);
    }
  };

  return (
    <>
      <Button
        variant="outline"
        icon={<RefreshCw className="w-4 h-4" />}
        loading={running}
        disabled={disabled}
        onClick={() => setConfirmOpen(true)}
      >
        {running ? 'Refreshing...' : label}
      </Button>

      <ConfirmModal
        open={confirmOpen}
        onClose={() => setConfirmOpen(false)}
        onConfirm={run}
        title={label}
        message={
          `Run a ${security ? 'security ' : ''}package scan on ${hostCount} ` +
          `host${hostCount === 1 ? '' : 's'} in ${scopeKind} "${scopeName}"? ` +
          'This refreshes inventory per host; partial failures are shown and no ' +
          'updates are applied.'
        }
        confirmLabel="Refresh"
        variant="warning"
        loading={running}
      />

      <Modal
        open={result != null}
        onClose={() => setResult(null)}
        title="Refresh results"
        maxWidth="max-w-2xl"
      >
        {result && (
          <div className="space-y-3">
            <div className="flex flex-wrap gap-4 text-sm text-content-muted">
              <span>
                <span className="text-content font-medium">{result.success_count}</span> refreshed
              </span>
              <span>
                <span className="text-content font-medium">{result.failure_count}</span> failed
              </span>
              <span>
                <span className="text-content font-medium">{result.skipped_count}</span> skipped
              </span>
            </div>
            <div className="max-h-80 divide-y divide-border overflow-y-auto rounded-md border border-border">
              {result.results.map((r) => (
                <div
                  key={r.system_id}
                  className="flex items-center justify-between gap-3 px-3 py-2 text-sm"
                >
                  <div className="min-w-0">
                    <div className="truncate text-content">{r.hostname}</div>
                    {r.message && (
                      <div className="truncate text-xs text-content-subtle">{r.message}</div>
                    )}
                  </div>
                  <Badge variant={statusVariant(r.status)}>{statusLabel(r.status)}</Badge>
                </div>
              ))}
            </div>
          </div>
        )}
      </Modal>
    </>
  );
};

export default CohortScanButton;
