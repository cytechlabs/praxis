import React, { useState } from 'react';
import { Copy } from 'lucide-react';
import { toast } from 'sonner';
import { Modal } from '@/components/ui';
import { BUILD_INFO } from '@/config/buildInfo';

/**
 * PRA-341: the compact build-identity badge for the status footer and its About
 * panel. Reads only the canonical `BUILD_INFO` contract - never anything
 * sensitive (no commit/branch, secrets, hosts, or URLs).
 */

const copyValue = (label: string, value: string) => {
  if (!navigator.clipboard) return;
  navigator.clipboard
    .writeText(value)
    .then(() => toast.success(`${label} copied`))
    .catch(() => {});
};

const Row: React.FC<{ label: string; value: string; copy?: string }> = ({ label, value, copy }) => (
  <div className="flex items-start justify-between gap-4 py-2 border-b border-border/50 last:border-0">
    <span className="text-xs uppercase tracking-wide text-content-subtle">{label}</span>
    <span className="flex items-center gap-2 min-w-0">
      <span className="text-sm text-content font-mono break-all text-right">{value}</span>
      {copy && (
        <button
          type="button"
          onClick={() => copyValue(label, copy)}
          aria-label={`Copy ${label.toLowerCase()}`}
          title={`Copy ${label.toLowerCase()}`}
          className="shrink-0 p-1 rounded text-content-subtle hover:text-content hover:bg-surface-overlay transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
        >
          <Copy size={13} />
        </button>
      )}
    </span>
  </div>
);

const BuildInfo: React.FC = () => {
  const [open, setOpen] = useState(false);
  const b = BUILD_INFO;

  return (
    <>
      <button
        type="button"
        onClick={() => setOpen(true)}
        title="About this build"
        className="font-mono text-content-subtle hover:text-content transition-colors focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring rounded"
      >
        Praxis {b.version}
      </button>

      <Modal open={open} onClose={() => setOpen(false)} title="About Praxis">
        <div className="space-y-0">
          <Row label="Version" value={b.version} copy={b.version} />
          <Row
            label="Build date"
            value={b.buildDateCompact ? `${b.buildDateCompact} · ${b.buildDate}` : b.buildDate}
            copy={b.buildDate !== 'unknown' ? b.buildDate : undefined}
          />
          <Row label="Environment" value={b.environment} />
          <Row label="Deployment" value={b.deploymentMode} />
        </div>
      </Modal>
    </>
  );
};

export default BuildInfo;
