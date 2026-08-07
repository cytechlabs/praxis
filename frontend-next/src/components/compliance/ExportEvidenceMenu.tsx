import React, { useState, useRef, useEffect } from 'react';
import { Download, ChevronDown, Lock } from 'lucide-react';
import {
  exportEvidenceHref,
  type ExportEvidenceOpts,
} from '@/services/complianceService';
import { useEntitlements } from '@/context/EntitlementsContext';
import { ENTITLEMENTS } from '@/services/editionService';

/**
 * PRA-237: single "Export evidence" control that consolidates the previously
 * duplicated adjacent JSONL/CSV buttons into one dropdown.
 *
 * CRITICAL: the format choices are plain `<a href={exportEvidenceHref(...)}>`
 * links, NOT fetch-to-blob downloads. Evidence exports can be large; letting
 * the browser GET the URL directly streams the response to disk (auth cookies
 * travel with the GET, Content-Disposition drives the save) instead of
 * buffering the whole payload in frontend memory the way `ExportButton` does.
 * Do not swap these anchors for `apiFetch`/blob handlers.
 *
 * `baseOpts` carries the page's current filters (system_id / policy_id /
 * verdict / date window); `format` is filled per menu item.
 */
type BaseOpts = Omit<ExportEvidenceOpts, 'format'>;

const ExportEvidenceMenu: React.FC<{ baseOpts?: BaseOpts }> = ({
  baseOpts = {},
}) => {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLDivElement>(null);
  const { hasEntitlement } = useEntitlements();
  const entitled = hasEntitlement(ENTITLEMENTS.COMPLIANCE_BULK_EXPORTS);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const formats: { key: 'jsonl' | 'csv'; label: string }[] = [
    { key: 'jsonl', label: 'JSONL' },
    { key: 'csv', label: 'CSV' },
  ];

  // PRA-132: bulk evidence export is a paid feature. In the free edition show a
  // locked affordance instead of the working menu; the backend also enforces it.
  if (!entitled) {
    return (
      <button
        type="button"
        disabled
        title="Bulk evidence export is part of the paid Praxis edition"
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-800 text-sm text-gray-500 cursor-not-allowed"
      >
        <Lock size={14} /> Export evidence (Pro)
      </button>
    );
  }

  return (
    <div ref={ref} className="relative inline-block">
      <button
        type="button"
        onClick={() => setOpen(!open)}
        className="inline-flex items-center gap-2 px-3 py-1.5 rounded-md bg-slate-700 hover:bg-slate-600 text-sm text-gray-100 transition-colors"
      >
        <Download size={14} /> Export evidence
        <ChevronDown className="w-3 h-3" />
      </button>
      {open && (
        <div className="absolute right-0 mt-1 bg-[#0c0c0f] border border-gray-800/60 rounded shadow-lg z-10">
          {formats.map((f) => (
            <a
              key={f.key}
              href={exportEvidenceHref({ ...baseOpts, format: f.key })}
              onClick={() => setOpen(false)}
              className="block w-full text-left px-4 py-2 text-sm text-gray-200 hover:bg-white/[0.03] whitespace-nowrap"
            >
              {f.label}
            </a>
          ))}
        </div>
      )}
    </div>
  );
};

export default ExportEvidenceMenu;
