import React, { useState, useRef, useEffect } from 'react';
import { Download, ChevronDown } from 'lucide-react';
import { apiFetch } from '@/utils/api';
import { toast } from 'sonner';

interface ExportButtonProps {
  endpoint: string;
  filename: string;
  formats?: ('csv' | 'json')[];
  params?: Record<string, string>;
  // Optional button text so callers can distinguish multiple exports on the
  // same page (e.g. "Export requests" vs "Export plans"). Defaults to the
  // generic "Export" / "Export <FORMAT>" wording.
  label?: string;
}

const ExportButton: React.FC<ExportButtonProps> = ({
  endpoint,
  filename,
  formats = ['csv', 'json'],
  params = {},
  label,
}) => {
  const [open, setOpen] = useState(false);
  const [exporting, setExporting] = useState(false);
  const ref = useRef<HTMLDivElement>(null);

  useEffect(() => {
    const handler = (e: MouseEvent) => {
      if (ref.current && !ref.current.contains(e.target as Node)) {
        setOpen(false);
      }
    };
    document.addEventListener('mousedown', handler);
    return () => document.removeEventListener('mousedown', handler);
  }, []);

  const doExport = async (format: string) => {
    setExporting(true);
    setOpen(false);
    try {
      const qs = new URLSearchParams({ ...params, format });
      const res = await apiFetch(`${endpoint}?${qs.toString()}`);
      if (!res.ok) throw new Error('Export failed');
      const blob = await res.blob();
      const url = window.URL.createObjectURL(blob);
      const a = document.createElement('a');
      a.href = url;
      a.download = `${filename}.${format}`;
      document.body.appendChild(a);
      a.click();
      a.remove();
      window.URL.revokeObjectURL(url);
      toast.success(`Exported as ${format.toUpperCase()}`);
    } catch (err) {
      toast.error(err instanceof Error ? err.message : 'Export failed');
    } finally {
      setExporting(false);
    }
  };

  if (formats.length === 1) {
    return (
      <button
        onClick={() => doExport(formats[0])}
        disabled={exporting}
        className="bg-gray-700 hover:bg-gray-600 text-gray-200 px-3 py-1.5 rounded flex items-center gap-1 text-sm disabled:opacity-50"
      >
        <Download className="w-4 h-4" />
        {exporting ? 'Exporting...' : (label ?? `Export ${formats[0].toUpperCase()}`)}
      </button>
    );
  }

  return (
    <div ref={ref} className="relative inline-block">
      <button
        onClick={() => setOpen(!open)}
        disabled={exporting}
        className="bg-gray-700 hover:bg-gray-600 text-gray-200 px-3 py-1.5 rounded flex items-center gap-1 text-sm disabled:opacity-50"
      >
        <Download className="w-4 h-4" />
        {exporting ? 'Exporting...' : (label ?? 'Export')}
        <ChevronDown className="w-3 h-3" />
      </button>
      {open && (
        <div className="absolute right-0 mt-1 bg-[#0c0c0f] border border-gray-800/60 rounded shadow-lg z-10">
          {formats.map((f) => (
            <button
              key={f}
              onClick={() => doExport(f)}
              className="block w-full text-left px-4 py-2 text-sm text-gray-200 hover:bg-white/[0.03]"
            >
              {f.toUpperCase()}
            </button>
          ))}
        </div>
      )}
    </div>
  );
};

export default ExportButton;
