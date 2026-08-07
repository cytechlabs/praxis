import React, { useState } from 'react';
import { X } from 'lucide-react';
import { SearchInput } from '@/components/ui';

export interface SystemPickerSystem {
  id: number;
  hostname: string;
}

/**
 * Hostname-searchable multi-select for the System Comparison page.
 *
 * Scales to large fleets: instead of rendering every host as a chip, an operator
 * types part of a hostname to narrow an "Available" list. Already-selected hosts
 * live in a separate always-visible "Selected" row so they stay reachable and
 * removable even while the search hides everything else. Selection state (the
 * 2–10 min/max) is owned by the parent via `onToggle`; this component only
 * searches and renders.
 */
const SystemPicker: React.FC<{
  systems: SystemPickerSystem[];
  selectedIds: number[];
  onToggle: (id: number) => void;
}> = ({ systems, selectedIds, onToggle }) => {
  const [search, setSearch] = useState('');
  const query = search.trim().toLowerCase();

  const selectedSet = new Set(selectedIds);
  // Derive both lists from `systems` so the natural hostname ordering (PRA-352)
  // is preserved in the Selected row and the Available list alike.
  const selected = systems.filter((s) => selectedSet.has(s.id));
  const available = systems.filter(
    (s) => !selectedSet.has(s.id) && (!query || s.hostname.toLowerCase().includes(query)),
  );

  return (
    <div>
      {selected.length > 0 && (
        <div className="mb-3">
          <div className="mb-1.5 text-xs font-medium text-content-muted">
            Selected ({selected.length})
          </div>
          <div className="flex flex-wrap gap-2">
            {selected.map((s) => (
              <span
                key={s.id}
                className="inline-flex items-center gap-1.5 rounded-md border border-border bg-surface-overlay px-2.5 py-1 text-sm text-content"
              >
                {s.hostname}
                <button
                  type="button"
                  onClick={() => onToggle(s.id)}
                  aria-label={`Remove ${s.hostname}`}
                  className="text-content-subtle transition-colors hover:text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring rounded"
                >
                  <X className="h-3.5 w-3.5" />
                </button>
              </span>
            ))}
          </div>
        </div>
      )}

      <div className="mb-3 max-w-sm">
        <SearchInput
          value={search}
          onChange={(e) => setSearch(e.target.value)}
          placeholder="Search systems by hostname..."
          aria-label="Search systems by hostname"
        />
      </div>

      <div
        role="group"
        aria-label="Available systems"
        className="flex max-h-48 flex-wrap gap-2 overflow-y-auto"
      >
        {available.length === 0 ? (
          <div className="w-full py-6 text-center text-sm text-content-muted">
            {query ? (
              <>
                <p>No systems match &quot;{search.trim()}&quot;.</p>
                <button
                  type="button"
                  onClick={() => setSearch('')}
                  className="mt-2 text-sm text-link transition-colors hover:text-link-hover focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring rounded"
                >
                  Clear filter
                </button>
              </>
            ) : systems.length === 0 ? (
              'No systems available.'
            ) : (
              'All systems are selected.'
            )}
          </div>
        ) : (
          available.map((s) => (
            <button
              key={s.id}
              type="button"
              onClick={() => onToggle(s.id)}
              aria-label={`Add ${s.hostname}`}
              className="rounded-md border border-border bg-surface-sunken px-3 py-1.5 text-sm text-content-muted transition-colors hover:border-border-strong hover:text-content focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
            >
              {s.hostname}
            </button>
          ))
        )}
      </div>
    </div>
  );
};

export default SystemPicker;
