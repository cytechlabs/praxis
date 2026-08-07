import React from 'react';
import EmptyState from './EmptyState';
import { SkeletonTable } from './Skeleton';

/**
 * PRA-269: shared operator DataTable.
 *
 * Consolidates the ~59 hand-rolled `<table>`s so list pages share one compact,
 * scannable, token-driven surface with consistent density, sticky header,
 * selection, row actions, empty state, and EXPLICIT horizontal overflow at a
 * supported minimum width (never squish columns - scroll instead).
 *
 * Search/filters live in the `toolbar` slot (compose SearchInput/Select) so each
 * page keeps its own filter logic; DataTable owns layout + states only.
 */

export interface Column<T> {
  key: string;
  header: React.ReactNode;
  /** Cell content; defaults to `String(row[key])`. */
  render?: (row: T) => React.ReactNode;
  align?: 'left' | 'right' | 'center';
  /** Tailwind width/whitespace hint for the column, e.g. 'w-40' or 'whitespace-nowrap'. */
  className?: string;
  headerClassName?: string;
}

export interface DataTablePagination {
  page: number; // 1-indexed
  pageSize: number;
  total: number;
  onPageChange: (page: number) => void;
}

interface DataTableProps<T> {
  columns: Column<T>[];
  rows: T[];
  rowKey: (row: T) => string | number;
  density?: 'compact' | 'normal';
  loading?: boolean;
  /** Rendered when there are no rows (and not loading). Defaults to a neutral EmptyState. */
  empty?: React.ReactNode;
  onRowClick?: (row: T) => void;
  /** Right-aligned per-row actions column. */
  rowActions?: (row: T) => React.ReactNode;
  selectable?: boolean;
  selectedKeys?: Set<string | number>;
  onSelectionChange?: (keys: Set<string | number>) => void;
  /** Filters/search slot rendered above the table. */
  toolbar?: React.ReactNode;
  /** Min width so columns scroll (overflow-x) instead of squishing on desktop. */
  minWidth?: string;
  stickyHeader?: boolean;
  /** Accessible table caption (visually hidden). */
  caption?: string;
  pagination?: DataTablePagination;
  className?: string;
}

const alignClass = (a?: 'left' | 'right' | 'center') =>
  a === 'right' ? 'text-right' : a === 'center' ? 'text-center' : 'text-left';

export function DataTable<T>({
  columns,
  rows,
  rowKey,
  density = 'normal',
  loading,
  empty,
  onRowClick,
  rowActions,
  selectable,
  selectedKeys,
  onSelectionChange,
  toolbar,
  minWidth,
  stickyHeader = true,
  caption,
  pagination,
  className = '',
}: DataTableProps<T>) {
  const cellPad = density === 'compact' ? 'px-3 py-1.5 text-xs' : 'px-4 py-2.5 text-sm';
  const headPad = density === 'compact' ? 'px-3 py-2' : 'px-4 py-2.5';

  const selected = selectedKeys ?? new Set<string | number>();
  const allSelected = rows.length > 0 && rows.every((r) => selected.has(rowKey(r)));
  const someSelected = rows.some((r) => selected.has(rowKey(r)));

  const toggleAll = () => {
    if (!onSelectionChange) return;
    onSelectionChange(allSelected ? new Set() : new Set(rows.map(rowKey)));
  };
  const toggleRow = (k: string | number) => {
    if (!onSelectionChange) return;
    const next = new Set(selected);
    if (next.has(k)) next.delete(k);
    else next.add(k);
    onSelectionChange(next);
  };

  const colCount = columns.length + (selectable ? 1 : 0) + (rowActions ? 1 : 0);

  return (
    <div className={`space-y-3 ${className}`}>
      {toolbar && <div className="flex flex-wrap items-center gap-2">{toolbar}</div>}

      <div className="bg-surface-raised border border-border rounded-lg overflow-hidden">
        <div className="overflow-x-auto">
          <table className={`w-full border-collapse ${minWidth ?? ''}`}>
            {caption && <caption className="sr-only">{caption}</caption>}
            <thead className={stickyHeader ? 'sticky top-0 z-10 bg-surface-raised' : 'bg-surface-raised'}>
              <tr className="border-b border-border">
                {selectable && (
                  <th scope="col" className={`${headPad} w-10`}>
                    <input
                      type="checkbox"
                      aria-label="Select all rows"
                      checked={allSelected}
                      ref={(el) => {
                        if (el) el.indeterminate = !allSelected && someSelected;
                      }}
                      onChange={toggleAll}
                      className="align-middle"
                    />
                  </th>
                )}
                {columns.map((col) => (
                  <th
                    key={col.key}
                    scope="col"
                    className={`${headPad} text-xs font-medium uppercase tracking-wider text-content-muted ${alignClass(
                      col.align,
                    )} ${col.headerClassName ?? ''}`}
                  >
                    {col.header}
                  </th>
                ))}
                {rowActions && <th scope="col" className={`${headPad} text-right w-px`}>&nbsp;</th>}
              </tr>
            </thead>
            <tbody>
              {loading ? (
                <tr>
                  <td colSpan={colCount}>
                    <SkeletonTable rows={5} cols={Math.max(columns.length, 3)} />
                  </td>
                </tr>
              ) : rows.length === 0 ? (
                <tr>
                  <td colSpan={colCount} className="p-0">
                    {empty ?? <EmptyState variant="no-results" />}
                  </td>
                </tr>
              ) : (
                rows.map((row) => {
                  const k = rowKey(row);
                  const clickable = !!onRowClick;
                  return (
                    <tr
                      key={k}
                      className={`border-b border-border last:border-b-0 hover:bg-surface-overlay/40 ${
                        clickable ? 'cursor-pointer' : ''
                      } ${selected.has(k) ? 'bg-surface-overlay/30' : ''}`}
                      onClick={clickable ? () => onRowClick!(row) : undefined}
                      tabIndex={clickable ? 0 : undefined}
                      onKeyDown={
                        clickable
                          ? (e) => {
                              if (e.key === 'Enter' || e.key === ' ') {
                                e.preventDefault();
                                onRowClick!(row);
                              }
                            }
                          : undefined
                      }
                    >
                      {selectable && (
                        <td className={`${cellPad} w-10`} onClick={(e) => e.stopPropagation()}>
                          <input
                            type="checkbox"
                            aria-label="Select row"
                            checked={selected.has(k)}
                            onChange={() => toggleRow(k)}
                            className="align-middle"
                          />
                        </td>
                      )}
                      {columns.map((col) => (
                        <td
                          key={col.key}
                          className={`${cellPad} text-content ${alignClass(col.align)} ${col.className ?? ''}`}
                        >
                          {col.render ? col.render(row) : String((row as Record<string, unknown>)[col.key] ?? '')}
                        </td>
                      ))}
                      {rowActions && (
                        <td className={`${cellPad} text-right whitespace-nowrap`} onClick={(e) => e.stopPropagation()}>
                          {rowActions(row)}
                        </td>
                      )}
                    </tr>
                  );
                })
              )}
            </tbody>
          </table>
        </div>

        {pagination && rows.length > 0 && <PaginationFooter density={density} {...pagination} />}
      </div>
    </div>
  );
}

const PaginationFooter: React.FC<DataTablePagination & { density: 'compact' | 'normal' }> = ({
  page,
  pageSize,
  total,
  onPageChange,
  density,
}) => {
  const totalPages = Math.max(1, Math.ceil(total / pageSize));
  const from = total === 0 ? 0 : (page - 1) * pageSize + 1;
  const to = Math.min(page * pageSize, total);
  const pad = density === 'compact' ? 'px-3 py-1.5' : 'px-4 py-2';
  return (
    <div className={`flex items-center justify-between border-t border-border text-xs text-content-subtle ${pad}`}>
      <span>
        {from}–{to} of {total}
      </span>
      <div className="flex items-center gap-1">
        <button
          type="button"
          onClick={() => onPageChange(page - 1)}
          disabled={page <= 1}
          className="px-2 py-1 rounded border border-border text-content-muted hover:border-border-strong disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
        >
          Prev
        </button>
        <span className="px-1">
          {page} / {totalPages}
        </span>
        <button
          type="button"
          onClick={() => onPageChange(page + 1)}
          disabled={page >= totalPages}
          className="px-2 py-1 rounded border border-border text-content-muted hover:border-border-strong disabled:opacity-40 disabled:cursor-not-allowed focus:outline-none focus-visible:ring-2 focus-visible:ring-focusring"
        >
          Next
        </button>
      </div>
    </div>
  );
};

export default DataTable;
