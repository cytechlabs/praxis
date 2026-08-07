// @vitest-environment jsdom
import { describe, it, expect, vi, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, within } from '@testing-library/react';

import DataTable, { type Column } from './DataTable';

interface Row {
  id: number;
  name: string;
  status: string;
}

const rows: Row[] = [
  { id: 1, name: 'alpha', status: 'active' },
  { id: 2, name: 'bravo', status: 'failed' },
];

const columns: Column<Row>[] = [
  { key: 'name', header: 'Name' },
  { key: 'status', header: 'Status', render: (r) => `S:${r.status}` },
];

afterEach(cleanup);

describe('DataTable', () => {
  it('renders headers and rows (default + custom render)', () => {
    render(<DataTable columns={columns} rows={rows} rowKey={(r) => r.id} />);
    expect(screen.getByText('Name')).toBeTruthy();
    expect(screen.getByText('alpha')).toBeTruthy();
    expect(screen.getByText('S:active')).toBeTruthy(); // custom render used
  });

  it('shows the empty state when there are no rows', () => {
    render(<DataTable columns={columns} rows={[]} rowKey={(r) => r.id} />);
    expect(screen.getByText('No matches')).toBeTruthy(); // no-results preset
  });

  it('fires row actions without triggering row click', () => {
    const onRowClick = vi.fn();
    const onAction = vi.fn();
    render(
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        onRowClick={onRowClick}
        rowActions={(r) => (
          <button onClick={() => onAction(r.id)}>act-{r.id}</button>
        )}
      />,
    );
    fireEvent.click(screen.getByText('act-1'));
    expect(onAction).toHaveBeenCalledWith(1);
    expect(onRowClick).not.toHaveBeenCalled(); // stopPropagation on the actions cell
  });

  it('supports select-all and per-row selection', () => {
    const onChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        selectable
        selectedKeys={new Set()}
        onSelectionChange={onChange}
      />,
    );
    fireEvent.click(screen.getByLabelText('Select all rows'));
    expect(onChange).toHaveBeenCalledWith(new Set([1, 2]));

    onChange.mockClear();
    fireEvent.click(screen.getAllByLabelText('Select row')[1]);
    expect(onChange).toHaveBeenCalledWith(new Set([2]));
  });

  it('renders a pagination footer and pages', () => {
    const onPageChange = vi.fn();
    render(
      <DataTable
        columns={columns}
        rows={rows}
        rowKey={(r) => r.id}
        pagination={{ page: 2, pageSize: 2, total: 6, onPageChange }}
      />,
    );
    expect(screen.getByText('3–4 of 6')).toBeTruthy();
    fireEvent.click(screen.getByText('Next'));
    expect(onPageChange).toHaveBeenCalledWith(3);
    fireEvent.click(screen.getByText('Prev'));
    expect(onPageChange).toHaveBeenCalledWith(1);
  });

  it('activates a clickable row via keyboard (Enter)', () => {
    const onRowClick = vi.fn();
    render(
      <DataTable columns={columns} rows={rows} rowKey={(r) => r.id} onRowClick={onRowClick} />,
    );
    const firstRow = screen.getByText('alpha').closest('tr')!;
    fireEvent.keyDown(within(firstRow).getByText('alpha'), { key: 'Enter' });
    // keydown handler is on the row; dispatch on the row itself:
    fireEvent.keyDown(firstRow, { key: 'Enter' });
    expect(onRowClick).toHaveBeenCalled();
  });
});
