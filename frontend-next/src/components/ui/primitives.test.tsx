// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

import Button from './Button';
import { StatusBadge } from './Badge';
import EmptyState from './EmptyState';
import { FormField } from './FormField';

afterEach(cleanup);

describe('Button', () => {
  it('renders each variant as a button', () => {
    const { rerender } = render(<Button variant="primary">Save</Button>);
    expect(screen.getByRole('button', { name: 'Save' })).toBeTruthy();
    for (const v of ['secondary', 'danger', 'ghost', 'link'] as const) {
      rerender(<Button variant={v}>Go</Button>);
      expect(screen.getByRole('button', { name: 'Go' })).toBeTruthy();
    }
  });

  it('is disabled while loading', () => {
    render(
      <Button variant="primary" loading>
        Submit
      </Button>,
    );
    expect(screen.getByRole('button')).toHaveProperty('disabled', true);
  });

  it('icon-only exposes an accessible name via aria-label', () => {
    render(<Button iconOnly aria-label="Delete" icon={<span>x</span>} />);
    expect(screen.getByRole('button', { name: 'Delete' })).toBeTruthy();
  });

  // PRA-357 action-hierarchy correction: non-danger create/update/add submits
  // were converted from raw Signal-Red submit buttons to `<Button variant="primary">`.
  // This locks the invariant those corrections depend on — `primary` is the neutral
  // action token, and Signal Red stays reserved for `danger`.
  it('keeps primary neutral and reserves Signal Red for danger', () => {
    const { rerender } = render(<Button variant="primary">Create Job</Button>);
    const primary = screen.getByRole('button', { name: 'Create Job' });
    expect(primary.className).toContain('bg-action');
    expect(primary.className).not.toMatch(/bg-(red|danger)/);

    rerender(<Button variant="danger">Delete</Button>);
    const danger = screen.getByRole('button', { name: 'Delete' });
    expect(danger.className).toContain('bg-danger');
  });
});

describe('StatusBadge', () => {
  it('humanizes the status label', () => {
    render(<StatusBadge status="in_progress" />);
    expect(screen.getByText('In progress')).toBeTruthy();
  });

  it('keeps acronyms and applies overrides', () => {
    const { rerender } = render(<StatusBadge status="not_enrolled" />);
    expect(screen.getByText('Not enrolled')).toBeTruthy();
    rerender(<StatusBadge status="auth_failed" />);
    expect(screen.getByText('Auth failed')).toBeTruthy();
  });
});

describe('EmptyState', () => {
  it('renders preset copy per variant', () => {
    const { rerender } = render(<EmptyState variant="no-results" />);
    expect(screen.getByText('No matches')).toBeTruthy();
    rerender(<EmptyState variant="restricted" />);
    expect(screen.getByText('Access restricted')).toBeTruthy();
    rerender(<EmptyState variant="locked" />);
    expect(screen.getByText('Not included in your plan')).toBeTruthy();
  });

  it('lets title/description override the preset', () => {
    render(<EmptyState variant="error" title="Custom title" description="Custom desc" />);
    expect(screen.getByText('Custom title')).toBeTruthy();
    expect(screen.getByText('Custom desc')).toBeTruthy();
  });
});

describe('FormField', () => {
  it('shows a required marker and error (error hides helper)', () => {
    render(
      <FormField label="Hostname" required helper="dns name" error="Required">
        <input />
      </FormField>,
    );
    expect(screen.getByText('Hostname')).toBeTruthy();
    expect(screen.getByText('*')).toBeTruthy();
    expect(screen.getByText('Required')).toBeTruthy();
    expect(screen.queryByText('dns name')).toBeNull(); // error suppresses helper
  });
});
