// @vitest-environment jsdom
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

import { Select, nativeSelectClass } from './Input';

afterEach(cleanup);

/**
 * The shared native select primitive. These lock the contrast contract the
 * expanded option list depends on, and the form/accessibility behavior that
 * adopting the contract must not disturb.
 */
describe('Select', () => {
  it('pins an opaque surface and explicit option colors on the control', () => {
    render(
      <Select label="Target System" defaultValue="web-01">
        <option value="web-01">web-01</option>
      </Select>,
    );
    const select = screen.getByRole('combobox', { name: 'Target System' });

    // The control itself resolves to a semantic surface/content pair...
    expect(select.className).toContain('bg-surface-sunken');
    expect(select.className).toContain('text-content');

    // ...and so do the option/optgroup children, so the browser-painted list
    // cannot fall back to its own default surface.
    expect(select.className).toContain('[&_option]:bg-surface-sunken');
    expect(select.className).toContain('[&_option]:text-content');
    expect(select.className).toContain('[&_optgroup]:bg-surface-sunken');
  });

  it('never carries a translucent or theme-blind background', () => {
    render(<Select label="Severity" />);
    const select = screen.getByRole('combobox', { name: 'Severity' });
    // A translucent background is composited against the browser's own popup
    // surface, which is what made option text unreadable.
    expect(select.className).not.toMatch(/bg-(black|white)\b/);
    expect(select.className).not.toMatch(/bg-praxis-/);
    expect(select.className).not.toMatch(/bg-surface-sunken\/\d/);
  });

  it('keeps a visible keyboard focus ring', () => {
    render(<Select label="Source" />);
    const select = screen.getByRole('combobox', { name: 'Source' });
    expect(select.className).toContain('focus-visible:ring-2');
    expect(select.className).toContain('focus-visible:ring-focusring');
  });

  it('associates the label with the control and generates an id when absent', () => {
    render(<Select label="Distro family" />);
    const select = screen.getByRole('combobox', { name: 'Distro family' });
    expect(select.id).toBeTruthy();
    const label = document.querySelector('label');
    expect(label?.getAttribute('for')).toBe(select.id);
  });

  it('honours a caller-supplied id instead of generating one', () => {
    render(<Select label="Class" id="advisory-class" />);
    expect(screen.getByRole('combobox', { name: 'Class' }).id).toBe('advisory-class');
  });

  it('renders options and reflects the selected value', () => {
    render(
      <Select label="Package family" defaultValue="rpm">
        <option value="deb">deb (apt)</option>
        <option value="rpm">rpm (yum/dnf)</option>
      </Select>,
    );
    const select = screen.getByRole('combobox', { name: 'Package family' }) as HTMLSelectElement;
    expect(select.value).toBe('rpm');
    expect(screen.getAllByRole('option')).toHaveLength(2);
  });

  it('preserves disabled and name so form submission behavior is unchanged', () => {
    render(
      <Select label="Source mode" name="source_mode" disabled>
        <option value="upstream_sync">upstream_sync</option>
      </Select>,
    );
    const select = screen.getByRole('combobox', { name: 'Source mode' }) as HTMLSelectElement;
    expect(select.disabled).toBe(true);
    expect(select.name).toBe('source_mode');
    expect(select.className).toContain('disabled:opacity-60');
  });

  it('appends caller classes after the shared contract', () => {
    render(<Select label="Scope" className="w-40" />);
    const select = screen.getByRole('combobox', { name: 'Scope' });
    expect(select.className).toContain('w-40');
    expect(select.className).toContain(nativeSelectClass.split(' ')[0]);
  });
});
