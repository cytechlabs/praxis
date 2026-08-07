// @vitest-environment jsdom
//
// PRA-347: Settings must not preserve or re-save an invalid durable timezone.
// A legacy DB value like `EDT` must be coerced to an allowed IANA ID on load so
// it can never be displayed or written back unchanged.
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';

const fetchAppSettings = vi.fn();
const updateAppSettings = vi.fn();
const refresh = vi.fn();

vi.mock('@/services/appSettingsService', () => ({
  fetchAppSettings: () => fetchAppSettings(),
  updateAppSettings: (settings: Record<string, string>) => updateAppSettings(settings),
}));

vi.mock('@/context/TimestampPreferencesContext', () => ({
  useTimestampPreferences: () => ({ refresh }),
}));

vi.mock('sonner', () => ({ toast: { success: vi.fn(), error: vi.fn() } }));

import GeneralSettingsTab from './GeneralSettingsTab';

function legacyEdtSettings() {
  return [
    { setting_key: 'app_name', setting_value: 'Praxis' },
    { setting_key: 'timezone', setting_value: 'EDT' },
    { setting_key: 'date_format', setting_value: 'YYYY-MM-DD' },
    { setting_key: 'time_format', setting_value: '24h' },
  ];
}

beforeEach(() => {
  fetchAppSettings.mockReset();
  updateAppSettings.mockReset();
  refresh.mockReset();
});
afterEach(() => cleanup());

function normalSettings() {
  return [
    { setting_key: 'app_name', setting_value: 'Praxis' },
    { setting_key: 'timezone', setting_value: 'UTC' },
    { setting_key: 'date_format', setting_value: 'YYYY-MM-DD' },
    { setting_key: 'time_format', setting_value: '24h' },
  ];
}

describe('GeneralSettingsTab timezone selector', () => {
  it('renders the timezone control as a single-select combobox, not an always-open listbox', async () => {
    fetchAppSettings.mockResolvedValue(normalSettings());

    render(<GeneralSettingsTab />);

    // PRA-276: normal dropdown (combobox), never a permanently-open listbox.
    const select = (await screen.findByRole('combobox', { name: 'Timezone' })) as HTMLSelectElement;
    expect(select.value).toBe('UTC');
    expect(select.hasAttribute('size')).toBe(false);
    expect(screen.queryByRole('listbox')).toBeNull();
  });

  it('coerces a legacy EDT stored timezone to UTC on load', async () => {
    fetchAppSettings.mockResolvedValue(legacyEdtSettings());

    render(<GeneralSettingsTab />);

    // The timezone control's bound value is the normalized IANA ID, never the
    // raw `EDT` that came from the DB (PRA-347 correctness preserved).
    const select = (await screen.findByRole('combobox', { name: 'Timezone' })) as HTMLSelectElement;
    expect(select.value).toBe('UTC');
  });

  it('persists the normalized timezone, never the legacy EDT value', async () => {
    fetchAppSettings.mockResolvedValue(legacyEdtSettings());
    updateAppSettings.mockResolvedValue([]);

    render(<GeneralSettingsTab />);

    // Wait for load-normalization to land.
    const select = (await screen.findByRole('combobox', { name: 'Timezone' })) as HTMLSelectElement;
    expect(select.value).toBe('UTC');

    // Edit an unrelated field to enable Save, then save.
    fireEvent.change(screen.getByDisplayValue('Praxis'), {
      target: { value: 'Praxis 2' },
    });
    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => expect(updateAppSettings).toHaveBeenCalledTimes(1));
    const payload = updateAppSettings.mock.calls[0][0] as Record<string, string>;
    expect(payload.timezone).toBe('UTC');
    expect(payload.app_name).toBe('Praxis 2');
    expect(refresh).toHaveBeenCalled();
  });

  it('persists a newly selected valid IANA timezone', async () => {
    fetchAppSettings.mockResolvedValue(normalSettings());
    updateAppSettings.mockResolvedValue([]);

    render(<GeneralSettingsTab />);

    const select = (await screen.findByRole('combobox', { name: 'Timezone' })) as HTMLSelectElement;
    fireEvent.change(select, { target: { value: 'America/New_York' } });
    expect(select.value).toBe('America/New_York');

    fireEvent.click(screen.getByText('Save Changes'));

    await waitFor(() => expect(updateAppSettings).toHaveBeenCalledTimes(1));
    const payload = updateAppSettings.mock.calls[0][0] as Record<string, string>;
    expect(payload.timezone).toBe('America/New_York');
    expect(refresh).toHaveBeenCalled();
  });
});
