// @vitest-environment jsdom
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, waitFor, fireEvent, cleanup } from '@testing-library/react';

interface MockAuthState {
  current: {
    user: {
      id: number;
      username: string;
      email: string;
      is_active: boolean;
      roles: string[];
    } | null;
    loading: boolean;
  };
}

const authState = vi.hoisted(
  (): MockAuthState => ({
    current: {
      user: {
        id: 1,
        username: 'admin',
        email: 'admin@example.com',
        is_active: true,
        roles: ['admin'],
      },
      loading: false,
    },
  }),
);

vi.mock('./AuthContext', () => ({
  useAuth: () => authState.current,
}));

import {
  FormattedTimestamp,
  TimestampPreferencesProvider,
  useTimestampPreferences,
} from './TimestampPreferencesContext';

const UTC_INPUT = '2026-03-15T14:30:45Z';

function settingsResponse(dateFormat: string, timezone = 'UTC') {
  return {
    ok: true,
    json: async () => [
      { setting_key: 'timezone', setting_value: timezone },
      { setting_key: 'date_format', setting_value: dateFormat },
      { setting_key: 'time_format', setting_value: '24h' },
    ],
  } as Response;
}

const fetchMock = vi.fn();

beforeEach(() => {
  authState.current = {
    user: {
      id: 1,
      username: 'admin',
      email: 'admin@example.com',
      is_active: true,
      roles: ['admin'],
    },
    loading: false,
  };
  fetchMock.mockReset();
  vi.stubGlobal('fetch', fetchMock);
});
afterEach(() => {
  cleanup();
  vi.unstubAllGlobals();
});

describe('rendered timestamps update when settings load', () => {
  it('re-renders from the default format to the loaded format', async () => {
    // Loaded preference differs from the default (YYYY-MM-DD) so a change is
    // observable in the rendered output.
    fetchMock.mockResolvedValue(settingsResponse('MM/DD/YYYY'));

    render(
      <TimestampPreferencesProvider>
        <span data-testid="ts">
          <FormattedTimestamp value={UTC_INPUT} dateOnly />
        </span>
      </TimestampPreferencesProvider>,
    );

    // After the client effect resolves, the rendered date reflects the loaded
    // preference (MM/DD/YYYY), not the default.
    await waitFor(() => {
      expect(screen.getByTestId('ts').textContent).toBe('03/15/2026');
    });
    expect(fetchMock).toHaveBeenCalledWith('/api/backend/app-settings');
  });
});

describe('timestamp preferences wait for authentication', () => {
  it('does not fetch while logged out, then loads preferences after login', async () => {
    authState.current = { user: null, loading: false };
    fetchMock.mockResolvedValue(settingsResponse('MM/DD/YYYY'));

    const { rerender } = render(
      <TimestampPreferencesProvider>
        <span data-testid="ts">
          <FormattedTimestamp value={UTC_INPUT} dateOnly />
        </span>
      </TimestampPreferencesProvider>,
    );

    expect(screen.getByTestId('ts').textContent).toBe('2026-03-15');
    expect(fetchMock).not.toHaveBeenCalled();

    authState.current = {
      user: {
        id: 1,
        username: 'admin',
        email: 'admin@example.com',
        is_active: true,
        roles: ['admin'],
      },
      loading: false,
    };

    rerender(
      <TimestampPreferencesProvider>
        <span data-testid="ts">
          <FormattedTimestamp value={UTC_INPUT} dateOnly />
        </span>
      </TimestampPreferencesProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('ts').textContent).toBe('03/15/2026');
    });
    expect(fetchMock).toHaveBeenCalledWith('/api/backend/app-settings');
  });
});

describe('rendered timestamps update after a preference change (refresh)', () => {
  it('an already-rendered timestamp re-renders when refresh() reloads new prefs', async () => {
    fetchMock.mockResolvedValue(settingsResponse('MM/DD/YYYY'));

    function Harness() {
      const { refresh } = useTimestampPreferences();
      return (
        <>
          <span data-testid="ts">
            <FormattedTimestamp value={UTC_INPUT} dateOnly />
          </span>
          <button onClick={() => void refresh()}>refresh</button>
        </>
      );
    }

    render(
      <TimestampPreferencesProvider>
        <Harness />
      </TimestampPreferencesProvider>,
    );

    await waitFor(() => {
      expect(screen.getByTestId('ts').textContent).toBe('03/15/2026');
    });

    // Simulate saving a new preference: the next load returns a different format.
    fetchMock.mockResolvedValue(settingsResponse('DD.MM.YYYY'));
    fireEvent.click(screen.getByText('refresh'));

    await waitFor(() => {
      expect(screen.getByTestId('ts').textContent).toBe('15.03.2026');
    });
  });
});

describe('timezone preference drives Eastern rendering reactively', () => {
  it('re-renders a full timestamp into Eastern time when America/New_York loads', async () => {
    fetchMock.mockResolvedValue(settingsResponse('YYYY-MM-DD', 'America/New_York'));

    render(
      <TimestampPreferencesProvider>
        <span data-testid="ts">
          <FormattedTimestamp value={UTC_INPUT} />
        </span>
      </TimestampPreferencesProvider>,
    );

    // Initial SSR-safe default render is UTC; after the client effect loads the
    // preference it re-renders as EDT (2026-03-15 is US daylight time).
    expect(screen.getByTestId('ts').textContent).toBe('2026-03-15 14:30:45 UTC');
    await waitFor(() => {
      expect(screen.getByTestId('ts').textContent).toBe('2026-03-15 10:30:45 EDT');
    });
  });
});

describe('a bad stored timezone does not crash rendering', () => {
  it('renders UTC instead of throwing when the setting is EDT', async () => {
    fetchMock.mockResolvedValue(settingsResponse('YYYY-MM-DD', 'EDT'));

    render(
      <TimestampPreferencesProvider>
        <span data-testid="ts">
          <FormattedTimestamp value={UTC_INPUT} />
        </span>
      </TimestampPreferencesProvider>,
    );

    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    // Normalized to UTC in parseTimestampConfig — no RangeError, no blank screen.
    expect(screen.getByTestId('ts').textContent).toBe('2026-03-15 14:30:45 UTC');
  });
});

describe('failed settings fetch does not poison rendering', () => {
  it('keeps rendering with default config when the fetch fails', async () => {
    fetchMock.mockResolvedValue({ ok: false, status: 500 } as Response);

    render(
      <TimestampPreferencesProvider>
        <span data-testid="ts">
          <FormattedTimestamp value={UTC_INPUT} dateOnly />
        </span>
      </TimestampPreferencesProvider>,
    );

    // Default format survives a failed load — no crash, no poisoned cache.
    await waitFor(() => expect(fetchMock).toHaveBeenCalled());
    expect(screen.getByTestId('ts').textContent).toBe('2026-03-15');
  });
});
