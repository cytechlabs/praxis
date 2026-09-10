// @vitest-environment jsdom
import React from 'react';
import { describe, it, expect, vi, beforeEach, afterEach } from 'vitest';
import { render, screen, fireEvent, cleanup, waitFor, within } from '@testing-library/react';
import SSHSecurityPage from '@/pages/ssh-security';
import { apiFetch } from '@/utils/api';

// Page chrome that plays no part in what the create form submits.
vi.mock('next/head', () => ({ default: () => null }));
vi.mock('next/router', () => ({ useRouter: () => ({ push: vi.fn() }) }));
vi.mock('@/components/MainLayout', () => ({
  default: ({ children }: { children: React.ReactNode }) => <div>{children}</div>,
}));
vi.mock('@/components/help/HelpLink', () => ({ default: () => null }));
vi.mock('@/context/AuthContext', () => ({
  useAuth: () => ({ user: { id: 1, username: 'admin' }, loading: false }),
}));
vi.mock('@/context/TimestampPreferencesContext', () => ({
  useFormatTimestamp: () => (value: string) => value,
}));
vi.mock('@/utils/api', () => ({
  apiFetch: vi.fn(),
  formatApiError: (_body: unknown, fallback: string) => fallback,
}));

const mockApiFetch = vi.mocked(apiFetch);

const existingPolicy = {
  id: 7,
  name: 'Default',
  description: 'Seeded default policy.',
  max_auth_tries: 3,
  connection_timeout: 10,
  idle_timeout: 600,
  require_host_key_verification: true,
  minimum_key_size: 2048,
  allowed_auth_methods: 'publickey,password',
  allowed_ciphers: 'aes256-ctr,aes192-ctr,aes128-ctr',
  allowed_macs: 'hmac-sha2-512,hmac-sha2-256',
  allowed_kex: '',
  log_commands: true,
  log_file_transfers: true,
  created_by: 1,
};

const jsonResponse = (body: unknown) =>
  ({ ok: true, json: () => Promise.resolve(body) }) as unknown as Response;

/** The JSON bodies of every POST the page made to the policy collection. */
const postedPolicies = () =>
  mockApiFetch.mock.calls
    .filter(([, init]) => init?.method === 'POST')
    .map(([, init]) => JSON.parse(String(init?.body)));

async function openCreateForm(): Promise<HTMLElement> {
  // The header button and the modal submit share a label; the modal is not
  // mounted until the header button is pressed, so the first match is it.
  const [openButton] = await screen.findAllByText('Create Policy');
  fireEvent.click(openButton);
  const heading = await screen.findByText('Create SSH Security Policy');
  return heading.parentElement as HTMLElement;
}

/** The form's text fields, in document order; the first one is the name. */
const textFields = (modal: HTMLElement) =>
  within(modal).getAllByRole('textbox') as HTMLInputElement[];

function submitCreateForm() {
  const buttons = screen.getAllByText('Create Policy');
  fireEvent.click(buttons[buttons.length - 1]);
}

describe('SSH security policy creation defaults', () => {
  beforeEach(() => {
    mockApiFetch.mockReset();
    mockApiFetch.mockImplementation((_url, init) => {
      if (init?.method === 'POST') {
        return Promise.resolve(jsonResponse({ ...existingPolicy, id: 8, name: 'created' }));
      }
      return Promise.resolve(jsonResponse({ policies: [existingPolicy], total: 1 }));
    });
  });

  afterEach(() => {
    cleanup();
  });

  it('submits an unconstrained key exchange and the modern cipher and MAC lists', async () => {
    render(<SSHSecurityPage />);
    const modal = await openCreateForm();

    fireEvent.change(textFields(modal)[0], { target: { value: 'praxis-427-ui' } });
    submitCreateForm();

    await waitFor(() => expect(postedPolicies()).toHaveLength(1));
    const [body] = postedPolicies();
    expect(body.name).toBe('praxis-427-ui');
    expect(body.allowed_kex).toBe('');
    expect(body.allowed_ciphers).toBe('aes256-ctr,aes192-ctr,aes128-ctr');
    expect(body.allowed_macs).toBe('hmac-sha2-512,hmac-sha2-256');
    expect(body.require_host_key_verification).toBe(true);
  });

  it('resets to the same defaults after a successful create', async () => {
    render(<SSHSecurityPage />);
    const first = await openCreateForm();
    fireEvent.change(textFields(first)[0], { target: { value: 'first' } });
    fireEvent.change(textFields(first)[1], { target: { value: 'a description' } });
    submitCreateForm();
    await waitFor(() => expect(postedPolicies()).toHaveLength(1));
    await waitFor(() =>
      expect(screen.queryByText('Create SSH Security Policy')).toBeNull()
    );

    // The form is empty again, and what it submits untouched is the default.
    const reopened = await openCreateForm();
    for (const field of textFields(reopened)) {
      expect(field.value).toBe('');
    }
    submitCreateForm();

    await waitFor(() => expect(postedPolicies()).toHaveLength(2));
    const [, second] = postedPolicies();
    expect(second.name).toBe('');
    expect(second.allowed_kex).toBe('');
    expect(second.allowed_ciphers).toBe('aes256-ctr,aes192-ctr,aes128-ctr');
    expect(second.allowed_macs).toBe('hmac-sha2-512,hmac-sha2-256');
  });

  it('never sends the legacy default key exchange pin', async () => {
    render(<SSHSecurityPage />);
    await openCreateForm();
    submitCreateForm();

    await waitFor(() => expect(postedPolicies()).toHaveLength(1));
    expect(JSON.stringify(postedPolicies()[0])).not.toContain('diffie-hellman');
  });
});
