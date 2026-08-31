// @vitest-environment jsdom
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest';

import {
  OnboardingError,
  buildDiscoveryConfirmation,
  confirmDiscovery,
  createDraft,
  fetchDraft,
  runDiscovery,
  saveAuthentication,
  saveConnection,
} from './onboardingService';

/**
 * The wizard branches on the backend's structured code, never on message text.
 * These pin that the code survives the transport layer intact, and that a
 * failure without one still produces something the UI can render.
 */
describe('PRA-414 onboarding service error handling', () => {
  const fetchMock = vi.fn();

  beforeEach(() => {
    vi.stubGlobal('fetch', fetchMock);
    fetchMock.mockReset();
  });

  afterEach(() => {
    vi.unstubAllGlobals();
  });

  const respond = (status: number, body: unknown) =>
    fetchMock.mockResolvedValue({
      ok: status < 400,
      status,
      json: async () => body,
    });

  it('preserves the structured code from a refused step', async () => {
    respond(409, {
      detail: { code: 'draft_expired', message: 'This setup expired.' },
    });

    await expect(fetchDraft('abc')).rejects.toMatchObject({
      code: 'draft_expired',
      message: 'This setup expired.',
    });
  });

  it('keeps the reason code and checks from an unavailable discovery', async () => {
    respond(409, {
      detail: {
        code: 'discovery_unavailable',
        message: 'The host refused the credential.',
        reason_code: 'authentication_failed',
        checks: [
          {
            check: 'authentication',
            status: 'fail',
            reason_code: 'authentication_failed',
            message: 'The host refused the credential.',
          },
        ],
      },
    });

    try {
      await runDiscovery('abc');
      throw new Error('should have rejected');
    } catch (err) {
      const error = err as OnboardingError;
      expect(error.code).toBe('discovery_unavailable');
      expect(error.reasonCode).toBe('authentication_failed');
      expect(error.checks?.[0].check).toBe('authentication');
    }
  });

  it('still yields a usable error when the body carries no code', async () => {
    respond(500, { detail: 'Internal Server Error' });

    await expect(createDraft()).rejects.toMatchObject({
      code: 'request_failed',
    });
  });

  it('sends the version it read so a stale write is refused server-side', async () => {
    respond(200, { draft: {} });
    await saveConnection(
      'abc',
      { address: '10.0.0.1', ssh_port: 22 },
      7,
    );
    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toContain('/drafts/abc/connect?state_version=7');
    expect(init.method).toBe('PUT');
    expect(JSON.parse(init.body)).toMatchObject({ address: '10.0.0.1', ssh_port: 22 });
  });

  it('never puts a secret in a draft write', async () => {
    respond(200, { draft: {} });
    await saveAuthentication('abc', { credential_id: 4 }, 1);
    const [, init] = fetchMock.mock.calls[0];
    const body = JSON.parse(init.body);
    // Only a reference travels; the secret stays in the secrets service.
    expect(body).toEqual({ credential_id: 4, ssh_security_policy_id: undefined });
    expect(JSON.stringify(body)).not.toMatch(/password|ssh_key|vault/i);
  });
});


/**
 * A managed host is serviced through its distribution, so binding it to a
 * supported release is the whole of the discover step. These pin the client
 * half of that: what a selection sends, and that no selection is not a request
 * at all rather than one the server has to refuse.
 */
describe('PRA-424 discovery confirmation request', () => {
  it('sends the chosen distro and never claims the host is unmapped', () => {
    expect(buildDiscoveryConfirmation('12')).toEqual({
      distro_id: 12,
      confirmed_unknown: false,
    });
  });

  it('cannot advance without a selection', () => {
    expect(buildDiscoveryConfirmation('')).toBeNull();
    expect(buildDiscoveryConfirmation('   ')).toBeNull();
  });

  it('cannot advance on a value that is not a distro id', () => {
    for (const value of ['0', '-3', '1.5', 'ubuntu', 'NaN']) {
      expect(buildDiscoveryConfirmation(value)).toBeNull();
    }
  });

  it('puts exactly that body on the wire', async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      status: 200,
      json: async () => ({ draft: {} }),
    });
    vi.stubGlobal('fetch', fetchMock);
    try {
      const body = buildDiscoveryConfirmation('12');
      expect(body).not.toBeNull();
      await confirmDiscovery('abc', body!, 4);

      const [url, init] = fetchMock.mock.calls[0];
      expect(url).toContain('/drafts/abc/discovery-confirmation?state_version=4');
      expect(init.method).toBe('PUT');
      expect(JSON.parse(init.body)).toEqual({
        distro_id: 12,
        confirmed_unknown: false,
      });
    } finally {
      vi.unstubAllGlobals();
    }
  });
});
