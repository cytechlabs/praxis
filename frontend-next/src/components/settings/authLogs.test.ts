import { describe, it, expect, vi, beforeEach } from 'vitest';

import type { AuditEvent } from '../../services/auditService';

// Mock the audit service so fetchAuthLogRows is exercised without real HTTP.
vi.mock('../../services/auditService', () => ({
  listAuditEvents: vi.fn(),
}));

import { listAuditEvents } from '../../services/auditService';
import {
  AUTH_LOG_FETCH_LIMIT,
  MAX_CONSECUTIVE_FAILURES,
  actorLabel,
  fetchAuthLogRows,
  isAuthRelevant,
  outcomeVariant,
  shouldKeepPolling,
  toAuthLogRows,
} from './authLogs';

const mockList = vi.mocked(listAuditEvents);

function ev(partial: Partial<AuditEvent>): AuditEvent {
  return {
    schema_version: 1,
    event_uuid: partial.event_uuid ?? 'uuid-1',
    timestamp: partial.timestamp ?? '2026-08-01T00:00:00Z',
    action: partial.action ?? 'session.open',
    outcome: partial.outcome ?? 'success',
    actor: partial.actor ?? { user_id: 1, username: 'alice', ip: '10.0.0.1' },
    target: partial.target ?? { kind: null, system_id: null, id: null },
    context: partial.context ?? {},
  };
}

beforeEach(() => {
  mockList.mockReset();
});

describe('isAuthRelevant', () => {
  it('accepts auth/access/identity action families', () => {
    for (const a of [
      'session.open',
      'access_request.approve',
      'review.create',
      'revocation.request',
      'binding.create',
      'totp.step_up',
      'ssh.user_cert.sign',
      'activation_token.redeem',
      'fleet.effective_access.viewed',
    ]) {
      expect(isAuthRelevant(a)).toBe(true);
    }
  });

  it('rejects non-auth actions (content/patch/license/etc.)', () => {
    for (const a of [
      'content_profile.created',
      'license.applied',
      'host_facts.ingest',
      'command.exec',
      'support.bundle.generated',
      'airgap_import.ok',
    ]) {
      expect(isAuthRelevant(a)).toBe(false);
    }
  });
});

describe('actorLabel', () => {
  it('prefers username, then user id, then system', () => {
    expect(actorLabel({ user_id: 1, username: 'bob', ip: null })).toBe('bob');
    expect(actorLabel({ user_id: 7, username: null, ip: null })).toBe('user #7');
    expect(actorLabel({ user_id: null, username: null, ip: null })).toBe('system');
  });
});

describe('outcomeVariant', () => {
  it('maps outcomes to badge variants', () => {
    expect(outcomeVariant('success')).toBe('success');
    expect(outcomeVariant('denied')).toBe('warning');
    expect(outcomeVariant('failure')).toBe('danger');
  });
});

describe('toAuthLogRows', () => {
  it('filters to auth-relevant events and maps the row shape', () => {
    const rows = toAuthLogRows([
      ev({ event_uuid: 'a', action: 'session.open' }),
      ev({ event_uuid: 'b', action: 'content_profile.created' }), // dropped
      ev({
        event_uuid: 'c',
        action: 'access_request.reject',
        outcome: 'denied',
        actor: { user_id: 9, username: null, ip: null },
      }),
    ]);
    expect(rows.map((r) => r.key)).toEqual(['a', 'c']);
    expect(rows[0].action).toBe('session.open');
    expect(rows[0].actor).toBe('alice');
    expect(rows[1].actor).toBe('user #9');
    expect(rows[1].outcome).toBe('denied');
    // Details is pretty JSON containing actor/target/context.
    expect(rows[0].details).toContain('"actor"');
    expect(rows[0].details).toContain('"context"');
  });
});

describe('shouldKeepPolling', () => {
  it('keeps polling below the failure cap and stops at/after it', () => {
    expect(shouldKeepPolling(0)).toBe(true);
    expect(shouldKeepPolling(MAX_CONSECUTIVE_FAILURES - 1)).toBe(true);
    expect(shouldKeepPolling(MAX_CONSECUTIVE_FAILURES)).toBe(false);
    expect(shouldKeepPolling(MAX_CONSECUTIVE_FAILURES + 5)).toBe(false);
  });
});

describe('fetchAuthLogRows', () => {
  it('returns mapped auth rows on a successful response', async () => {
    mockList.mockResolvedValue({
      total: 2,
      events: [
        ev({ event_uuid: 'a', action: 'session.open' }),
        ev({ event_uuid: 'b', action: 'license.applied' }), // filtered out
      ],
    });
    const rows = await fetchAuthLogRows();
    expect(mockList).toHaveBeenCalledWith({ limit: AUTH_LOG_FETCH_LIMIT });
    expect(rows.map((r) => r.key)).toEqual(['a']);
  });

  it('propagates the error on a failed response', async () => {
    mockList.mockRejectedValue(new Error('fetch events failed'));
    await expect(fetchAuthLogRows()).rejects.toThrow('fetch events failed');
  });
});
