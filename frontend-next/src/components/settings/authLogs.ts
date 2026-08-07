/**
 * PRA-257: Settings → Auth Logs data logic.
 *
 * The old tab fetched an unauthenticated Next endpoint (`/api/logs/auth`) backed
 * by a server-side file logger that was never written to, and polled it every
 * 10s forever. This module replaces that with the real, admin/auditor-gated
 * audit stream (`GET /api/backend/audit/events` via apiFetch) and keeps the
 * mapping/filter/polling decisions as pure, unit-testable functions.
 *
 * Honesty note: Praxis does NOT persist discrete login/logout/auth-failure
 * events as AuditEvent rows today. Rather than invent file-backed "auth logs",
 * this surfaces the access & identity events that ARE recorded - the auth-
 * relevant subset of the unified audit stream.
 */

import {
  listAuditEvents,
  type AuditEvent,
  type EventListParams,
} from '../../services/auditService';

type BadgeVariant = 'success' | 'warning' | 'danger' | 'info' | 'neutral' | 'orange';

export interface AuthLogRow {
  /** event_uuid - stable React key. */
  key: string;
  timestamp: string | null;
  action: string;
  actor: string;
  outcome: AuditEvent['outcome'];
  /** Pretty-printed actor/target/context for the details drawer. */
  details: string;
}

/**
 * Action prefixes that are authentication / access / identity relevant. These
 * are the dotted-action families actually emitted as AuditEvent rows (verified
 * against the backend emit sites). Login/logout are intentionally absent - they
 * are not audited today, so we do not fabricate them.
 */
export const AUTH_ACTION_PREFIXES = [
  'session.', // interactive access sessions (open/close/moderation)
  'access_request.', // access request lifecycle
  'review.', // access reviews
  'revocation.', // access revocation
  'binding.', // role bindings
  'totp.', // MFA step-up
  'ssh.user_cert.', // per-login SSH certificate issuance
  'activation_token.', // agent enrollment tokens
  'fleet.effective_access.', // effective-access views
] as const;

export function isAuthRelevant(action: string): boolean {
  return AUTH_ACTION_PREFIXES.some((p) => action.startsWith(p));
}

export function actorLabel(actor: AuditEvent['actor']): string {
  if (actor?.username) return actor.username;
  if (actor?.user_id != null) return `user #${actor.user_id}`;
  return 'system';
}

export function outcomeVariant(outcome: AuditEvent['outcome']): BadgeVariant {
  if (outcome === 'success') return 'success';
  if (outcome === 'denied') return 'warning';
  return 'danger'; // failure
}

export function toAuthLogRow(ev: AuditEvent): AuthLogRow {
  return {
    key: ev.event_uuid,
    timestamp: ev.timestamp,
    action: ev.action,
    actor: actorLabel(ev.actor),
    outcome: ev.outcome,
    details: JSON.stringify(
      { actor: ev.actor, target: ev.target, context: ev.context },
      null,
      2,
    ),
  };
}

/** Map + filter a page of audit events down to the auth-relevant rows. */
export function toAuthLogRows(events: AuditEvent[]): AuthLogRow[] {
  return events.filter((e) => isAuthRelevant(e.action)).map(toAuthLogRow);
}

// ---- polling policy ----

/** Stop auto-refresh after this many consecutive failures; a success resets. */
export const MAX_CONSECUTIVE_FAILURES = 3;

/** Auto-refresh cadence (ms). */
export const POLL_INTERVAL_MS = 15000;

export function shouldKeepPolling(
  consecutiveFailures: number,
  maxFailures: number = MAX_CONSECUTIVE_FAILURES,
): boolean {
  return consecutiveFailures < maxFailures;
}

// ---- fetch orchestration ----

/** How many recent audit events to pull per refresh before filtering. */
export const AUTH_LOG_FETCH_LIMIT = 200;

/**
 * Fetch the most recent audit events (admin/auditor-gated, via apiFetch) and
 * return the auth-relevant rows. Throws on a failed response so the caller can
 * drive the bounded-polling failure path.
 */
export async function fetchAuthLogRows(
  params: EventListParams = {},
): Promise<AuthLogRow[]> {
  const { events } = await listAuditEvents({
    limit: AUTH_LOG_FETCH_LIMIT,
    ...params,
  });
  return toAuthLogRows(events);
}
