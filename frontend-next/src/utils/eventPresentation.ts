/**
 * PRA-350: one shared presentation mapping for activity/notification events.
 *
 * The bug this fixes: the Activity Feed and notification surfaces used raw,
 * page-local color maps that made every `source="notification"` item (and other
 * normal events) render in Signal Red, so a routine `package_scan_complete` read
 * like a critical alert. Red must mean operator attention, not "a notification
 * exists."
 *
 * This helper derives one semantic {@link BadgeVariant} from an event, checked in
 * priority order so the same concept maps identically everywhere:
 *   1. `type` / `event_type` — the most specific signal (e.g.
 *      `package_scan_complete` is success regardless of anything else).
 *   2. `severity` — the backend's `info` | `warning` | `error` fallback.
 *   3. `source` — category only; it NEVER implies red. Unknown → `neutral`.
 *
 * It is a pure function (no React, no I/O) so it is trivially unit-testable and
 * usable from the TopBar bell, the Alerts page, the Activity Feed, and the
 * Activity Sidebar alike.
 */
import type { BadgeVariant } from '@/components/ui/Badge';

export interface EventLike {
  /** notification `type` or activity-feed `event_type` (most specific). */
  type?: string | null;
  /** backend severity: `info` | `warning` | `error`. */
  severity?: string | null;
  /** activity-feed source category; used only as a last-resort fallback. */
  source?: string | null;
}

// Explicit event types the backend emits (see package_service / health_service /
// notification_service / job_service). Kept exhaustive for the events the
// acceptance calls out so they never fall through to a weaker signal.
const DANGER_TYPES = new Set([
  'package_scan_failure',
  'job_failed',
  'system_unreachable',
]);
const WARNING_TYPES = new Set(['job_cancelled']);
const SUCCESS_TYPES = new Set([
  'package_scan_complete',
  'job_completed',
  'system_recovered',
]);

// Heuristics for event types we don't enumerate, so a future
// `*_failed` / `*_recovered` still lands sensibly. Word boundaries keep e.g.
// `update` from matching `up`. Order matters: danger wins over success wins over
// warning.
const DANGER_RE =
  /(fail|error|critical|unreachable|offline|\bdown\b|denied|reject|breach|destroy|security)/;
const SUCCESS_RE =
  /(complete|success|succeeded|recovered|resolved|restored|online|healthy|passed)/;
const WARNING_RE = /(cancel|warn|degraded|pending|expir|stale|partial|paused)/;

function typeKeywordVariant(type: string): BadgeVariant | null {
  if (DANGER_RE.test(type)) return 'danger';
  if (SUCCESS_RE.test(type)) return 'success';
  if (WARNING_RE.test(type)) return 'warning';
  return null;
}

/**
 * Map an event to its semantic badge variant. `danger` is Signal Red and is
 * reserved for genuine operator attention (failures, host unreachable, errors).
 */
export function eventVariant(event: EventLike): BadgeVariant {
  const type = (event.type ?? '').toLowerCase().trim();
  if (type) {
    if (DANGER_TYPES.has(type)) return 'danger';
    if (WARNING_TYPES.has(type)) return 'warning';
    if (SUCCESS_TYPES.has(type)) return 'success';
    const kw = typeKeywordVariant(type);
    if (kw) return kw;
  }

  const severity = (event.severity ?? '').toLowerCase().trim();
  if (severity === 'error' || severity === 'critical') return 'danger';
  if (severity === 'warning' || severity === 'warn') return 'warning';
  if (severity === 'info') return 'info';

  // `source` is deliberately not mapped to a color — a notification is not an
  // alert by virtue of being a notification. Unknown events read as neutral.
  return 'neutral';
}

/** Text color class for a variant (theme-aware semantic tokens). */
export function eventTextClass(variant: BadgeVariant): string {
  switch (variant) {
    case 'success':
      return 'text-success';
    case 'warning':
      return 'text-warning';
    case 'danger':
      return 'text-danger';
    case 'info':
      return 'text-info';
    default:
      return 'text-content-muted';
  }
}

/** Dot/indicator background class for a variant. */
export function eventDotClass(variant: BadgeVariant): string {
  switch (variant) {
    case 'success':
      return 'bg-success';
    case 'warning':
      return 'bg-warning';
    case 'danger':
      return 'bg-danger';
    case 'info':
      return 'bg-info';
    default:
      return 'bg-content-muted';
  }
}

/** Card border + wash class for a variant (subtle; neutral stays quiet). */
export function eventCardClass(variant: BadgeVariant): string {
  switch (variant) {
    case 'success':
      return 'border-success/30 bg-success/5';
    case 'warning':
      return 'border-warning/30 bg-warning/5';
    case 'danger':
      return 'border-danger/40 bg-danger/5';
    case 'info':
      return 'border-info/30 bg-info/5';
    default:
      return 'border-border/60 bg-surface/40';
  }
}

/**
 * Short human label by variant, for surfaces that show a semantic tag instead of
 * a raw source name (e.g. the sidebar's per-item label). `danger` reads "Alert";
 * everything calmer reads as a notice/status, never "Alert".
 */
export function eventLabel(variant: BadgeVariant): string {
  switch (variant) {
    case 'success':
      return 'Resolved';
    case 'warning':
      return 'Warning';
    case 'danger':
      return 'Alert';
    case 'info':
      return 'Notice';
    default:
      return 'Notice';
  }
}
