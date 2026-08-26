import type { ApplyUpdatesResult, RebootEvidence } from '@/services/packageService';

/**
 * How a reboot observation should be reported to the operator who just ran
 * a package update.
 *
 * `required` and `notRequired` are answers the host gave. `unknown` is the
 * absence of an answer, and is deliberately not folded into `notRequired`:
 * a host that could not be asked is not a host that said no.
 */
export type RebootStatusTone = 'required' | 'notRequired' | 'unknown';

export interface RebootStatusNotice {
  tone: RebootStatusTone;
  message: string;
}

/** Probe outcomes worded for an operator who has to act on them. */
const OUTCOME_REASONS: Record<string, string> = {
  unsupported:
    'the host has no supported reboot-required indicator (RPM hosts need dnf-utils or yum-utils installed)',
  timeout: 'the check timed out',
  transport_error: 'the host could not be reached',
  malformed_output: 'the host returned output that could not be read',
  probe_failed: 'the check failed to run',
  not_collected: 'no check was run',
};

function reasonFor(evidence: RebootEvidence): string {
  return OUTCOME_REASONS[evidence.outcome] ?? 'the check did not return an answer';
}

/**
 * Describe the reboot state of a host after a successful package update, or
 * return null when there is nothing to report.
 *
 * Returns null when no observation was taken, which is the case when the
 * update changed nothing. Reporting "unknown" there would invent a problem
 * out of a no-op.
 */
export function rebootStatusNotice(result: ApplyUpdatesResult): RebootStatusNotice | null {
  const evidence = result.reboot_evidence;
  if (!evidence) return null;

  const host = result.hostname || `system #${result.system_id}`;

  if (evidence.outcome === 'success' && evidence.value === true) {
    return {
      tone: 'required',
      message: `${host} needs a reboot for these updates to take effect.`,
    };
  }
  if (evidence.outcome === 'success' && evidence.value === false) {
    return {
      tone: 'notRequired',
      message: `${host} does not need a reboot.`,
    };
  }
  return {
    tone: 'unknown',
    message: `Could not determine whether ${host} needs a reboot: ${reasonFor(evidence)}.`,
  };
}

/** The minimal toast surface this helper needs. */
export interface RebootStatusToastApi {
  info: (message: string) => void;
  warning: (message: string) => void;
}

/**
 * Report the reboot state of a host after a successful package update.
 *
 * "Needs a reboot" and "could not tell" are both states the operator has to
 * act on, so neither is reported as routine information; only a host that
 * explicitly answered "no" is.
 */
export function notifyRebootStatus(
  result: ApplyUpdatesResult,
  toastApi: RebootStatusToastApi,
): RebootStatusNotice | null {
  const notice = rebootStatusNotice(result);
  if (!notice) return null;
  if (notice.tone === 'notRequired') {
    toastApi.info(notice.message);
  } else {
    toastApi.warning(notice.message);
  }
  return notice;
}
