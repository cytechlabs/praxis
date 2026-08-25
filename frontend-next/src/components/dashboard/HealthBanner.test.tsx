// @vitest-environment jsdom
//
// PRA-400: the dashboard hero must not announce a fleet as healthy while its
// security status is unknown. A fleet nobody has security-scanned, a scan in
// flight, a failed scan, and partial coverage each get their own state; only a
// completed scan with no findings reaches the healthy banner.
import { describe, it, expect, afterEach } from 'vitest';
import { render, screen, cleanup } from '@testing-library/react';

import HealthBanner from './HealthBanner';
import type {
  SecurityPosture,
  SecurityPostureState,
} from '@/services/fleetHealthService';

afterEach(cleanup);

const posture = (
  state: SecurityPostureState,
  overrides: Partial<SecurityPosture> = {},
): SecurityPosture => ({
  state,
  coverage_complete: state === 'complete',
  counts_trustworthy: state === 'complete',
  systems_total: 3,
  systems_scanned: state === 'complete' ? 3 : 0,
  systems_partial: 0,
  systems_failed: 0,
  systems_scanning: 0,
  systems_never_scanned: state === 'complete' ? 0 : 3,
  last_successful_scan_at: null,
  last_scan_at: null,
  last_failure_detail: null,
  coverage_detail: 'No security scan has completed for any of the 3 systems.',
  systems_with_security_updates: 0,
  pending_security_updates: 0,
  ...overrides,
});

const renderBanner = (props: Partial<React.ComponentProps<typeof HealthBanner>> = {}) =>
  render(
    <HealthBanner
      unreachable={0}
      securityUpdates={0}
      systemsWithSecurityUpdates={0}
      pendingUpdates={0}
      systemsWithUpdates={0}
      totalSystems={3}
      {...props}
    />,
  );

describe('HealthBanner security state', () => {
  it('does not call an unscanned fleet healthy', () => {
    renderBanner({ securityPosture: posture('not_scanned') });

    expect(screen.queryByText(/All 3 systems healthy/)).toBeNull();
    expect(screen.getByText(/Security status unknown/)).toBeTruthy();
    expect(
      screen.getByText(/No security scan has completed for any of the 3 systems\./),
    ).toBeTruthy();
    expect(screen.getByText('Run a security scan')).toBeTruthy();
  });

  it('reports a scan in progress', () => {
    renderBanner({
      securityPosture: posture('scanning', {
        systems_scanning: 2,
        coverage_detail: 'Security scan running on 2 of 3 systems.',
      }),
    });

    expect(screen.getByText('Security scan in progress')).toBeTruthy();
    expect(screen.queryByText(/healthy/)).toBeNull();
  });

  it('surfaces sanitized failure context for a failed scan', () => {
    renderBanner({
      securityPosture: posture('failed', {
        systems_failed: 3,
        systems_never_scanned: 0,
        coverage_detail: '0 of 3 systems have a completed security scan.',
        last_failure_detail: 'no output from remote host',
      }),
    });

    expect(screen.getByText(/Security scan failed/)).toBeTruthy();
    expect(screen.getByText(/Last failure: no output from remote host/)).toBeTruthy();
  });

  it('does not treat partial coverage as complete', () => {
    renderBanner({
      securityPosture: posture('partial', {
        systems_scanned: 1,
        systems_never_scanned: 2,
        coverage_detail: '1 of 3 systems have a completed security scan.',
      }),
    });

    expect(screen.getByText('Security scan covers 1 of 3 systems')).toBeTruthy();
    expect(screen.queryByText(/All 3 systems healthy/)).toBeNull();
  });

  it('announces a healthy fleet only when a completed scan found nothing', () => {
    renderBanner({
      securityPosture: posture('complete', {
        coverage_detail: 'All 3 systems have a completed security scan.',
      }),
    });

    expect(screen.getByText('All 3 systems healthy')).toBeTruthy();
    expect(
      screen.getByText(/All 3 systems have a completed security scan\./),
    ).toBeTruthy();
  });

  it('keeps pending security findings ahead of the coverage caveat', () => {
    renderBanner({
      securityUpdates: 5,
      systemsWithSecurityUpdates: 2,
      securityPosture: posture('partial', {
        systems_scanned: 1,
        systems_with_security_updates: 2,
        pending_security_updates: 5,
        coverage_detail: '1 of 3 systems have a completed security scan.',
      }),
    });

    expect(
      screen.getByText('5 critical security updates pending across 2 systems'),
    ).toBeTruthy();
    expect(
      screen.getByText(/1 of 3 systems have a completed security scan\./),
    ).toBeTruthy();
  });

  it('still reports unreachable hosts first', () => {
    renderBanner({
      unreachable: 1,
      securityPosture: posture('not_scanned'),
    });

    expect(screen.getByText('1 system unreachable')).toBeTruthy();
  });
});
