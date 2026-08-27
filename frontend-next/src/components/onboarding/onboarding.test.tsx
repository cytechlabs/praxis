// @vitest-environment jsdom
import { afterEach, describe, expect, it, vi } from 'vitest';
import { cleanup, fireEvent, render, screen } from '@testing-library/react';

import StepIndicator, { STEP_ORDER } from './StepIndicator';
import VerificationReport, { HostKeyReview } from './VerificationReport';
import type { VerificationCheck } from '@/services/onboardingService';

const check = (
  name: VerificationCheck['check'],
  status: VerificationCheck['status'],
  reason: string,
  message = 'Operator-facing explanation.',
): VerificationCheck => ({
  check: name,
  status,
  reason_code: reason,
  message,
});

describe('PRA-414 step indicator', () => {
  afterEach(cleanup);

  it('exposes all seven steps in order', () => {
    expect(STEP_ORDER).toEqual([
      'connect',
      'authenticate',
      'verify',
      'discover',
      'organize',
      'confirm',
      'finish',
    ]);
  });

  it('marks the current step for assistive technology', () => {
    const { container } = render(
      <StepIndicator current="verify" furthest="verify" />,
    );
    const current = container.querySelector('[aria-current="step"]');
    expect(current?.textContent).toContain('Verify');
  });

  it('gives a narrow viewport a position summary instead of seven labels', () => {
    render(<StepIndicator current="organize" furthest="organize" />);
    expect(screen.getByText(/Step 5 of 7/)).toBeTruthy();
  });

  it('is labelled as navigation so it can be skipped', () => {
    render(<StepIndicator current="connect" furthest="connect" />);
    expect(screen.getByRole('navigation', { name: /setup progress/i })).toBeTruthy();
  });
});

describe('PRA-414 verification report', () => {
  afterEach(cleanup);

  it('reports each check independently rather than as one failure', () => {
    render(
      <VerificationReport
        verified={false}
        checks={[
          check('address', 'pass', 'verified'),
          check('network', 'pass', 'verified'),
          check('host_identity', 'pass', 'verified'),
          check(
            'authentication',
            'fail',
            'authentication_failed',
            'The host refused the credential.',
          ),
        ]}
      />,
    );
    expect(screen.getByText('Network reachability')).toBeTruthy();
    expect(screen.getByText('Credential authentication')).toBeTruthy();
    expect(screen.getByText('The host refused the credential.')).toBeTruthy();
    expect(screen.getByText('authentication_failed')).toBeTruthy();
  });

  it('does not claim success when a check failed', () => {
    render(
      <VerificationReport
        verified={false}
        checks={[check('network', 'fail', 'connection_timeout')]}
      />,
    );
    expect(screen.getByRole('status').textContent).toContain(
      'Verification did not complete',
    );
  });

  it('states success plainly when everything passed', () => {
    render(
      <VerificationReport
        verified
        checks={[check('authentication', 'pass', 'verified')]}
      />,
    );
    expect(screen.getByRole('status').textContent).toContain(
      'reachable and the credential works',
    );
  });

  it('shows a skipped check as not-checked rather than passed', () => {
    render(
      <VerificationReport verified checks={[check('sudo', 'skipped', 'verified')]} />,
    );
    expect(screen.getByText(/Elevation/).textContent).toContain('Not checked');
  });
});

describe('PRA-414 host key review', () => {
  afterEach(cleanup);

  const fingerprint = 'a'.repeat(64);

  it('shows the full fingerprint and offers no default choice', () => {
    const onDecide = vi.fn();
    render(
      <HostKeyReview
        fingerprint={fingerprint}
        keyType="ssh-ed25519"
        decision="pending"
        busy={false}
        onDecide={onDecide}
      />,
    );
    expect(screen.getByText(fingerprint)).toBeTruthy();
    expect(screen.getByText('ssh-ed25519')).toBeTruthy();
    // Both choices are explicit; neither is pre-selected or auto-advanced.
    expect(screen.getByRole('button', { name: /fingerprint is correct/i })).toBeTruthy();
    expect(screen.getByRole('button', { name: /does not match/i })).toBeTruthy();
    expect(onDecide).not.toHaveBeenCalled();
  });

  it('reports approval and rejection distinctly', () => {
    const onDecide = vi.fn();
    render(
      <HostKeyReview
        fingerprint={fingerprint}
        keyType="ssh-ed25519"
        decision="pending"
        busy={false}
        onDecide={onDecide}
      />,
    );
    fireEvent.click(screen.getByRole('button', { name: /does not match/i }));
    expect(onDecide).toHaveBeenCalledWith(false);

    cleanup();
    render(
      <HostKeyReview
        fingerprint={fingerprint}
        keyType="ssh-ed25519"
        decision="rejected"
        busy={false}
        onDecide={onDecide}
      />,
    );
    expect(screen.getByText(/Nothing was added/i)).toBeTruthy();
  });

  it('disables both choices while a decision is in flight', () => {
    render(
      <HostKeyReview
        fingerprint={fingerprint}
        keyType="ssh-ed25519"
        decision="pending"
        busy
        onDecide={vi.fn()}
      />,
    );
    screen
      .getAllByRole('button')
      .forEach((button) => expect((button as HTMLButtonElement).disabled).toBe(true));
  });
});
