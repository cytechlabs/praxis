import React from 'react';
import { Check } from 'lucide-react';

import type { OnboardingStep } from '@/services/onboardingService';

export const STEP_ORDER: OnboardingStep[] = [
  'connect',
  'authenticate',
  'verify',
  'discover',
  'organize',
  'confirm',
  'finish',
];

const STEP_LABELS: Record<OnboardingStep, string> = {
  connect: 'Connect',
  authenticate: 'Authenticate',
  verify: 'Verify',
  discover: 'Discover',
  organize: 'Organize',
  confirm: 'Confirm',
  finish: 'Finish',
};

/**
 * Progress through the seven steps.
 *
 * An ordered list rather than a row of divs, so a screen reader announces
 * position and total without the visual sequence having to be inferred. On a
 * narrow viewport the labels collapse to the current step alone: seven labels
 * at 390px either wrap into an unreadable stack or get clipped.
 */
const StepIndicator: React.FC<{ current: OnboardingStep; furthest: OnboardingStep }> = ({
  current,
  furthest,
}) => {
  const currentIndex = STEP_ORDER.indexOf(current);
  const furthestIndex = STEP_ORDER.indexOf(furthest);

  return (
    <nav aria-label="Setup progress" className="mb-6">
      <p className="sm:hidden text-sm text-content-muted mb-2">
        Step {currentIndex + 1} of {STEP_ORDER.length}:{' '}
        <span className="text-content font-medium">{STEP_LABELS[current]}</span>
      </p>
      <ol className="hidden sm:flex items-center gap-1 flex-wrap">
        {STEP_ORDER.map((step, index) => {
          const isCurrent = index === currentIndex;
          const isDone = index < furthestIndex || (index < currentIndex);
          return (
            <li key={step} className="flex items-center gap-1">
              <span
                aria-current={isCurrent ? 'step' : undefined}
                className={[
                  'flex items-center gap-1.5 rounded-md px-2.5 py-1 text-xs whitespace-nowrap',
                  isCurrent
                    ? 'bg-action text-action-fg font-medium'
                    : isDone
                      ? 'text-content-muted'
                      : 'text-content-subtle',
                ].join(' ')}
              >
                <span
                  className={[
                    'flex h-4 w-4 shrink-0 items-center justify-center rounded-full text-[10px]',
                    isCurrent
                      ? 'bg-action-fg text-action'
                      : isDone
                        ? 'bg-success/20 text-success'
                        : 'border border-border',
                  ].join(' ')}
                  aria-hidden="true"
                >
                  {isDone && !isCurrent ? <Check size={10} /> : index + 1}
                </span>
                {STEP_LABELS[step]}
                <span className="sr-only">
                  {isDone && !isCurrent ? ' (completed)' : ''}
                </span>
              </span>
              {index < STEP_ORDER.length - 1 && (
                <span aria-hidden="true" className="text-content-subtle">
                  /
                </span>
              )}
            </li>
          );
        })}
      </ol>
    </nav>
  );
};

export default StepIndicator;
