import React from 'react';
import { ArrowLeft, ArrowRight } from 'lucide-react';

import { Button } from '@/components/ui';
import type { OnboardingStep } from '@/services/onboardingService';

/**
 * What the operator can do about a failed step.
 *
 * The structured code decides the offer, so an expired or cancelled setup gets
 * a restart, a stale one gets a reload, and a duplicate points at the host that
 * already exists. Anything else states the failure and stops there.
 */
export const OnboardingErrorBanner: React.FC<{
  error: { code: string; message: string };
  onRestart: () => void;
  onReload: () => void;
  onViewSystems: () => void;
}> = ({ error, onRestart, onReload, onViewSystems }) => (
  <div
    role="alert"
    className="mb-4 rounded-md border border-danger/40 bg-danger/10 p-4"
  >
    <p className="text-sm text-danger">{error.message}</p>
    <p className="mt-1 font-mono text-[11px] text-content-subtle">{error.code}</p>
    {['draft_expired', 'draft_canceled', 'authority_changed'].includes(
      error.code,
    ) && (
      <p className="mt-2 text-xs text-content-muted">
        Nothing was added, so no host or licence seat was used.{' '}
        <button
          type="button"
          onClick={onRestart}
          className="text-link underline underline-offset-2 hover:text-link-hover"
        >
          Start again
        </button>
        .
      </p>
    )}
    {error.code === 'draft_stale' && (
      <p className="mt-2 text-xs text-content-muted">
        This setup changed somewhere else.{' '}
        <button
          type="button"
          onClick={onReload}
          className="text-link underline underline-offset-2 hover:text-link-hover"
        >
          Reload it
        </button>
        .
      </p>
    )}
    {error.code === 'duplicate_host' && (
      <p className="mt-2 text-xs text-content-muted">
        <button
          type="button"
          onClick={onViewSystems}
          className="text-link underline underline-offset-2 hover:text-link-hover"
        >
          Look at the systems you already have
        </button>
        .
      </p>
    )}
  </div>
);

/**
 * Step controls.
 *
 * Back and Cancel are always available; the primary action belongs to the step
 * the operator is on, which is why each one names its own handler and its own
 * enabling condition rather than sharing a generic Next.
 */
export const StepFooter: React.FC<{
  step: OnboardingStep;
  busy: boolean;
  canLeaveVerify: boolean;
  hasAddress: boolean;
  hasCredential: boolean;
  hasDiscovery: boolean;
  canFinish: boolean;
  onBack: () => void;
  onCancel: () => void;
  onConnect: () => void;
  onAuthenticate: () => void;
  onLeaveVerify: () => void;
  onLeaveDiscover: () => void;
  onOrganize: () => void;
  onFinish: () => void;
}> = ({
  step,
  busy,
  canLeaveVerify,
  hasAddress,
  hasCredential,
  hasDiscovery,
  canFinish,
  onBack,
  onCancel,
  onConnect,
  onAuthenticate,
  onLeaveVerify,
  onLeaveDiscover,
  onOrganize,
  onFinish,
}) => (
  <div className="flex flex-wrap items-center justify-between gap-2 border-t border-border pt-4">
    <Button
      variant="ghost"
      icon={<ArrowLeft size={14} />}
      disabled={busy || step === 'connect'}
      onClick={onBack}
    >
      Back
    </Button>
    <div className="flex flex-wrap gap-2">
      <Button variant="ghost" onClick={onCancel} disabled={busy}>
        Cancel
      </Button>
      {step === 'connect' && (
        <Button
          variant="primary"
          icon={<ArrowRight size={14} />}
          onClick={onConnect}
          loading={busy}
          disabled={!hasAddress}
        >
          Next
        </Button>
      )}
      {step === 'authenticate' && (
        <Button
          variant="primary"
          icon={<ArrowRight size={14} />}
          onClick={onAuthenticate}
          loading={busy}
          disabled={!hasCredential}
        >
          Next
        </Button>
      )}
      {step === 'verify' && (
        <Button
          variant="primary"
          icon={<ArrowRight size={14} />}
          onClick={onLeaveVerify}
          disabled={busy || !canLeaveVerify}
        >
          Next
        </Button>
      )}
      {step === 'discover' && (
        <Button
          variant="primary"
          icon={<ArrowRight size={14} />}
          onClick={onLeaveDiscover}
          disabled={busy || !hasDiscovery}
        >
          Next
        </Button>
      )}
      {step === 'organize' && (
        <Button
          variant="primary"
          icon={<ArrowRight size={14} />}
          onClick={onOrganize}
          loading={busy}
        >
          Next
        </Button>
      )}
      {step === 'confirm' && (
        <Button
          variant="primary"
          onClick={onFinish}
          loading={busy}
          disabled={!canFinish}
        >
          Add this system
        </Button>
      )}
    </div>
  </div>
);
