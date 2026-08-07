import React from 'react';
import { BrandWordmark } from '../ui/BrandLogo';

/**
 * PRA-272: the shared full-screen loading/auth transition shell.
 *
 * Every "we're deciding what to show you" moment - app boot, auth resolution,
 * the login page's own loading gate - renders this instead of an unbranded blank
 * or a bare "Loading..." string. It reserves full-viewport geometry (`h-screen`)
 * so there is no black flash or layout jump between the shell and the resolved
 * page, and carries the official wordmark + the block-cursor terminal motif.
 */
export default function BrandedLoadingScreen({ label = 'Loading' }: { label?: string }) {
  return (
    <div
      className="h-screen w-full flex flex-col items-center justify-center bg-surface"
      role="status"
      aria-live="polite"
      aria-busy="true"
    >
      <BrandWordmark height={30} className="mb-4" />
      <div className="flex items-center gap-1 text-content-muted text-sm">
        <span>{label}</span>
        <span className="praxis-cursor" aria-hidden="true" />
      </div>
    </div>
  );
}
