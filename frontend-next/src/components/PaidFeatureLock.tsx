import React from 'react';
import Link from 'next/link';
import { Lock, Check } from 'lucide-react';
import { Button } from './ui';

/**
 * PRA-132 / PRA-274: the shared paid/entitlement-locked surface.
 *
 * A calm, on-brand commercial panel - feature name, a one-line value, a few
 * concrete benefits, an upgrade CTA, and an optional docs link - NOT a noisy
 * upsell card. Presentation only: the server enforces the entitlement and
 * returns HTTP 402 if a paid action is attempted without it.
 */
interface PaidFeatureLockProps {
  /** Feature / page name shown as the heading. */
  feature?: string;
  /** One-line value proposition. */
  value?: string;
  /** 2–3 concrete benefits. */
  benefits?: string[];
  /** Where the upgrade CTA points. Defaults to the in-app License tab. */
  upgradeHref?: string;
  /** Optional docs/learn-more link (omitted if not provided). */
  docsHref?: string;
  /** Back-compat: prior callers passed `title` / `description`. */
  title?: string;
  description?: string;
}

const DEFAULT_BENEFITS = [
  'Governance and scale controls for larger fleets',
  'Included with any paid Praxis license',
  'No change to your existing data or workflows',
];

const PaidFeatureLock: React.FC<PaidFeatureLockProps> = ({
  feature,
  value,
  benefits = DEFAULT_BENEFITS,
  upgradeHref = '/settings?tab=license',
  docsHref,
  title,
  description,
}) => {
  const heading = feature ?? title ?? 'Paid feature';
  const valueLine =
    value ??
    description ??
    'Part of the paid Praxis edition. The free edition includes the full core ' +
      'fleet, patch, content, and compliance surfaces.';

  return (
    <div className="mx-auto my-12 max-w-md rounded-lg border border-border bg-surface-raised p-6 text-center">
      <div className="mx-auto mb-4 flex h-11 w-11 items-center justify-center rounded-full bg-amber-500/10">
        <Lock size={20} className="text-amber-400" />
      </div>
      <h3 className="text-base font-semibold text-content">{heading}</h3>
      <p className="mt-1 text-sm text-content-muted">{valueLine}</p>

      {benefits.length > 0 && (
        <ul className="mx-auto mt-4 max-w-xs space-y-1.5 text-left">
          {benefits.map((b) => (
            <li key={b} className="flex items-start gap-2 text-sm text-content-muted">
              <Check size={15} className="mt-0.5 shrink-0 text-success" />
              <span>{b}</span>
            </li>
          ))}
        </ul>
      )}

      <div className="mt-6 flex items-center justify-center gap-4">
        <Link href={upgradeHref}>
          <Button variant="primary" size="sm">View plans</Button>
        </Link>
        {docsHref && (
          <Link
            href={docsHref}
            className="text-sm text-link hover:text-link-hover underline underline-offset-2"
          >
            Learn more
          </Link>
        )}
      </div>
    </div>
  );
};

export default PaidFeatureLock;
