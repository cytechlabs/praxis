import React from 'react';

/**
 * PRA-268: official Praxis brand marks.
 *
 * Uses the official assets from `brand_gfx/` (copied into `public/brand/`) rather
 * than a hand-built wordmark. Each mark ships in a dark-background and a
 * light-background variant; both are rendered and CSS (`.brand-dark` /
 * `.brand-light` in globals.css) shows the correct one per `data-theme`. Dark is
 * the 1.0 default theme.
 *
 * `<img>` is used deliberately (static SVG from /public) - next/image adds no
 * value for an inline vector logo and would need per-SVG config.
 */

export function BrandWordmark({
  height = 24,
  className = '',
}: {
  height?: number;
  className?: string;
}) {
  return (
    <span className={`inline-flex items-center ${className}`} role="img" aria-label="Praxis">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/brand/praxis-primary-dark.svg" alt="" className="brand-dark" style={{ height }} />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/brand/praxis-on-light.svg" alt="" className="brand-light" style={{ height }} />
    </span>
  );
}

export function BrandIcon({
  size = 24,
  className = '',
}: {
  size?: number;
  className?: string;
}) {
  return (
    <span className={`inline-flex ${className}`} role="img" aria-label="Praxis">
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/brand/praxis-icon-white.svg" alt="" className="brand-dark" width={size} height={size} />
      {/* eslint-disable-next-line @next/next/no-img-element */}
      <img src="/brand/praxis-icon-ink.svg" alt="" className="brand-light" width={size} height={size} />
    </span>
  );
}

export default BrandWordmark;
