import Link from 'next/link';
import { HelpCircle } from 'lucide-react';

interface HelpLinkProps {
  /** Slug under /help/ - e.g. "packages" */
  slug: string;
  /** Optional label for screen readers / tooltips. */
  label?: string;
  className?: string;
}

/**
 * (?) icon placed in page headers that deep-links to the relevant help
 * guide. Opens in the same tab by default. Use like:
 *
 *   <PageHeader title="Packages" action={<HelpLink slug="packages" />} />
 */
const HelpLink: React.FC<HelpLinkProps> = ({ slug, label = 'Help', className = '' }) => {
  return (
    <Link
      href={`/help/${slug}`}
      aria-label={label}
      title={label}
      className={`inline-flex items-center justify-center w-7 h-7 rounded-full text-content-subtle hover:text-red-400 hover:bg-red-500/10 transition-colors ${className}`}
    >
      <HelpCircle size={16} />
    </Link>
  );
};

export default HelpLink;
