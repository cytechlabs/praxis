import Link from 'next/link';
import { useRouter } from 'next/router';
import type { HelpIndexItem } from '@/utils/help';

interface HelpNavProps {
  items: HelpIndexItem[];
}

const HelpNav: React.FC<HelpNavProps> = ({ items }) => {
  const router = useRouter();
  const activeSlug = Array.isArray(router.query.slug)
    ? router.query.slug[0]
    : router.query.slug;

  const sections = items.reduce<Record<string, HelpIndexItem[]>>((acc, item) => {
    (acc[item.section] ||= []).push(item);
    return acc;
  }, {});

  return (
    <nav className="space-y-6 text-sm">
      {Object.entries(sections).map(([section, sectionItems]) => (
        <div key={section}>
          <h3 className="text-xs font-semibold uppercase tracking-wider text-gray-500 mb-2">
            {section}
          </h3>
          <ul className="space-y-0.5">
            {sectionItems
              .sort((a, b) => a.order - b.order)
              .map((item) => {
                const isActive = activeSlug === item.slug;
                return (
                  <li key={item.slug}>
                    <Link
                      href={`/help/${item.slug}`}
                      className={`block px-2.5 py-1.5 rounded text-sm transition-colors ${
                        isActive
                          ? 'bg-red-500/10 text-red-400 border-l-2 border-red-500 pl-2'
                          : 'text-gray-400 hover:text-gray-200 hover:bg-white/[0.03]'
                      }`}
                    >
                      {item.title}
                    </Link>
                  </li>
                );
              })}
          </ul>
        </div>
      ))}
    </nav>
  );
};

export default HelpNav;
