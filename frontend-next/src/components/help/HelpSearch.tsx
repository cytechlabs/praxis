import { useMemo, useState } from 'react';
import Link from 'next/link';
import { Search, X } from 'lucide-react';
import type { HelpIndexItem } from '@/utils/help';

interface HelpSearchProps {
  items: HelpIndexItem[];
}

/**
 * Lightweight client-side search. We could wire in flexsearch for larger
 * corpora, but with ~10 guides a simple substring scan over the pre-built
 * searchText field is instant and adds zero bundle weight.
 */
const HelpSearch: React.FC<HelpSearchProps> = ({ items }) => {
  const [query, setQuery] = useState('');
  const q = query.trim().toLowerCase();

  const results = useMemo(() => {
    if (!q) return [];
    return items
      .filter((item) => item.searchText.includes(q))
      .slice(0, 10);
  }, [items, q]);

  return (
    <div className="relative">
      <div className="relative">
        <Search size={14} className="absolute left-3 top-1/2 -translate-y-1/2 text-gray-500" />
        <input
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          placeholder="Search help…"
          className="w-full pl-9 pr-9 py-2 text-sm bg-gray-900/60 border border-gray-800 rounded-md text-gray-200 placeholder-gray-600 focus:outline-none focus:border-red-500/50 focus:ring-1 focus:ring-red-500/30"
        />
        {query && (
          <button
            type="button"
            onClick={() => setQuery('')}
            className="absolute right-2 top-1/2 -translate-y-1/2 p-1 text-gray-500 hover:text-gray-300"
            aria-label="Clear search"
          >
            <X size={14} />
          </button>
        )}
      </div>

      {q && (
        <div className="absolute left-0 right-0 mt-1 rounded-md shadow-2xl bg-[#0c0c0f] border border-gray-800/60 overflow-hidden z-20">
          {results.length === 0 ? (
            <div className="px-3 py-3 text-sm text-gray-500">No matches.</div>
          ) : (
            <ul className="divide-y divide-gray-800/60">
              {results.map((item) => (
                <li key={item.slug}>
                  <Link
                    href={`/help/${item.slug}`}
                    onClick={() => setQuery('')}
                    className="block px-3 py-2 hover:bg-white/[0.03] transition-colors"
                  >
                    <div className="text-sm text-gray-200">{item.title}</div>
                    <div className="text-xs text-gray-500 truncate">{item.description}</div>
                  </Link>
                </li>
              ))}
            </ul>
          )}
        </div>
      )}
    </div>
  );
};

export default HelpSearch;
