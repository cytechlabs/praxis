import type { GetStaticProps } from 'next';
import Head from 'next/head';
import Link from 'next/link';
import MainLayout from '@/components/MainLayout';
import HelpNav from '@/components/help/HelpNav';
import HelpSearch from '@/components/help/HelpSearch';
import { buildHelpIndex, type HelpIndexItem } from '@/utils/help';

interface HelpIndexProps {
  index: HelpIndexItem[];
}

const HelpIndexPage: React.FC<HelpIndexProps> = ({ index }) => {
  return (
    <MainLayout>
      <Head>
        <title>Help | Praxis</title>
      </Head>

      <div className="flex gap-6 max-w-7xl mx-auto">
        <aside className="w-64 flex-shrink-0 sticky top-20 self-start max-h-[calc(100vh-6rem)] overflow-y-auto">
          <div className="mb-4">
            <HelpSearch items={index} />
          </div>
          <HelpNav items={index} />
        </aside>

        <main className="flex-1 min-w-0 max-w-3xl">
          <h1 className="text-2xl font-bold text-content mb-2">Help</h1>
          <p className="text-content-muted mb-6">
            Pick a guide from the navigation to get started. Every page is linkable -
            copy a URL and paste it anywhere.
          </p>
          <ul className="grid grid-cols-1 sm:grid-cols-2 gap-3">
            {index.map((item) => (
              <li key={item.slug}>
                <Link
                  href={`/help/${item.slug}`}
                  className="block p-4 rounded-md border border-border hover:border-red-500/50 hover:bg-white/[0.02] transition-colors"
                >
                  <div className="text-sm font-semibold text-content mb-1">{item.title}</div>
                  <div className="text-xs text-content-subtle">{item.description}</div>
                </Link>
              </li>
            ))}
          </ul>
        </main>
      </div>
    </MainLayout>
  );
};

export const getStaticProps: GetStaticProps<HelpIndexProps> = async () => {
  return { props: { index: buildHelpIndex() } };
};

export default HelpIndexPage;
