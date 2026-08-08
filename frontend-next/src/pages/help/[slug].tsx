import type { GetStaticPaths, GetStaticProps } from 'next';
import Head from 'next/head';
import { MDXRemote, type MDXRemoteSerializeResult } from 'next-mdx-remote';
import { serialize } from 'next-mdx-remote/serialize';
import MainLayout from '@/components/MainLayout';
import HelpNav from '@/components/help/HelpNav';
import HelpSearch from '@/components/help/HelpSearch';
import {
  buildHelpIndex,
  listHelpEntries,
  readHelpEntry,
  type HelpEntry,
  type HelpIndexItem,
} from '@/utils/help';

interface HelpPageProps {
  entry: HelpEntry;
  mdx: MDXRemoteSerializeResult;
  index: HelpIndexItem[];
}

const mdxComponents = {
  h1: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h1 className="text-2xl font-bold text-content mb-4 mt-0" {...props} />
  ),
  h2: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h2 className="text-xl font-semibold text-content mt-8 mb-3 border-b border-border pb-2" {...props} />
  ),
  h3: (props: React.HTMLAttributes<HTMLHeadingElement>) => (
    <h3 className="text-lg font-semibold text-content mt-6 mb-2" {...props} />
  ),
  p: (props: React.HTMLAttributes<HTMLParagraphElement>) => (
    <p className="text-content leading-relaxed mb-4" {...props} />
  ),
  ul: (props: React.HTMLAttributes<HTMLUListElement>) => (
    <ul className="list-disc list-outside ml-6 text-content mb-4 space-y-1" {...props} />
  ),
  ol: (props: React.OlHTMLAttributes<HTMLOListElement>) => (
    <ol className="list-decimal list-outside ml-6 text-content mb-4 space-y-1" {...props} />
  ),
  li: (props: React.LiHTMLAttributes<HTMLLIElement>) => (
    <li className="text-content" {...props} />
  ),
  a: (props: React.AnchorHTMLAttributes<HTMLAnchorElement>) => (
    <a className="text-red-400 hover:text-red-300 underline underline-offset-2" {...props} />
  ),
  code: (props: React.HTMLAttributes<HTMLElement>) => (
    <code className="px-1.5 py-0.5 rounded bg-surface-raised/80 border border-border text-[0.85em] text-content" {...props} />
  ),
  pre: (props: React.HTMLAttributes<HTMLPreElement>) => (
    <pre className="p-4 rounded-md bg-surface-raised/80 border border-border overflow-x-auto text-sm text-content mb-4" {...props} />
  ),
  strong: (props: React.HTMLAttributes<HTMLElement>) => (
    <strong className="text-content font-semibold" {...props} />
  ),
  em: (props: React.HTMLAttributes<HTMLElement>) => (
    <em className="text-content-muted italic" {...props} />
  ),
  blockquote: (props: React.BlockquoteHTMLAttributes<HTMLQuoteElement>) => (
    <blockquote className="border-l-2 border-red-500/50 pl-4 italic text-content-muted my-4" {...props} />
  ),
};

const HelpGuidePage: React.FC<HelpPageProps> = ({ entry, mdx, index }) => {
  return (
    <MainLayout>
      <Head>
        <title>{`${entry.title} - Help | Praxis`}</title>
        {entry.description && <meta name="description" content={entry.description} />}
      </Head>

      <div className="flex gap-6 max-w-7xl mx-auto">
        <aside className="w-64 flex-shrink-0 sticky top-20 self-start max-h-[calc(100vh-6rem)] overflow-y-auto">
          <div className="mb-4">
            <HelpSearch items={index} />
          </div>
          <HelpNav items={index} />
        </aside>

        <main className="flex-1 min-w-0 max-w-3xl">
          <article className="prose prose-invert">
            <MDXRemote {...mdx} components={mdxComponents} />
          </article>
        </main>
      </div>
    </MainLayout>
  );
};

export const getStaticPaths: GetStaticPaths = async () => {
  const entries = listHelpEntries();
  return {
    paths: entries.map((e) => ({ params: { slug: e.slug } })),
    fallback: 'blocking',
  };
};

export const getStaticProps: GetStaticProps<HelpPageProps> = async ({ params }) => {
  const slug = params?.slug as string | undefined;
  if (!slug) return { notFound: true };

  const entry = readHelpEntry(slug);
  if (!entry) return { notFound: true };

  // Help pages are repository-owned MDX, but the compiler stays locked down:
  // blockJS strips JavaScript expressions from the source instead of compiling
  // them, so no help document can execute code at build or hydration time.
  const mdx = await serialize(entry.body, { parseFrontmatter: false, blockJS: true });
  const index = buildHelpIndex();
  return { props: { entry, mdx, index } };
};

export default HelpGuidePage;
