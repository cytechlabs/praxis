/**
 * Help-content indexer. Runs at build time inside getStaticProps / getStaticPaths.
 * Reads frontmatter from every .mdx under src/content/help/ and produces a
 * normalized list used by the nav tree and the client-side search index.
 */

import fs from 'fs';
import path from 'path';
import matter from 'gray-matter';

export interface HelpEntry {
  slug: string;
  title: string;
  description: string;
  section: string;
  order: number;
  keywords: string[];
  body: string;
}

const HELP_DIR = path.join(process.cwd(), 'src', 'content', 'help');

export function listHelpSlugs(): string[] {
  if (!fs.existsSync(HELP_DIR)) return [];
  return fs
    .readdirSync(HELP_DIR)
    .filter((f) => f.endsWith('.mdx'))
    .map((f) => f.replace(/\.mdx$/, ''));
}

export function readHelpEntry(slug: string): HelpEntry | null {
  const file = path.join(HELP_DIR, `${slug}.mdx`);
  if (!fs.existsSync(file)) return null;
  const raw = fs.readFileSync(file, 'utf8');
  const { data, content } = matter(raw);
  return {
    slug,
    title: data.title ?? slug,
    description: data.description ?? '',
    section: data.section ?? 'Guides',
    order: typeof data.order === 'number' ? data.order : 999,
    keywords: Array.isArray(data.keywords) ? data.keywords : [],
    body: content,
  };
}

export function listHelpEntries(): HelpEntry[] {
  return listHelpSlugs()
    .map(readHelpEntry)
    .filter((e): e is HelpEntry => !!e)
    .sort((a, b) => a.order - b.order);
}

export interface HelpIndexItem {
  slug: string;
  title: string;
  description: string;
  section: string;
  order: number;
  searchText: string;
}

export function buildHelpIndex(): HelpIndexItem[] {
  return listHelpEntries().map((e) => ({
    slug: e.slug,
    title: e.title,
    description: e.description,
    section: e.section,
    order: e.order,
    searchText: [e.title, e.description, e.keywords.join(' '), e.body]
      .join(' ')
      .toLowerCase(),
  }));
}
