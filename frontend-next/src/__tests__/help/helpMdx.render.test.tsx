// @vitest-environment jsdom
/**
 * Contract coverage for the help guide MDX pipeline.
 *
 * The help page compiles repository-owned MDX at build time with `serialize`
 * and hydrates it with `<MDXRemote />`. These tests pin three things: every
 * shipped help document compiles and renders, the component overrides passed to
 * `<MDXRemote />` are applied, and JavaScript expressions in MDX source are
 * stripped rather than executed.
 */
import React from 'react';
import { describe, it, expect, afterEach } from 'vitest';
import { render, cleanup } from '@testing-library/react';
import { MDXRemote } from 'next-mdx-remote';
import { serialize } from 'next-mdx-remote/serialize';
import { listHelpEntries } from '@/utils/help';

// Must match the options the help page passes in getStaticProps.
const SERIALIZE_OPTIONS = { parseFrontmatter: false, blockJS: true } as const;

const components = {
  h1: (props: React.HTMLAttributes<HTMLHeadingElement>) => <h1 className="help-h1" {...props} />,
  a: (props: React.AnchorHTMLAttributes<HTMLAnchorElement>) => <a className="help-a" {...props} />,
  code: (props: React.HTMLAttributes<HTMLElement>) => <code className="help-code" {...props} />,
};

async function renderMdx(source: string) {
  const mdx = await serialize(source, SERIALIZE_OPTIONS);
  return render(<MDXRemote {...mdx} components={components} />);
}

describe('help MDX rendering', () => {
  afterEach(cleanup);

  it('compiles and renders every shipped help document', async () => {
    const entries = listHelpEntries();
    expect(entries.length).toBeGreaterThan(0);

    for (const entry of entries) {
      const mdx = await serialize(entry.body, SERIALIZE_OPTIONS);
      expect(mdx.compiledSource.length, `${entry.slug} produced no compiled source`).toBeGreaterThan(0);

      const { container, unmount } = render(<MDXRemote {...mdx} components={components} />);
      expect(container.querySelector('p'), `${entry.slug} rendered no prose`).toBeTruthy();
      expect((container.textContent ?? '').length, `${entry.slug} rendered no text`).toBeGreaterThan(100);
      unmount();
    }
  });

  it('renders representative markdown through the supplied component overrides', async () => {
    const { container } = await renderMdx(
      [
        '# Fleet basics',
        '',
        'Register a host from the **Fleet** page.',
        '',
        '- enrol the agent',
        '- verify the host key',
        '',
        '1. first',
        '2. second',
        '',
        '> Approvals are enforced server side.',
        '',
        'Run `praxis fleet list` to confirm.',
        '',
        '```json',
        '{ "op": "and" }',
        '```',
        '',
        '[Fleet guide](https://example.test/fleet)',
      ].join('\n'),
    );

    const heading = container.querySelector('h1');
    expect(heading?.textContent).toBe('Fleet basics');
    expect(heading?.className).toBe('help-h1');

    const link = container.querySelector('a');
    expect(link?.getAttribute('href')).toBe('https://example.test/fleet');
    expect(link?.className).toBe('help-a');

    expect(container.querySelectorAll('ul li')).toHaveLength(2);
    expect(container.querySelectorAll('ol li')).toHaveLength(2);
    expect(container.querySelector('blockquote')?.textContent).toContain('Approvals are enforced');
    expect(container.querySelector('strong')?.textContent).toBe('Fleet');
    expect(container.querySelector('pre code')?.textContent).toContain('"op": "and"');
  });

  it('strips JavaScript expressions instead of evaluating them', async () => {
    const { container } = await renderMdx('Total is {2 + 2} systems.');

    const text = container.textContent ?? '';
    expect(text).toContain('Total is');
    expect(text).not.toContain('4');
    expect(text).not.toContain('2 + 2');
  });

  it('keeps brace-bearing inline code intact', async () => {
    const { container } = await renderMdx('Rules take the form `{name, check}` per package.');

    const code = container.querySelector('code');
    expect(code?.textContent).toBe('{name, check}');
    expect(code?.className).toBe('help-code');
  });
});
