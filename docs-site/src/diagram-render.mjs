import { toHtml } from 'hast-util-to-html';
import rehypeMermaid from 'rehype-mermaid';

import { mermaidRenderOptions } from './mermaid.mjs';

/**
 * Turns Mermaid source into an SVG string, in a headless browser.
 *
 * This is the only module that reaches a browser, and nothing the site build
 * loads imports it. `scripts/build-docs-diagrams.mjs` is its one caller, and it
 * runs under plain Node rather than inside the site build: the build's imports
 * are served by Vite's module runner, which is torn down before pages render,
 * so a renderer reached from there is unavailable exactly when it is needed.
 *
 * The `<pre>` wrapper is rebuilt around the source because that is the shape
 * `rehype-mermaid` recognises. Only the text inside the `<code>` element is
 * read, and that text is what the diagram is keyed by, so what is rendered here
 * is what the build asked for.
 */
export async function renderDiagramSource(source) {
  const tree = {
    type: 'root',
    children: [
      {
        type: 'element',
        tagName: 'pre',
        properties: {},
        children: [
          {
            type: 'element',
            tagName: 'code',
            properties: { className: ['language-mermaid'] },
            children: [{ type: 'text', value: source }],
          },
        ],
      },
    ],
  };

  await rehypeMermaid(mermaidRenderOptions)(tree, { path: 'diagram' });

  const [svg] = tree.children;
  if (!svg || svg.type !== 'element' || svg.tagName !== 'svg') {
    throw new Error('the Mermaid renderer did not produce an SVG element');
  }

  return toHtml(svg, { space: 'svg' });
}
