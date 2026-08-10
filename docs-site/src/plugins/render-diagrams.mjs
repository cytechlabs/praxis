import { fromHtmlIsomorphic } from 'hast-util-from-html-isomorphic';
import { parse as parseClassNames } from 'space-separated-tokens';
import { SKIP, visit } from 'unist-util-visit';

import { MANIFEST, diagramKey, readDiagram, recordDiagram } from '../diagram-cache.mjs';

/** The text of a fenced code block, in document order. */
function sourceOf(node, parts = []) {
  if (node.type === 'text') parts.push(node.value);
  for (const child of node.children ?? []) sourceOf(child, parts);
  return parts.join('');
}

/**
 * Whether an element carries a class name.
 *
 * `className` is an array once hast has parsed it, but a plugin earlier in the
 * pipeline may leave it as the raw attribute string, so both are accepted.
 */
function hasClass(element, wanted) {
  const className = element.properties?.className;
  const classes = typeof className === 'string' ? parseClassNames(className) : className;
  return Array.isArray(classes) && classes.includes(wanted);
}

/** Every Mermaid fence on a page, with where it sits in the tree. */
function fencesIn(tree) {
  const found = [];

  visit(tree, 'element', (node, index, parent) => {
    if (node.tagName !== 'pre' || !parent || index === undefined) return;

    const code = node.children.find(
      (child) => child.type === 'element' && child.tagName === 'code',
    );
    if (!code || !hasClass(code, 'language-mermaid')) return;

    found.push({ parent, index, source: sourceOf(code) });
    return SKIP;
  });

  return found;
}

/**
 * Replaces every Mermaid fence with its rendered diagram.
 *
 * The source stays plain Mermaid in `docs/`, which is what GitHub renders, and
 * the site gets an inline SVG: no client-side script, no network request, and
 * nothing the documentation content security policy does not already allow.
 *
 * The SVG is read from the committed directory that `src/diagram-cache.mjs`
 * describes. This runs during every build, including the one that publishes the
 * public site, so it deliberately does nothing that needs a browser and imports
 * nothing that leads to one.
 *
 * A fence with nothing stored for it fails the build. Silently shipping the
 * previous picture for an edited diagram, or shipping the source as a code
 * block, are both worse than stopping. The exception is a collecting build,
 * whose only job is to report which fences exist so they can be rendered; its
 * pages are thrown away.
 */
export function renderDiagrams() {
  const collecting = MANIFEST !== '';

  return function transformer(tree, file) {
    for (const { parent, index, source } of fencesIn(tree)) {
      const key = diagramKey(source);

      if (collecting) recordDiagram(key, source);

      const svg = readDiagram(key);
      if (!svg) {
        if (collecting) continue;
        throw new Error(
          `${file?.path ?? 'a document'}: no rendered diagram stored for "${key}". ` +
            'Regenerate with: node scripts/build-docs-diagrams.mjs',
        );
      }

      parent.children[index] = fromHtmlIsomorphic(svg, { fragment: true }).children[0];
    }
  };
}
