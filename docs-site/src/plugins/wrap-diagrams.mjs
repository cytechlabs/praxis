import { SKIP, visit } from 'unist-util-visit';

/** Marks a wrapper this plugin created, so a second pass leaves it alone. */
const WRAPPER_CLASS = 'diagram';

/**
 * Puts each rendered diagram in a scrollable figure.
 *
 * Diagram width is decided by the diagram, not by the page. An architecture
 * flowchart is several times wider than the documentation column, and scaling
 * one down to fit takes its labels below a readable size. Wide reference tables
 * on this site already scroll inside the column rather than shrinking or
 * widening the page, and a diagram is the same problem, so it gets the same
 * answer. `praxis.css` styles the wrapper.
 *
 * Only the SVG that the Mermaid renderer emits is wrapped. Inline icons carry
 * no `role`, so they are left where they are.
 */
export function wrapDiagrams() {
  return function transformer(tree) {
    visit(tree, 'element', (node, index, parent) => {
      if (node.tagName !== 'svg' || !parent || index === undefined) return;
      if (node.properties?.role !== 'graphics-document document') return;

      parent.children[index] = {
        type: 'element',
        tagName: 'figure',
        properties: { className: [WRAPPER_CLASS] },
        children: [node],
      };

      // The subtree is already final; descending into it would find the same
      // element again and wrap it a second time.
      return SKIP;
    });
  };
}
