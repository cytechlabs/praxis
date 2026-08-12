/**
 * How Mermaid fences in `docs/` become diagrams.
 *
 * A fence stays plain Mermaid source in the repository, which GitHub renders
 * natively. The documentation build replaces it with an inline SVG, so the
 * public site and the copy bundled at `/help` both show a picture with no
 * client-side script, no network request, and no change to the documentation
 * content security policy: an inline `<svg>` and its inline `<style>` are
 * already what the policy allows.
 *
 * `docs-site/src/styles/mermaid-render.css` explains why the font is pinned.
 * Everything else here exists for one of two reasons: legibility on the
 * dark-only theme, or reproducible output.
 */

/**
 * The stylesheet loaded into the render browser. It has to be a URL rather than
 * a path: the renderer links it into the page, and the relative `url()` inside
 * it only resolves against the stylesheet's own location.
 */
const RENDER_CSS = new URL('./styles/mermaid-render.css', import.meta.url);

/**
 * Palette, taken from `src/styles/praxis.css` so a diagram reads as part of the
 * page rather than as a pasted-in image. Signal Red is reserved for the trust
 * boundary a subgraph draws, which is the one thing in these diagrams that is
 * worth the accent.
 */
const THEME_VARIABLES = {
  background: '#09090b',
  primaryColor: '#0c0c0f',
  primaryBorderColor: '#3f3f46',
  primaryTextColor: '#f4f4f5',
  secondaryColor: '#171e28',
  tertiaryColor: '#0c0c0f',
  mainBkg: '#0c0c0f',
  nodeBorder: '#3f3f46',
  nodeTextColor: '#f4f4f5',
  textColor: '#f4f4f5',
  lineColor: '#a1a1aa',
  clusterBkg: '#09090b',
  clusterBorder: '#ce1b2b',
  titleColor: '#f4f4f5',
  edgeLabelBackground: '#09090b',
  fontSize: '15px',
};

export const mermaidRenderOptions = {
  // The SVG is written into the page, so nothing has to be fetched to see the
  // diagram and no separate asset can go missing from one of the two outputs.
  strategy: 'inline-svg',
  colorScheme: 'dark',
  css: RENDER_CSS,
  mermaidConfig: {
    theme: 'base',
    themeVariables: THEME_VARIABLES,
    // Arimo is the font the build measures with; Arial and Helvetica are
    // metric-compatible with it, so a reader who has neither still gets labels
    // laid out at the size the diagram was built for.
    fontFamily: 'Arimo, Arial, Helvetica, sans-serif',
    // Mermaid otherwise seeds element identifiers randomly, which would make
    // every build emit different bytes for unchanged source.
    deterministicIds: true,
    deterministicIDSeed: 'praxis-docs',
    // Labels are drawn as SVG text rather than HTML in a foreignObject. HTML
    // labels put each label in a box sized during the build and re-flowed by
    // the reader, and the line break in a multi-line label does not survive
    // being serialised out of the render browser and back into the page.
    htmlLabels: false,
    flowchart: {
      htmlLabels: false,
      // Keep the intrinsic size. A diagram several times wider than the
      // documentation column becomes unreadable when it is scaled to fit, so
      // the wrapper in `plugins/wrap-diagrams.mjs` scrolls it instead.
      useMaxWidth: false,
    },
  },
};
