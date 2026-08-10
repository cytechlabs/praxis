# Documentation site

Build tooling for the Praxis documentation. **The content is not here.** It
lives in `docs/` at the repository root, as plain Markdown that reads correctly
both on this site and in the repository.

## One source, two mount points

`docs/` produces two outputs from the same content and the same build command.
They differ only in the URL prefix they are served from:

| Output | Base | Served as |
|---|---|---|
| `docs-site/dist` | `/` | the public site at `docs.praxisfleet.com` |
| `frontend-next/public/help` | `/help` | the copy inside the frontend image |

Astro bakes the mount point into every emitted URL, so one byte-identical
directory cannot serve both a site rooted at `/` and one rooted at `/help`.
What is guaranteed instead is that neither output can drift from the other,
because both come from one source and CI proves it:

- **Determinism.** `check-docs-bundle.mjs` rebuilds the bundled copy into a
  temporary directory and fails if the committed bytes differ.
- **Parity.** The same check compares the two builds page by page, after
  normalising the base prefix and content hashes, and fails if any rendered
  text differs.

### Why the bundled copy is committed

The frontend production image is built with `frontend-next/` as its Docker
build context, so nothing in the image build can reach `docs/`. Committing the
compiled output under `frontend-next/public/help/` is what puts documentation
into the released image at all. The determinism gate is what keeps that
committed artifact honest.

Treat `frontend-next/public/help/` as generated. Do not edit it; edit `docs/`
and rebuild.

## Working on the documentation

```sh
cd docs-site
npm ci

npm run dev              # local preview at /
npm run build            # both outputs
npm run build:public     # public site only
npm run build:bundled    # regenerate the committed bundled copy
npm run verify           # everything CI runs
```

After changing anything in `docs/`, regenerate and commit the bundled copy:

```sh
node scripts/build-docs.mjs --bundled
```

## Adding a page

1. Add `docs/<slug>.md` with `title` and `description` frontmatter, and no
   top-level heading in the body; the title comes from frontmatter.
2. Link to neighbouring pages as `other-page.md`, which stays clickable in the
   repository and is rewritten to a routed, base-aware URL at build time.
   Site-absolute links are rejected because they cannot be correct at both
   mount points.
3. Add the slug to a group in `src/sidebar.mjs`.
4. Register it in the reviewed inventory:
   `node scripts/check-docs-public-content.mjs --write`.
5. Rebuild the bundled copy and commit it.

Pages live flat in `docs/` on purpose, so a documentation URL never changes
because a page was regrouped. Slugs must not contain a dot; the application's
`/help` rewrite treats a dot as an asset.

Only top-level `docs/*.md` is published. Subdirectories are never routed, and
`src/published.mjs` names the top-level files that stay unpublished, which is
where maintainer runbooks live.

## Publishing to Cloudflare Pages

Nothing in this repository deploys. A branch build and a pull request run the
checks and stop; publication is a separate, deliberate action.

### One-time project setup

Create a Pages project connected to this repository, with:

| Setting | Value |
|---|---|
| Framework preset | None |
| Build command | `cd docs-site && npm ci && node ../scripts/build-docs.mjs --public` |
| Build output directory | `docs-site/dist` |
| Root directory | repository root |
| Node version | `22`, via a `NODE_VERSION` environment variable |

The build needs no secrets and makes no network calls beyond installing
dependencies.

### Custom domain

Add `docs.praxisfleet.com` as a custom domain on the Pages project and let
Cloudflare create the CNAME. Cloudflare issues and renews the certificate.
Extensionless URLs such as `/install` resolve to `install/index.html`
natively, and `404.html` is served with a 404 status.

### Web analytics, if wanted

Cloudflare Web Analytics is cookie-free and collects no personal data. Enable
it on the Pages project rather than by adding a script to the site: the
injected beacon must not become part of the build, or it would ship inside the
application image and try to phone home from an offline deployment.

### Verification that needs a real deployment

These cannot be checked before the site is live, and should be confirmed after
the first publish:

- `docs.praxisfleet.com` resolves and serves over HTTPS with a valid
  certificate;
- extensionless deep links resolve, and a refresh on one still works;
- an unknown path returns the 404 page with a 404 status; and
- search returns results on the deployed origin.

## Public-only delivery metadata

The public build sets `PRAXIS_DOCS_SITE` to `https://docs.praxisfleet.com`,
which produces a canonical URL on every page and a sitemap. The bundled build
leaves it unset and gets neither: a canonical pointing at the public origin
would be wrong inside an operator's own deployment, and a sitemap of public
URLs is dead weight in an offline bundle. The origin is defined once, as
`PUBLIC_SITE` in `scripts/build-docs.mjs`.

Combining `PRAXIS_DOCS_SITE` with a mount point is refused at build time, so
the public origin cannot leak into the bundled copy by an inherited
environment variable.

These two files, `sitemap-index.xml` and `sitemap-0.xml`, plus the canonical
and `og:url` tags, are the only permitted differences between the outputs.
`check-docs-bundle.mjs` allows exactly them, asserts the public canonicals and
sitemap URLs use the docs origin, and asserts no bundled page carries a
canonical or mentions the public origin at all. Rendered content and links are
still compared page by page.
