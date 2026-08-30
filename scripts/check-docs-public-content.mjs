#!/usr/bin/env node
/**
 * Guards what the public documentation site is allowed to contain.
 *
 * The site is published on the open web and shipped inside the application
 * image, so a page reaching it is a release decision. This checks:
 *
 *   1. the routed page set matches the reviewed inventory in
 *      docs-site/published-routes.json;
 *   2. every published page is reachable from the sidebar, and no page routes
 *      out of the material that is deliberately kept unpublished;
 *   3. no published page carries issue identifiers, internal process
 *      language, release-planning language, or non-ASCII punctuation;
 *   4. no published page, and no emitted page payload, carries credential
 *      material, a personal filesystem path, or a private workspace name; and
 *   5. neither the source nor either build contains an em dash.
 *
 * The checks in (3) read prose only, because a fenced example may legitimately
 * discuss things prose should not. The checks in (4) read the complete source
 * including fenced blocks, because a command or sample output is exactly where
 * a real token or a copied home directory leaks. The check in (5) reads
 * everything, including the rendered output, because an em dash introduced by
 * a component or a theme string ships just as visibly as one in a document.
 *
 * Usage:
 *   node scripts/check-docs-public-content.mjs
 *   node scripts/check-docs-public-content.mjs --self-test   check the checker
 *   node scripts/check-docs-public-content.mjs --write       update the inventory
 */

import { execFileSync } from 'node:child_process';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import zlib from 'node:zlib';

import { DOCS_DIR, listPublishedSlugs } from '../docs-site/src/published.mjs';
import { sidebar } from '../docs-site/src/sidebar.mjs';

const REPO = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const INVENTORY = path.join(REPO, 'docs-site', 'published-routes.json');
const PUBLIC_OUT = path.join(REPO, 'docs-site', 'dist');
const BUNDLED_OUT = path.join(REPO, 'frontend-next', 'public', 'help');

/** Pages that may be published without a sidebar entry. */
const UNLISTED_BY_DESIGN = new Set(['index']);

/**
 * Documents that predate the ASCII rule and still contain diagrams or
 * typographic punctuation. Nothing may be added here; shrink it instead.
 *
 * The allowance is for characters that carry meaning a reader can see, such as
 * a box-drawing diagram or a comparison operator. It never covers the
 * punctuation in PUNCTUATION_CHECKS, which is rejected everywhere.
 */
const LEGACY_NON_ASCII = new Set([
  'agent-capability-matrix',
  'agent-protocol',
  'airgap',
  'audit-schema',
  'browser-support',
  'compliance-map',
  'oidc-setup',
  'production-hardening',
  'remediation-workflow',
  'scaling-assessment-500-hosts',
  'support-matrix',
]);

/**
 * Directories under `docs/` that hold material for people working on the
 * repository rather than people running Praxis. They are unrouted by
 * construction, and a published page must not send a reader to one.
 *
 * `ui-review` is named even though a given checkout may not have it, for the
 * same reason `published.mjs` names the local working files it excludes: the
 * rule has to read the same on every machine.
 */
const UNROUTED_AREAS = ['maintainers', 'contributors', 'design', 'audits', 'ui-review'];

/**
 * Account names that are generic examples rather than a real person. A home
 * directory naming one of these is documentation, not a leak.
 */
const PLACEHOLDER_ACCOUNTS =
  'user|username|youruser|your-user|someone|operator|admin|praxis|ubuntu|debian|root';

/**
 * Checked against prose only. A fenced example may legitimately contain words
 * that should not appear in the surrounding text.
 */
const PROSE_CHECKS = [
  { name: 'issue identifier', pattern: /\bPRA-\d+\b/g },
  {
    name: 'milestone provenance',
    pattern: /\b(?:introduced|added|shipped|delivered) in M\d+\b/gi,
  },
  {
    name: 'internal process language',
    pattern: /\b(?:Codex|Claude|worker report|slice handoff|supplement)\b/g,
  },
  {
    // The documentation describes the release it ships with. A page that
    // sorts behavior into what exists now and what is meant to come later
    // stops being true the moment the plan changes, and it reads as a promise
    // to the person deciding whether to deploy. A present limit is still
    // worth stating: say what Praxis does not do, not when it might.
    name: 'release-planning language',
    pattern:
      /\b(?:pre-1\.0|post-1\.0|roadmap|coming soon|at launch|pre-launch|launch (?:blocker|step|promise|wording)|launch-incompatible|follow-up PRAs?|future (?:release|version|milestone|work|development|capability|execution)|not yet (?:implemented|supported|available|shipped|first-class)|will (?:be added|ship|arrive|introduce|refactor|replace|keep adding)|planned,? not|planned for a|deferred (?:past|until|to a)|tracked as (?:a )?follow-up)\b/gi,
  },
  {
    // A status banner on a published page is a note to the author, and a page
    // that calls itself a draft undercuts everything on it.
    name: 'draft status banner',
    pattern: /^\**Status:?\**\s*\**(?:Draft|WIP|Work in progress|Proposed)\b/gim,
  },
  {
    name: 'milestone provenance token',
    pattern: /\b(?:pre-|post-)?M(?:[1-9]|1\d|2\d)\b(?=[\s,.);:]|$)/g,
  },
];

/**
 * Punctuation that never publishes, in any document and in either build.
 *
 * The em dash is the one character the documentation set has repeatedly
 * reintroduced, and it is invisible in review. Rewriting the sentence is the
 * fix; substituting a hyphen is not, which is why this is a gate and not a
 * formatter.
 */
const PUNCTUATION_CHECKS = [{ name: 'em dash', pattern: /\u2014/gu }];

/**
 * Checked against prose with inline code removed, because the Markdown
 * processor turns a free-standing double hyphen into an em dash. The source
 * looks ASCII and the published page is not, so this names the document rather
 * than making the author work backwards from an emitted file. Option flags such
 * as `--profile` are inside code and are left alone.
 */
const RENDERED_PUNCTUATION_CHECKS = [
  { name: 'double hyphen that renders as an em dash', pattern: /(?:^|\s)--(?=\s|$)/gm },
];

/**
 * Paths into the unrouted areas. A reader on the site or in the bundled help
 * cannot open one, so naming it in a published page is a dead reference.
 */
const BOUNDARY_CHECKS = [
  {
    name: 'unrouted documentation path',
    pattern: new RegExp(
      String.raw`\b(?:docs/)?(?:${UNROUTED_AREAS.join('|')})/[A-Za-z0-9._-]+\.md\b`,
      'g',
    ),
  },
];

/**
 * Checked against the complete source including fenced blocks, and against
 * every emitted page payload. Each pattern targets material that is never
 * correct to publish, in prose or in an example.
 */
const SECRET_CHECKS = [
  {
    name: 'private key block',
    pattern: /-----BEGIN (?:RSA |EC |DSA |OPENSSH |PGP )?PRIVATE KEY-----/g,
  },
  {
    name: 'GitHub token',
    pattern: /\bgh[pousr]_[A-Za-z0-9]{36,}\b|\bgithub_pat_[A-Za-z0-9_]{22,}\b/g,
  },
  { name: 'AWS access key id', pattern: /\bAKIA[0-9A-Z]{16}\b/g },
  { name: 'Slack token', pattern: /\bxox[baprs]-[A-Za-z0-9-]{10,}\b/g },
  {
    name: 'Vault or OpenBao token',
    pattern: /\bhv[sb]\.[A-Za-z0-9_-]{24,}\b/g,
  },
  {
    // The documented placeholder is a run of X characters, which stays legal.
    name: 'Praxis activation token',
    pattern: /\bpraxis_(?!X+\b)[A-Za-z0-9]{20,}\b/g,
  },
  {
    name: 'personal home directory',
    pattern: new RegExp(
      String.raw`/home/(?!(?:${PLACEHOLDER_ACCOUNTS})\b)(?![<$\{])[a-z][a-z0-9._-]*`,
      'g',
    ),
  },
  {
    name: 'personal Windows profile',
    pattern: new RegExp(
      String.raw`[A-Z]:\\Users\\(?!(?:${PLACEHOLDER_ACCOUNTS})\b)(?![<%])[A-Za-z][A-Za-z0-9._-]*`,
      'g',
    ),
  },
  {
    name: 'private workspace path',
    pattern: /\b(?:project-docs|claude-codex)\/|(?:^|\s)\.secrets\//g,
  },
];

/**
 * Directories and files under `docs/` and `docs-site/` that are build output
 * rather than something a person wrote. `dist/` and `diagrams/` are produced by
 * the documentation build, and a lockfile is produced by the package manager.
 */
const GENERATED_SOURCES = ['docs-site/dist/', 'docs-site/diagrams/', 'docs-site/package-lock.json'];

/** Extensions holding text a person authored. Binary assets are skipped. */
const AUTHORED_EXTENSIONS = new Set([
  '.md', '.mdx', '.astro', '.mjs', '.js', '.ts', '.tsx', '.css', '.json', '.py', '.csv', '.txt',
  '.sh', '.yml', '.yaml',
]);

/**
 * Authored documentation sources, selected from repository-relative paths.
 *
 * Every one of these is a file the punctuation rule applies to, whether or not
 * it publishes. An em dash in `docs/maintainers/` is as much a hygiene failure
 * as one on a routed page; the routed set is a publishing decision, not a
 * writing-style boundary. Exported so the self-test can prove the selection
 * covers unrouted material rather than only proving the regex works.
 */
export function documentationSources(paths) {
  return paths
    .map((entry) => entry.split(path.sep).join('/'))
    .filter((rel) => {
      if (!rel.startsWith('docs/') && !rel.startsWith('docs-site/')) return false;
      if (rel.includes('/node_modules/')) return false;
      if (GENERATED_SOURCES.some((prefix) => rel === prefix || rel.startsWith(prefix))) return false;
      return AUTHORED_EXTENSIONS.has(path.posix.extname(rel));
    })
    .sort();
}

/**
 * The authored documentation sources in this checkout.
 *
 * Version control decides membership, so the set is identical on every machine
 * at a given commit. `--others --exclude-standard` includes a file that is
 * written but not yet staged, which is where a new em dash actually arrives,
 * and excludes ignored local working files. A path that git still lists but
 * that no longer exists on disk is a staged deletion.
 */
function trackedDocumentationSources() {
  const listed = execFileSync(
    'git',
    ['ls-files', '--cached', '--others', '--exclude-standard', '--', 'docs', 'docs-site'],
    { cwd: REPO, encoding: 'utf8' },
  ).split('\n').filter(Boolean);

  return documentationSources(listed).filter((rel) => fs.existsSync(path.join(REPO, rel)));
}

/** Fenced blocks removed, for the prose-only checks. */
function proseOf(text) {
  return text.replace(/^```[\s\S]*?^```/gm, '');
}

/** Prose with inline code spans removed as well, for punctuation. */
function proseTextOf(text) {
  return proseOf(text).replace(/`[^`\n]*`/g, '');
}

/** Run one check family over one body of text. */
function scan(checks, text, describe, problems) {
  for (const { name, pattern } of checks) {
    const hits = [...text.matchAll(pattern)].map((m) => m[0].trim());
    if (hits.length > 0) {
      problems.push(`${describe} contains ${name}: ${[...new Set(hits)].slice(0, 3).join(', ')}`);
    }
  }
}

function sidebarSlugs(items, found = new Set()) {
  for (const item of items) {
    if (typeof item === 'string') found.add(item);
    else if (item.slug) found.add(item.slug);
    if (Array.isArray(item.items)) sidebarSlugs(item.items, found);
  }
  return found;
}

function walk(dir, found = []) {
  for (const entry of fs.readdirSync(dir, { withFileTypes: true })) {
    const full = path.join(dir, entry.name);
    if (entry.isDirectory()) walk(full, found);
    else found.push(full);
  }
  return found;
}

/**
 * Every textual payload a reader can receive from a build: the rendered pages,
 * and the search fragments, which carry the full text of every page. Markup is
 * stripped as well as kept, because a token split across highlighting spans is
 * only visible once the tags are removed.
 */
function* emittedPayloads(distDir) {
  for (const file of walk(distDir)) {
    const rel = path.relative(distDir, file);

    if (file.endsWith('.html')) {
      const raw = fs.readFileSync(file, 'utf8');
      yield [rel, raw];
      yield [`${rel} (text)`, raw.replace(/<[^>]+>/g, '')];
      continue;
    }

    if (file.endsWith('.pf_fragment')) {
      yield [rel, zlib.gunzipSync(fs.readFileSync(file)).toString('utf8')];
      continue;
    }

    if (/\.(json|txt|xml)$/.test(file) && !rel.startsWith(`_astro${path.sep}`)) {
      yield [rel, fs.readFileSync(file, 'utf8')];
    }
  }
}

/* ------------------------------------------------------------------ */
/* Self-test: the checker has to fail on real leaks and pass on the    */
/* placeholders the documentation legitimately uses.                   */
/* ------------------------------------------------------------------ */

// Built at runtime so no credential-shaped literal exists in this file.
const FAKE = {
  githubToken: `ghp_${'A1b2C3d4E5'.repeat(4)}`,
  awsKey: `AKIA${'QWERTYUIOPASDFGH'}`,
  vaultToken: `hvs.${'CAESIJ'.repeat(5)}`,
  praxisToken: `praxis_${'k3Jd9Fm2Qp7Zx1Vb8Nt4'}`,
};

const SELF_TEST_CASES = [
  // Must be rejected, and each is inside a fenced block on purpose.
  {
    name: 'GitHub token in a fence',
    source: `# x\n\n\`\`\`sh\nexport GHCR_PAT=${FAKE.githubToken}\n\`\`\`\n`,
    expect: 'GitHub token',
  },
  {
    name: 'AWS key in a fence',
    source: `\`\`\`sh\naws configure set aws_access_key_id ${FAKE.awsKey}\n\`\`\`\n`,
    expect: 'AWS access key id',
  },
  {
    name: 'Vault token in a fence',
    source: `\`\`\`sh\nexport VAULT_TOKEN=${FAKE.vaultToken}\n\`\`\`\n`,
    expect: 'Vault or OpenBao token',
  },
  {
    name: 'activation token in a fence',
    source: `\`\`\`sh\ncurl -H "X-Praxis-Activation-Token: ${FAKE.praxisToken}" ...\n\`\`\`\n`,
    expect: 'Praxis activation token',
  },
  {
    name: 'personal home directory in a fence',
    source: '```sh\ncd /home/chris/repos/praxis\n```\n',
    expect: 'personal home directory',
  },
  {
    name: 'personal home directory in prose',
    source: 'Run it from /home/dfreeman/praxis and retry.\n',
    expect: 'personal home directory',
  },
  {
    name: 'private key block in a fence',
    source: '```text\n-----BEGIN OPENSSH PRIVATE KEY-----\nb3BlbnNz\n```\n',
    expect: 'private key block',
  },
  {
    name: 'private workspace path in a fence',
    source: '```sh\ncp notes.md project-docs/notes.md\n```\n',
    expect: 'private workspace path',
  },
  {
    name: 'Windows profile path in a fence',
    source: '```text\nC:\\Users\\Christopher\\praxis\n```\n',
    expect: 'personal Windows profile',
  },

  // Must be accepted. These all appear in the real documentation.
  {
    name: 'documented activation token placeholder',
    source: '```sh\ncurl -H "X-Praxis-Activation-Token: praxis_XXXXXXXX..." ...\n```\n',
    expect: null,
  },
  {
    name: 'environment variable names without values',
    source:
      '```sh\nexport VAULT_TOKEN="$VAULT_TOKEN"\necho "$GHCR_PAT" | docker login ghcr.io\n```\n',
    expect: null,
  },
  {
    name: 'required environment variables in prose',
    source:
      'Set `SECRET_KEY`, `POSTGRES_PASSWORD`, `ADMIN_PASSWORD`, and `PRAXIS_LICENSE_PUBLIC_KEY`.\n',
    expect: null,
  },
  {
    name: 'generic home directories',
    source: '```sh\nsudo -u ubuntu ls /home/ubuntu\nls /home/<user>/.ssh\nls /home/$USER\n```\n',
    expect: null,
  },
  {
    name: 'digest and checksum placeholders',
    source:
      '```sh\ndocker pull ghcr.io/cytechlabs/praxis-backend@sha256:<digest>\nsha256sum -c checksums.txt\n```\n',
    expect: null,
  },
  {
    name: 'agent artifact directory',
    source: 'Drop the assets into `/opt/praxis/agent-artifacts`.\n',
    expect: null,
  },

  // Punctuation. Rejected wherever it appears, prose or fence.
  {
    name: 'em dash in prose',
    checks: PUNCTUATION_CHECKS,
    source: 'Praxis records the plan \u2014 it does not run it.\n',
    expect: 'em dash',
  },
  {
    name: 'em dash in a fence',
    checks: PUNCTUATION_CHECKS,
    source: '```text\nstate \u2014 pending\n```\n',
    expect: 'em dash',
  },
  {
    name: 'hyphen and ASCII dash run',
    checks: PUNCTUATION_CHECKS,
    source: 'Use a well-known port. The plan is ready, and nothing dispatches.\n',
    expect: null,
  },
  {
    name: 'double hyphen in prose',
    checks: RENDERED_PUNCTUATION_CHECKS,
    source: 'RPO/RTO targets -- see the contract above.\n',
    expect: 'double hyphen',
  },
  {
    name: 'option flag in inline code',
    checks: RENDERED_PUNCTUATION_CHECKS,
    prose: true,
    source: 'Run it with `--profile proxy` and `docker compose --profile bundled up`.\n',
    expect: null,
  },
  {
    name: 'thematic break',
    checks: RENDERED_PUNCTUATION_CHECKS,
    source: 'One paragraph.\n\n---\n\nAnother paragraph.\n',
    expect: null,
  },

  // Release-planning language. Prose only.
  {
    name: 'future release promise',
    checks: PROSE_CHECKS,
    prose: true,
    source: 'A future release will add the runner that consumes this state.\n',
    expect: 'release-planning language',
  },
  {
    name: 'post-1.0 sorting',
    checks: PROSE_CHECKS,
    prose: true,
    source: 'These are candidates for post-1.0 promotion.\n',
    expect: 'release-planning language',
  },
  {
    name: 'launch wording',
    checks: PROSE_CHECKS,
    prose: true,
    source: 'The free tier is set at launch, on purpose.\n',
    expect: 'release-planning language',
  },
  {
    name: 'draft status banner',
    checks: PROSE_CHECKS,
    prose: true,
    source: '**Status:** Draft.\n',
    expect: 'draft status banner',
  },
  {
    name: 'milestone token',
    checks: PROSE_CHECKS,
    prose: true,
    source: 'The thin agent (M13) is an outbound-only daemon.\n',
    expect: 'milestone provenance token',
  },
  {
    name: 'present-tense limit',
    checks: PROSE_CHECKS,
    prose: true,
    source:
      'Praxis does not execute remediation. The readiness gate records intent; ' +
      'nothing is dispatched to a host.\n',
    expect: null,
  },
  {
    name: 'deferred reboot behavior',
    checks: PROSE_CHECKS,
    prose: true,
    source: 'The policy decides whether the reboot is deferred into the bound window.\n',
    expect: null,
  },
  {
    name: 'draft plan state',
    checks: PROSE_CHECKS,
    prose: true,
    source: 'A rebuild supersedes the row and creates a new current draft plan.\n',
    expect: null,
  },
  {
    name: 'unit abbreviation near a number',
    checks: PROSE_CHECKS,
    prose: true,
    source: 'Allow 512 MB of headroom and a 30 s scheduler interval.\n',
    expect: null,
  },

  // Route boundary.
  {
    name: 'link into an unrouted area',
    checks: BOUNDARY_CHECKS,
    source: 'See [the release checklist](maintainers/release-checklist.md).\n',
    expect: 'unrouted documentation path',
  },
  {
    name: 'repository-qualified unrouted path',
    checks: BOUNDARY_CHECKS,
    source: 'The branch model is in docs/contributors/branching-model.md.\n',
    expect: 'unrouted documentation path',
  },
  {
    name: 'link to a published page',
    checks: BOUNDARY_CHECKS,
    source: 'See [backup and restore](backup-restore.md#restoring).\n',
    expect: null,
  },
];

/**
 * Which paths the punctuation sweep claims. Stated as a fixture rather than
 * read from disk, so it proves the rule and not the contents of one checkout.
 *
 * The point of the first group is that being unrouted buys no exemption: a
 * release runbook, a branching note, a design reference, and an audit README
 * are all authored documentation and all get swept.
 */
const SOURCE_SELECTION_CASES = [
  // Unrouted, and covered anyway.
  { path: 'docs/maintainers/release-checklist.md', selected: true },
  { path: 'docs/maintainers/dependency-security-policy.md', selected: true },
  { path: 'docs/contributors/branching-model.md', selected: true },
  { path: 'docs/design/ui-primitives.md', selected: true },
  { path: 'docs/audits/py-w2000/README.md', selected: true },
  { path: 'docs/audits/py-w2000/scan_unused_imports.py', selected: true },

  // Routed pages and authored site sources.
  { path: 'docs/install.md', selected: true },
  { path: 'docs-site/src/components/Footer.astro', selected: true },
  { path: 'docs-site/src/version.mjs', selected: true },
  { path: 'docs-site/astro.config.mjs', selected: true },
  { path: 'docs-site/published-routes.json', selected: true },

  // Build output, dependencies, and binary assets.
  { path: 'docs-site/dist/install/index.html', selected: false },
  { path: 'docs-site/diagrams/2e6c1c4bb6fe77a2.svg', selected: false },
  { path: 'docs-site/package-lock.json', selected: false },
  { path: 'docs-site/node_modules/astro/package.json', selected: false },
  { path: 'docs/assets/praxis-demo.mp4', selected: false },
  { path: 'docs/assets/readme/fleet-dashboard.png', selected: false },

  // Outside the documentation trees.
  { path: 'frontend-next/public/help/install/index.html', selected: false },
  { path: 'backend/app/services/package_service.py', selected: false },
];

function selectionSelfTest(failures) {
  const selected = new Set(documentationSources(SOURCE_SELECTION_CASES.map((c) => c.path)));

  for (const testCase of SOURCE_SELECTION_CASES) {
    if (selected.has(testCase.path) !== testCase.selected) {
      failures.push(
        `source selection: "${testCase.path}" should ${testCase.selected ? '' : 'not '}be swept`,
      );
    }
  }
}

function selfTest() {
  const failures = [];

  for (const testCase of SELF_TEST_CASES) {
    const problems = [];
    const checks = testCase.checks ?? SECRET_CHECKS;
    const source = testCase.prose ? proseTextOf(testCase.source) : testCase.source;
    scan(checks, source, 'fixture', problems);

    const matched =
      testCase.expect !== null && problems.some((p) => p.includes(testCase.expect));

    if (testCase.expect && !matched) {
      failures.push(`${testCase.name}: expected "${testCase.expect}", got ${problems.length === 0 ? 'nothing' : problems.join('; ')}`);
    }
    if (!testCase.expect && problems.length > 0) {
      failures.push(`${testCase.name}: expected no finding, got ${problems.join('; ')}`);
    }
  }

  selectionSelfTest(failures);

  if (failures.length > 0) {
    console.error(`Public content self-test failed (${failures.length}):\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }

  const rejected = SELF_TEST_CASES.filter((c) => c.expect).length;
  const unrouted = SOURCE_SELECTION_CASES.filter(
    (c) => c.selected && !c.path.startsWith('docs-site/') && c.path.slice(5).includes('/'),
  ).length;
  console.log(
    `Public content self-test OK: ${rejected} leak fixtures rejected, ` +
      `${SELF_TEST_CASES.length - rejected} placeholder fixtures allowed, ` +
      `${SOURCE_SELECTION_CASES.length} source paths sorted correctly ` +
      `(${unrouted} of them unrouted documentation that is swept anyway).`,
  );
}

/* ------------------------------------------------------------------ */

function writeInventory(slugs) {
  fs.writeFileSync(INVENTORY, `${JSON.stringify({ routes: slugs }, null, 2)}\n`);
  console.log(`Wrote ${slugs.length} routes to ${path.relative(REPO, INVENTORY)}.`);
}

// 1. Reviewed inventory.
function checkInventory(slugs, problems) {
  if (!fs.existsSync(INVENTORY)) {
    console.error(
      `Missing ${path.relative(REPO, INVENTORY)}. ` +
        'Run: node scripts/check-docs-public-content.mjs --write',
    );
    process.exit(1);
  }

  const expected = JSON.parse(fs.readFileSync(INVENTORY, 'utf8')).routes;
  for (const slug of slugs) {
    if (!expected.includes(slug)) {
      problems.push(`docs/${slug}.md would be published but is not in the reviewed inventory`);
    }
  }
  for (const slug of expected) {
    if (!slugs.includes(slug)) {
      problems.push(`the inventory lists "${slug}", which no longer publishes`);
    }
  }
}

// 2. Sidebar reachability.
function checkSidebarReachability(slugs, problems) {
  const listed = sidebarSlugs(sidebar);
  for (const slug of slugs) {
    if (!listed.has(slug) && !UNLISTED_BY_DESIGN.has(slug)) {
      problems.push(`docs/${slug}.md publishes but no sidebar group lists it`);
    }
  }
}

// 3 and 4. Source hygiene.
function checkSourceHygiene(slugs, problems) {
  for (const slug of slugs) {
    const file = path.join(DOCS_DIR, `${slug}.md`);
    const raw = fs.readFileSync(file, 'utf8');
    const where = `docs/${slug}.md`;

    scan(PROSE_CHECKS, proseOf(raw), where, problems);
    scan(SECRET_CHECKS, raw, where, problems);
    scan(PUNCTUATION_CHECKS, raw, where, problems);
    scan(RENDERED_PUNCTUATION_CHECKS, proseTextOf(raw), where, problems);
    scan(BOUNDARY_CHECKS, raw, where, problems);

    if (!LEGACY_NON_ASCII.has(slug)) {
      const nonAscii = [...new Set([...raw].filter((c) => c.charCodeAt(0) > 127))];
      if (nonAscii.length > 0) {
        problems.push(`${where} contains non-ASCII characters: ${nonAscii.slice(0, 8).join(' ')}`);
      }
    }

    if (!/^---\n[\s\S]*?\ntitle:|^---\ntitle:/m.test(raw)) {
      problems.push(`${where} has no title in its frontmatter`);
    }

    if (/^#\s/m.test(proseOf(raw).replace(/^---[\s\S]*?\n---\n/, ''))) {
      problems.push(`${where} has a top-level heading in its body; the title comes from frontmatter`);
    }

    if (slug.includes('.')) {
      problems.push(
        `${where} has a dot in its slug, which the application's /help rewrite treats as an asset`,
      );
    }
  }
}

function checkLegacyNonAsciiAllowance(slugs, problems) {
  for (const stale of LEGACY_NON_ASCII) {
    if (!slugs.includes(stale)) {
      problems.push(`LEGACY_NON_ASCII lists "${stale}", which is no longer published; remove the entry`);
      continue;
    }
    // The allowance only shrinks. A document that has since been cleaned must
    // give it up, or the list stops describing anything and the next document
    // to regress inside it goes unnoticed.
    const raw = fs.readFileSync(path.join(DOCS_DIR, `${stale}.md`), 'utf8');
    if (![...raw].some((c) => c.charCodeAt(0) > 127)) {
      problems.push(`LEGACY_NON_ASCII lists "${stale}", which is now pure ASCII; remove the entry`);
    }
  }
}

// 5. Punctuation across every authored documentation source, published or
//    not. The routed pages above are already covered; this reaches the
//    maintainer, contributor, design, and audit material that is deliberately
//    unrouted but still shipped in the repository.
function scanAuthoredSources(problems) {
  let sourcesScanned = 0;
  for (const rel of trackedDocumentationSources()) {
    sourcesScanned += 1;
    scan(PUNCTUATION_CHECKS, fs.readFileSync(path.join(REPO, rel), 'utf8'), rel, problems);
  }
  return sourcesScanned;
}

// 6. The same secret and punctuation checks over everything either build
//    emits, and the route boundary as it exists on disk.
function scanEmittedPayloads(problems) {
  let payloadsScanned = 0;
  for (const [label, dist] of [
    ['public site', PUBLIC_OUT],
    ['bundled copy', BUNDLED_OUT],
  ]) {
    if (!fs.existsSync(dist)) {
      problems.push(`no ${label} build at ${path.relative(REPO, dist)}; run scripts/build-docs.mjs`);
      continue;
    }
    for (const [rel, text] of emittedPayloads(dist)) {
      payloadsScanned += 1;
      scan(SECRET_CHECKS, text, `${label} ${rel}`, problems);
      scan(PUNCTUATION_CHECKS, text, `${label} ${rel}`, problems);

      const top = rel.split(path.sep)[0];
      if (UNROUTED_AREAS.includes(top)) {
        problems.push(`${label} emitted "${rel}", which is inside unrouted area "${top}"`);
      }
    }
  }
  return payloadsScanned;
}

function reportProblems(problems, slugs, sourcesScanned, payloadsScanned) {
  if (problems.length > 0) {
    console.error(`Public content check failed (${problems.length} problems):\n`);
    for (const problem of problems.slice(0, 40)) console.error(`  ${problem}`);
    if (problems.length > 40) console.error(`  ... and ${problems.length - 40} more`);
    process.exit(1);
  }

  console.log(
    `Public content OK: ${slugs.length} published pages, all listed in the sidebar and the ` +
      `reviewed inventory; ${sourcesScanned} authored documentation sources and ` +
      `${payloadsScanned} emitted payloads scanned.`,
  );
}

function verifyPublishedContent(slugs) {
  const problems = [];

  checkInventory(slugs, problems);
  checkSidebarReachability(slugs, problems);
  checkSourceHygiene(slugs, problems);
  checkLegacyNonAsciiAllowance(slugs, problems);

  const sourcesScanned = scanAuthoredSources(problems);
  if (sourcesScanned === 0) {
    problems.push('no authored documentation sources were found; the punctuation sweep did nothing');
  }

  const payloadsScanned = scanEmittedPayloads(problems);

  reportProblems(problems, slugs, sourcesScanned, payloadsScanned);
}

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }

  const slugs = listPublishedSlugs();

  if (process.argv.includes('--write')) {
    writeInventory(slugs);
    return;
  }

  verifyPublishedContent(slugs);
}

main();
