#!/usr/bin/env node
/**
 * Guards what the public documentation site is allowed to contain.
 *
 * The site is published on the open web and shipped inside the application
 * image, so a page reaching it is a release decision. This checks:
 *
 *   1. the routed page set matches the reviewed inventory in
 *      docs-site/published-routes.json;
 *   2. every published page is reachable from the sidebar;
 *   3. no published page carries issue identifiers, internal process
 *      language, or non-ASCII punctuation; and
 *   4. no published page, and no emitted page payload, carries credential
 *      material, a personal filesystem path, or a private workspace name.
 *
 * The checks in (3) read prose only, because a fenced example may legitimately
 * discuss things prose should not. The checks in (4) read the complete source
 * including fenced blocks, because a command or sample output is exactly where
 * a real token or a copied home directory leaks.
 *
 * Usage:
 *   node scripts/check-docs-public-content.mjs
 *   node scripts/check-docs-public-content.mjs --self-test   check the checker
 *   node scripts/check-docs-public-content.mjs --write       update the inventory
 */

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
 */
const LEGACY_NON_ASCII = new Set([
  'access-revocation',
  'agent-capability-matrix',
  'agent-protocol',
  'airgap',
  'audit-schema',
  'backup-restore',
  'browser-support',
  'compliance-map',
  'demo-walkthrough-auditor',
  'demo-walkthrough-operator',
  'dependency-security-policy',
  'editions',
  'eol-data',
  'oidc-setup',
  'production-hardening',
  'remediation-workflow',
  'reporting-contract',
  'scaling-assessment-500-hosts',
  'security-model',
  'support-matrix',
  'upgrade-notes-1-0',
]);

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

/** Fenced blocks removed, for the prose-only checks. */
function proseOf(text) {
  return text.replace(/^```[\s\S]*?^```/gm, '');
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
];

function selfTest() {
  const failures = [];

  for (const testCase of SELF_TEST_CASES) {
    const problems = [];
    scan(SECRET_CHECKS, testCase.source, 'fixture', problems);

    const matched = problems.some((p) => p.includes(testCase.expect ?? ' '));

    if (testCase.expect && !matched) {
      failures.push(`${testCase.name}: expected "${testCase.expect}", got ${problems.length === 0 ? 'nothing' : problems.join('; ')}`);
    }
    if (!testCase.expect && problems.length > 0) {
      failures.push(`${testCase.name}: expected no finding, got ${problems.join('; ')}`);
    }
  }

  if (failures.length > 0) {
    console.error(`Public content self-test failed (${failures.length}):\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }

  const rejected = SELF_TEST_CASES.filter((c) => c.expect).length;
  console.log(
    `Public content self-test OK: ${rejected} leak fixtures rejected, ` +
      `${SELF_TEST_CASES.length - rejected} placeholder fixtures allowed.`,
  );
}

/* ------------------------------------------------------------------ */

function main() {
  if (process.argv.includes('--self-test')) {
    selfTest();
    return;
  }

  const slugs = listPublishedSlugs();

  if (process.argv.includes('--write')) {
    fs.writeFileSync(INVENTORY, `${JSON.stringify({ routes: slugs }, null, 2)}\n`);
    console.log(`Wrote ${slugs.length} routes to ${path.relative(REPO, INVENTORY)}.`);
    return;
  }

  const problems = [];

  // 1. Reviewed inventory.
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

  // 2. Sidebar reachability.
  const listed = sidebarSlugs(sidebar);
  for (const slug of slugs) {
    if (!listed.has(slug) && !UNLISTED_BY_DESIGN.has(slug)) {
      problems.push(`docs/${slug}.md publishes but no sidebar group lists it`);
    }
  }

  // 3 and 4. Source hygiene.
  for (const slug of slugs) {
    const file = path.join(DOCS_DIR, `${slug}.md`);
    const raw = fs.readFileSync(file, 'utf8');
    const where = `docs/${slug}.md`;

    scan(PROSE_CHECKS, proseOf(raw), where, problems);
    scan(SECRET_CHECKS, raw, where, problems);

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

  for (const stale of LEGACY_NON_ASCII) {
    if (!slugs.includes(stale)) {
      problems.push(`LEGACY_NON_ASCII lists "${stale}", which is no longer published; remove the entry`);
    }
  }

  // 5. The same secret checks over everything either build emits.
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
    }
  }

  if (problems.length > 0) {
    console.error(`Public content check failed (${problems.length} problems):\n`);
    for (const problem of problems.slice(0, 40)) console.error(`  ${problem}`);
    if (problems.length > 40) console.error(`  ... and ${problems.length - 40} more`);
    process.exit(1);
  }

  console.log(
    `Public content OK: ${slugs.length} published pages, all listed in the sidebar and the ` +
      `reviewed inventory; ${payloadsScanned} emitted payloads scanned for credential material.`,
  );
}

main();
