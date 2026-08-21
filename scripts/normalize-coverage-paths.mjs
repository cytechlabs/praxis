#!/usr/bin/env node
/**
 * Prepares a coverage report for upload and proves it describes real files in
 * this repository.
 *
 * Coverage tools write source paths relative to the directory their tests ran
 * in, while a coverage service resolves those paths against the repository
 * root. This rewrites the paths when a prefix is given, then fails unless every
 * path is a repository-relative file that exists in the checkout and the report
 * measured something. A report that silently describes nothing, or describes
 * files that are not in the analysed commit, is worse than no report at all.
 *
 * Go cover profiles are validated, never rewritten: they carry import paths,
 * and the coverage service maps those back to files using the module import
 * root. Passing that root here checks the same mapping against the checkout.
 *
 * Usage:
 *   node scripts/normalize-coverage-paths.mjs --format lcov --prefix frontend-next coverage/lcov.info
 *   node scripts/normalize-coverage-paths.mjs --format cobertura coverage-python.xml
 *   node scripts/normalize-coverage-paths.mjs --format go --import-root github.com/example/project coverage.out
 *   node scripts/normalize-coverage-paths.mjs --self-test
 */

import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const FORMATS = ['lcov', 'cobertura', 'go'];
const GO_BLOCK = /^(.+\.go):\d+\.\d+,\d+\.\d+ \d+ \d+$/;

function withPrefix(prefix, filePath) {
  return prefix ? `${prefix}/${filePath}` : filePath;
}

/** Rewrites the `SF:` records of an LCOV report and counts its line records. */
function rewriteLcov(source, prefix) {
  const paths = [];
  let measured = 0;

  const text = source
    .split('\n')
    .map((line) => {
      if (line.startsWith('SF:')) {
        const next = withPrefix(prefix, line.slice('SF:'.length).trim());
        paths.push(next);
        return `SF:${next}`;
      }
      if (line.startsWith('DA:')) measured += 1;
      return line;
    })
    .join('\n');

  return { text, paths, measured, problems: [] };
}

/** Rewrites the `filename` attributes of a Cobertura report. */
function rewriteCobertura(source, prefix) {
  const paths = [];

  const text = source.replace(/filename="([^"]*)"/g, (_match, filePath) => {
    const next = withPrefix(prefix, filePath);
    paths.push(next);
    return `filename="${next}"`;
  });

  return {
    text,
    paths,
    measured: (source.match(/<line number=/g) ?? []).length,
    problems: [],
  };
}

/** Maps the import paths of a Go cover profile back to repository paths. */
function readGoProfile(source, importRoot) {
  const paths = [];
  const problems = [];
  let measured = 0;

  for (const line of source.split('\n')) {
    const record = line.trim();
    if (record === '' || record.startsWith('mode:')) continue;

    const match = GO_BLOCK.exec(record);
    if (!match) {
      problems.push(`unparsable profile record: ${record}`);
      continue;
    }

    measured += 1;
    const importPath = match[1];
    if (!importPath.startsWith(`${importRoot}/`)) {
      problems.push(`${importPath} does not start with the import root ${importRoot}`);
      continue;
    }

    paths.push(importPath.slice(importRoot.length + 1));
  }

  return { text: source, paths, measured, problems };
}

/** Every reported path must name a file that exists under `repoRoot`. */
function validate(paths, repoRoot) {
  const problems = [];

  for (const filePath of new Set(paths)) {
    if (filePath === '') {
      problems.push('a source record has an empty path');
    } else if (filePath.startsWith('/') || /^[a-zA-Z]:[\\/]/.test(filePath)) {
      problems.push(`${filePath} is not repository relative`);
    } else if (filePath.split('/').includes('..')) {
      problems.push(`${filePath} escapes the repository root`);
    } else if (!fs.existsSync(path.join(repoRoot, filePath))) {
      problems.push(`${filePath} does not exist in the checkout`);
    }
  }

  return problems;
}

function shape(format, source, { prefix, importRoot }) {
  if (format === 'lcov') return rewriteLcov(source, prefix);
  if (format === 'cobertura') return rewriteCobertura(source, prefix);
  return readGoProfile(source, importRoot);
}

function parseArguments(argv) {
  const options = { format: null, prefix: '', importRoot: '', file: null, selfTest: false };

  for (let i = 0; i < argv.length; i += 1) {
    const arg = argv[i];
    if (arg === '--self-test') options.selfTest = true;
    else if (arg === '--format') options.format = argv[++i];
    else if (arg === '--prefix') options.prefix = argv[++i];
    else if (arg === '--import-root') options.importRoot = argv[++i];
    else if (arg.startsWith('--')) usage(`unknown option ${arg}`);
    else if (options.file === null) options.file = arg;
    else usage('only one report can be checked at a time');
  }

  if (options.selfTest) return options;
  if (!FORMATS.includes(options.format)) usage(`--format must be one of ${FORMATS.join(', ')}`);
  if (options.file === null) usage('no report file given');
  if (options.format === 'go' && !options.importRoot) usage('--format go needs --import-root');
  if (options.format === 'go' && options.prefix) usage('--format go cannot be rewritten with --prefix');

  return options;
}

function usage(reason) {
  console.error(`${reason}\n`);
  console.error('Usage: node scripts/normalize-coverage-paths.mjs --format <lcov|cobertura|go> [--prefix <dir>] [--import-root <path>] <report>');
  process.exit(2);
}

function writeFixture(root, relative) {
  const full = path.join(root, relative);
  fs.mkdirSync(path.dirname(full), { recursive: true });
  fs.writeFileSync(full, '');
}

const LCOV_FIXTURE = 'TN:\nSF:src/app.ts\nDA:1,1\nDA:2,0\nend_of_record\n';
const COBERTURA_FIXTURE =
  '<coverage><packages><classes>' +
  '<class filename="backend/app/service.py"><lines><line number="1" hits="1"/></lines></class>' +
  '</classes></packages></coverage>';
const GO_FIXTURE =
  'mode: atomic\n' +
  'github.com/example/project/agent/internal/tunnel/op.go:12.20,14.3 2 1\n';

function selfTest() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), 'coverage-paths-'));
  const failures = [];

  const expect = (name, problems, needle) => {
    const matched = problems.some((problem) => problem.includes(needle ?? ''));
    if (needle === null && problems.length > 0) {
      failures.push(`${name}: expected no problem, got ${problems.join('; ')}`);
    }
    if (needle !== null && !matched) {
      failures.push(`${name}: expected "${needle}", got ${problems.length === 0 ? 'nothing' : problems.join('; ')}`);
    }
  };

  const run = (format, source, options) => {
    const report = shape(format, source, { prefix: '', importRoot: '', ...options });
    return { ...report, problems: [...report.problems, ...validate(report.paths, root)] };
  };

  try {
    writeFixture(root, 'frontend-next/src/app.ts');
    writeFixture(root, 'backend/app/service.py');
    writeFixture(root, 'agent/internal/tunnel/op.go');

    const prefixed = run('lcov', LCOV_FIXTURE, { prefix: 'frontend-next' });
    expect('lcov with the workspace prefix', prefixed.problems, null);
    if (!prefixed.text.includes('SF:frontend-next/src/app.ts')) {
      failures.push('lcov with the workspace prefix: the prefix was not written back');
    }
    if (prefixed.measured !== 2) {
      failures.push(`lcov with the workspace prefix: expected 2 measured lines, got ${prefixed.measured}`);
    }

    expect('lcov without a prefix', run('lcov', LCOV_FIXTURE, {}).problems, 'does not exist in the checkout');
    expect(
      'lcov with an absolute path',
      run('lcov', 'SF:/tmp/app.ts\nDA:1,1\nend_of_record\n', {}).problems,
      'is not repository relative',
    );
    expect(
      'lcov escaping the repository',
      run('lcov', 'SF:../outside.ts\nDA:1,1\nend_of_record\n', {}).problems,
      'escapes the repository root',
    );

    const empty = run('lcov', 'TN:\n', {});
    if (empty.paths.length !== 0 || empty.measured !== 0) {
      failures.push('empty lcov: expected no sources and no measured lines');
    }

    expect('cobertura already rooted at the repository', run('cobertura', COBERTURA_FIXTURE, {}).problems, null);
    expect(
      'cobertura given a second prefix',
      run('cobertura', COBERTURA_FIXTURE, { prefix: 'backend' }).problems,
      'does not exist in the checkout',
    );

    expect('go profile under its import root', run('go', GO_FIXTURE, { importRoot: 'github.com/example/project' }).problems, null);
    expect(
      'go profile under a foreign import root',
      run('go', GO_FIXTURE, { importRoot: 'github.com/example/other' }).problems,
      'does not start with the import root',
    );
    expect(
      'go profile with a malformed record',
      run('go', 'mode: atomic\nnot a profile record\n', { importRoot: 'github.com/example/project' }).problems,
      'unparsable profile record',
    );
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }

  if (failures.length > 0) {
    console.error(`Coverage path self-test failed (${failures.length}):\n`);
    for (const failure of failures) console.error(`  ${failure}`);
    process.exit(1);
  }

  console.log('Coverage path self-test OK: prefixing, path validation, and Go import-root mapping behave as documented.');
}

function main() {
  const options = parseArguments(process.argv.slice(2));

  if (options.selfTest) {
    selfTest();
    return;
  }

  if (!fs.existsSync(options.file)) {
    console.error(`Coverage report ${options.file} does not exist.`);
    process.exit(1);
  }

  const source = fs.readFileSync(options.file, 'utf8');
  const report = shape(options.format, source, options);
  const problems = [...report.problems, ...validate(report.paths, REPO_ROOT)];

  if (report.paths.length === 0) problems.unshift('the report names no source files');
  if (report.measured === 0) problems.unshift('the report measured no code');

  if (problems.length > 0) {
    console.error(`Coverage path check failed for ${options.file} (${problems.length} problems):\n`);
    for (const problem of problems.slice(0, 20)) console.error(`  ${problem}`);
    if (problems.length > 20) console.error(`  ... and ${problems.length - 20} more`);
    process.exit(1);
  }

  if (options.prefix) fs.writeFileSync(options.file, report.text);

  const unique = new Set(report.paths).size;
  console.log(
    `Coverage paths OK: ${options.file} (${options.format}) covers ${unique} files ` +
      `with ${report.measured} measured records.`,
  );
}

main();
