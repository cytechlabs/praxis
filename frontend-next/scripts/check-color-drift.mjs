#!/usr/bin/env node
/*
 * PRA-268 color-drift guardrail.
 *
 * The foundation surfaces this slice owns (semantic tokens + shared primitives +
 * shell) must not use raw `red-*` or `blue-*` Tailwind utilities for semantic UI
 * roles, nor the retired `#DC2626`. Signal Red / danger / brand now come from
 * tokens (bg-danger, text-brand, ...); neutral primary/link/info come from
 * tokens too. This script FAILS if a banned raw color reappears in those paths.
 *
 * Scope is intentionally NARROW: only the foundation directories/files below.
 * Feature pages (~845 legacy red-/blue- usages) are out of scope until the
 * PRA-270+ page sweeps migrate them, so they are NOT scanned here.
 *
 * Exception path: append a `praxis-color-exception:` comment ON THE SAME LINE
 * for an unavoidable functional color case, e.g.
 *   className="fill-red-500" // praxis-color-exception: brand chart series
 */

import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname } from 'node:path';

// Foundation paths this slice owns and cleans to zero.
const SCAN_PATHS = [
  'src/components/ui',
  'src/components/layout',
  'src/components/MainLayout.tsx',
  'src/app/globals.css',
  'tailwind.config.ts',
];

const EXTS = new Set(['.ts', '.tsx', '.css', '.js', '.jsx']);
const EXCEPTION = 'praxis-color-exception';

// Banned: raw red-/blue- utilities in any color-bearing prefix, and #DC2626.
const BANNED = [
  /\b(bg|text|border|ring|from|to|via|divide|outline|fill|stroke|shadow|placeholder|decoration|accent|caret|ring-offset)-(red|blue)-\d{2,3}\b/,
  /#dc2626\b/i,
];

function walk(path, out) {
  let st;
  try {
    st = statSync(path);
  } catch {
    return; // path may not exist yet
  }
  if (st.isDirectory()) {
    for (const entry of readdirSync(path)) walk(join(path, entry), out);
  } else if (EXTS.has(extname(path))) {
    out.push(path);
  }
}

const files = [];
for (const p of SCAN_PATHS) walk(p, files);

const violations = [];
for (const file of files) {
  const lines = readFileSync(file, 'utf8').split('\n');
  lines.forEach((line, i) => {
    if (line.includes(EXCEPTION)) return; // documented exception on this line
    for (const re of BANNED) {
      const m = line.match(re);
      if (m) {
        violations.push({ file, line: i + 1, match: m[0], text: line.trim() });
        break;
      }
    }
  });
}

if (violations.length > 0) {
  console.error(
    '\n✗ PRA-268 color-drift guardrail: raw red-/blue-/#DC2626 found in foundation surfaces.\n' +
      '  Use semantic tokens instead: brand/danger (Signal Red), action (neutral primary),\n' +
      '  link (neutral, red hover), info (neutral), success/warning. See docs/ui-foundation.md.\n' +
      `  Add "// ${EXCEPTION}: <reason>" on the line only for an unavoidable functional case.\n`,
  );
  for (const v of violations) {
    console.error(`  ${v.file}:${v.line}  [${v.match}]  ${v.text}`);
  }
  console.error(`\n${violations.length} violation(s).\n`);
  process.exit(1);
}

console.log(`✓ color-drift guardrail: ${files.length} foundation files clean (no raw red-/blue-/#DC2626).`);
