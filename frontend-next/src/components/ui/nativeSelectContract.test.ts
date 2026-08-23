import { describe, it, expect } from 'vitest';
import { readdirSync, readFileSync, statSync } from 'node:fs';
import { join, extname, relative } from 'node:path';
import { fileURLToPath } from 'node:url';

/**
 * Repository guardrail for native select readability.
 *
 * A native option list is painted by the browser using the control's used
 * background and text colors. A translucent or theme-blind background leaves
 * that list composited against the browser's own default surface, so light
 * option text can land on a light list. Every native select therefore has to
 * carry the shared contract in `Input.tsx` rather than restate colors locally.
 *
 * This scans source rather than rendered output because the defect reappears by
 * someone hand-styling a new select, which no page-level test would notice.
 */

const SRC = join(fileURLToPath(new URL('../../', import.meta.url)));
const EXTS = new Set(['.ts', '.tsx']);
const CONTRACT = 'nativeSelectClass';

// Backgrounds a native select must never use: `bg-black`/`bg-white` and the
// legacy `praxis-*` family are theme-blind, and any `/<alpha>` suffix is
// translucent.
const BANNED_BG = /\bbg-(?:black|white)\b|\bbg-praxis-[\w-]+|\bbg-[\w[\]./-]*?\/(?:\d{1,3}|\[[^\]]+\])\b/;

function walk(dir: string, out: string[]): string[] {
  for (const entry of readdirSync(dir)) {
    const entryPath = join(dir, entry);
    if (statSync(entryPath).isDirectory()) walk(entryPath, out);
    else if (EXTS.has(extname(entryPath))) out.push(entryPath);
  }
  return out;
}

/** Remove comments so prose mentioning a select tag is not scanned as markup. */
function stripComments(src: string): string {
  return src.replace(/\/\*[\s\S]*?\*\//g, '').replace(/^[ \t]*\/\/.*$/gm, '');
}

/** Extract each `<select ...>` opening tag, balancing JSX braces and strings. */
function selectTags(src: string): string[] {
  const tags: string[] = [];
  const re = /<select\b/g;
  let tagMatch: RegExpExecArray | null;
  while ((tagMatch = re.exec(src))) {
    let i = re.lastIndex;
    let depth = 0;
    let quote: string | null = null;
    while (i < src.length) {
      const char = src[i];
      if (quote) {
        if (char === '\\') {
          i += 2;
          continue;
        }
        if (char === quote) quote = null;
      } else if (char === '"' || char === "'" || char === '`') quote = char;
      else if (char === '{') depth++;
      else if (char === '}') depth--;
      else if (char === '>' && depth === 0) break;
      i++;
    }
    tags.push(src.slice(tagMatch.index, i + 1));
  }
  return tags;
}

/** The className expression as written: a quoted string, or a balanced `{...}`. */
function classExprOf(tag: string): string | null {
  const at = tag.search(/\bclassName=/);
  if (at === -1) return null;
  let i = at + tag.slice(at).indexOf('=') + 1;
  if (tag[i] === '"' || tag[i] === "'") {
    const end = tag.indexOf(tag[i], i + 1);
    return end === -1 ? null : tag.slice(i + 1, end);
  }
  if (tag[i] !== '{') return null;
  let depth = 0;
  let quote: string | null = null;
  const start = ++i;
  for (; i < tag.length; i++) {
    const char = tag[i];
    if (quote) {
      if (char === '\\') i++;
      else if (char === quote) quote = null;
    } else if (char === '"' || char === "'" || char === '`') quote = char;
    else if (char === '{') depth++;
    else if (char === '}') {
      if (depth === 0) return tag.slice(start, i);
      depth--;
    }
  }
  return null;
}

/** Text of a local `const NAME = ...;` initializer, if the file defines one. */
function localDefinition(name: string, source: string): string | null {
  const match = new RegExp(`\\b(?:const|let)\\s+${name}\\s*=([\\s\\S]*?);\\s*$`, 'm').exec(
    source,
  );
  return match ? match[1] : null;
}

/**
 * Flatten a className expression into the class text it can actually produce.
 *
 * A select may be styled through a literal, a template literal, or a local
 * constant (`className={selectCls}`), and those compose. Every check below runs
 * against this single resolved form, so an indirection cannot be used to smuggle
 * in a background that a literal would be rejected for.
 *
 * Identifier names are kept in the output as well as expanded, so a reference to
 * the imported `nativeSelectClass` still registers even though its definition
 * lives in another module.
 */
function resolveClassExpr(expr: string, source: string, seen = new Set<string>()): string {
  let out = expr;
  for (const name of expr.match(/[A-Za-z_$][\w$]*/g) ?? []) {
    if (name === CONTRACT || seen.has(name)) continue;
    const def = localDefinition(name, source);
    if (def === null) continue;
    seen.add(name);
    out += ` ${resolveClassExpr(def, source, seen)}`;
  }
  return out;
}

interface Found {
  file: string;
  /** The className expression as written, for readable failure output. */
  expr: string | null;
  /** That expression with local constants expanded. */
  resolved: string;
}

const selects: Found[] = [];
for (const file of walk(SRC, [])) {
  if (file.endsWith('.test.ts') || file.endsWith('.test.tsx')) continue;
  const raw = readFileSync(file, 'utf8');
  if (!raw.includes('<select')) continue;
  const src = stripComments(raw);
  for (const tag of selectTags(src)) {
    const expr = classExprOf(tag);
    selects.push({
      file: relative(SRC, file),
      expr,
      resolved: expr === null ? '' : resolveClassExpr(expr, src),
    });
  }
}

describe('native select contract', () => {
  it('finds the native selects it is meant to police', () => {
    // Guards against the scanner silently matching nothing and passing.
    expect(selects.length).toBeGreaterThan(100);
  });

  it('every native select carries the shared contract', () => {
    const offenders = selects
      .filter((s) => s.expr === null || !s.resolved.includes(CONTRACT))
      .map((s) => `${s.file}: ${s.expr ?? '(no className)'}`);
    expect(offenders).toEqual([]);
  });

  it('no native select reaches a translucent or theme-blind background', () => {
    // Applied to the resolved expression, so routing the background through a
    // local constant is caught exactly like writing it inline.
    const offenders = selects
      .filter((s) => BANNED_BG.test(s.resolved))
      .map((s) => `${s.file}: ${s.expr}`);
    expect(offenders).toEqual([]);
  });

  it('the shared contract pins both the control and its option children', () => {
    const input = readFileSync(join(SRC, 'components/ui/Input.tsx'), 'utf8');
    const def = /export const nativeSelectClass =([\s\S]*?);\n/.exec(input);
    // Fail fast rather than index a miss: this proves the regex found the
    // contract, and narrows `def` so the capture group is safe to read.
    if (def === null) throw new Error('Input.tsx no longer exports nativeSelectClass');
    const contract = def[1];
    for (const required of [
      'bg-surface-sunken',
      'text-content',
      '[&_option]:bg-surface-sunken',
      '[&_option]:text-content',
      '[&_optgroup]:bg-surface-sunken',
      'focus-visible:ring-focusring',
    ]) {
      expect(contract).toContain(required);
    }
    expect(contract).not.toMatch(BANNED_BG);
  });
});
