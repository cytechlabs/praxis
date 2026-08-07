"""Per-name unused-import scanner for the PY-W2000 canonical inventory.

Emits one JSON record per (file, line, name) where an imported binding is not
referenced in the module. Deliberately conservative: any textual appearance of
the name inside a string literal counts as a use, so forward references,
``monkeypatch.setattr("mod.Name", ...)`` targets and ``__all__`` entries can
only suppress a finding, never create one.

Also builds a cross-file consumer index so re-exports can be distinguished from
genuinely dead imports.
"""

import ast
import json
import os
import re
import sys
from collections import defaultdict

ROOT = sys.argv[1] if len(sys.argv) > 1 else "backend"
SKIP_DIRS = {"__pycache__", ".venv", "venv", "node_modules", ".git", ".mypy_cache"}

# DeepSource honours `# noqa` but NOT `# pylint: disable=unused-import`; pylint
# does the reverse. Tracking them separately is what makes the two inventories
# reconcilable.
NOQA_RE = re.compile(r"#.*\bnoqa\b", re.IGNORECASE)
PYLINT_RE = re.compile(r"#.*pylint:\s*disable[^#]*unused-import", re.IGNORECASE)


def iter_py_files(root):
    for dirpath, dirnames, filenames in os.walk(root):
        dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS]
        for fn in filenames:
            if fn.endswith(".py"):
                yield os.path.join(dirpath, fn)


def module_path_for(path, root):
    """backend/app/db/models.py -> app.db.models ; .../__init__.py -> package."""
    rel = os.path.relpath(path, root)
    rel = rel[:-3] if rel.endswith(".py") else rel
    parts = rel.split(os.sep)
    if parts and parts[-1] == "__init__":
        parts = parts[:-1]
    return ".".join(parts)


def resolve_relative(module, level, current_pkg):
    """Resolve `from ..x import y` to an absolute dotted module."""
    if not level:
        return module or ""
    base = current_pkg.split(".")
    # level 1 == current package; each extra level pops one component
    if level > 1:
        base = base[: -(level - 1)] if level - 1 <= len(base) else []
    prefix = ".".join(base)
    if module:
        return f"{prefix}.{module}" if prefix else module
    return prefix


class Collector(ast.NodeVisitor):
    def __init__(self):
        self.used = set()
        self.strings = []
        self.all_entries = set()
        self.has_future_annotations = False

    def visit_Name(self, node):
        self.used.add(node.id)
        self.generic_visit(node)

    def visit_Attribute(self, node):
        # capture the root of a dotted chain: a.b.c -> a
        cur = node
        while isinstance(cur, ast.Attribute):
            cur = cur.value
        if isinstance(cur, ast.Name):
            self.used.add(cur.id)
        self.generic_visit(node)

    def visit_Constant(self, node):
        if isinstance(node.value, str):
            self.strings.append(node.value)
        self.generic_visit(node)

    def visit_Assign(self, node):
        for tgt in node.targets:
            if isinstance(tgt, ast.Name) and tgt.id == "__all__":
                try:
                    vals = ast.literal_eval(node.value)
                    if isinstance(vals, (list, tuple, set)):
                        self.all_entries.update(str(v) for v in vals)
                except (ValueError, SyntaxError):
                    pass
        self.generic_visit(node)


def scan_file(path, root, src_lines):
    try:
        with open(path, "r", encoding="utf-8") as fh:
            src = fh.read()
    except OSError:
        return [], []
    try:
        tree = ast.parse(src, filename=path)
    except SyntaxError:
        return [], []

    lines = src.splitlines()
    src_lines[path] = lines

    col = Collector()
    col.visit(tree)

    # Names appearing anywhere inside any string literal count as used.
    string_blob = "\n".join(col.strings)
    string_tokens = set(re.findall(r"[A-Za-z_][A-Za-z0-9_]*", string_blob))

    imports = []       # bindings defined in this module
    consumes = []      # (abs_module, name) this module pulls from elsewhere

    current_pkg = module_path_for(path, root)
    if not path.endswith("__init__.py"):
        current_pkg = ".".join(current_pkg.split(".")[:-1])

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for a in node.names:
                bound = a.asname or a.name.split(".")[0]
                imports.append(
                    {
                        "name": bound,
                        "orig": a.name,
                        "module": None,
                        "lineno": node.lineno,
                        "col": node.col_offset,
                        "kind": "import",
                    }
                )
                consumes.append((a.name, None))
        elif isinstance(node, ast.ImportFrom):
            abs_mod = resolve_relative(node.module, node.level, current_pkg)
            if node.module == "__future__":
                continue
            for a in node.names:
                if a.name == "*":
                    consumes.append((abs_mod, "*"))
                    continue
                bound = a.asname or a.name
                imports.append(
                    {
                        "name": bound,
                        "orig": a.name,
                        "module": abs_mod,
                        "lineno": node.lineno,
                        "col": node.col_offset,
                        "kind": "from",
                    }
                )
                consumes.append((abs_mod, a.name))

    unused = []
    for imp in imports:
        n = imp["name"]
        if n in col.used or n in col.all_entries or n in string_tokens:
            continue
        stmt_line = lines[imp["lineno"] - 1] if imp["lineno"] - 1 < len(lines) else ""
        # find the physical line the name itself sits on (multi-line imports)
        name_line = imp["lineno"]
        for off in range(0, 40):
            idx = imp["lineno"] - 1 + off
            if idx >= len(lines):
                break
            if re.search(rf"\b{re.escape(imp['orig'])}\b", lines[idx]):
                name_line = idx + 1
                break
        pragma_line = lines[name_line - 1] if name_line - 1 < len(lines) else ""
        unused.append(
            {
                "path": os.path.relpath(path, os.path.dirname(root) or "."),
                "module": module_path_for(path, root),
                "name": n,
                "orig": imp["orig"],
                "from_module": imp["module"],
                "stmt_line": imp["lineno"],
                "name_line": name_line,
                "kind": imp["kind"],
                "has_noqa": bool(NOQA_RE.search(pragma_line) or NOQA_RE.search(stmt_line)),
                "has_pylint_disable": bool(
                    PYLINT_RE.search(pragma_line) or PYLINT_RE.search(stmt_line)
                ),
                "in_all": n in col.all_entries,
                "has_all_block": bool(col.all_entries),
            }
        )
    return unused, consumes


def main():
    root = ROOT
    src_lines = {}
    all_unused = []
    consumer_index = defaultdict(set)   # abs_module -> {names consumed by others}
    star_importers = defaultdict(set)   # abs_module -> {files doing import *}

    files = sorted(iter_py_files(root))
    for path in files:
        unused, consumes = scan_file(path, root, src_lines)
        all_unused.extend(unused)
        # Normalise the same way the `path` field is normalised, so output is
        # identical whether the scanner is invoked with a relative or an
        # absolute root.
        rel_path = os.path.relpath(path, os.path.dirname(root) or ".")
        for mod, name in consumes:
            if name == "*":
                star_importers[mod].add(rel_path)
            elif name:
                consumer_index[mod].add(name)

    # Mark re-exports two ways:
    #   (a) explicit  - some other module does `from M import <name>`
    #   (b) star      - some other module does `from M import *`, which pulls in
    #                   every public binding of M, so any non-underscore unused
    #                   import in M is potentially consumed downstream.
    for rec in all_unused:
        m = rec["module"]
        rec["reexport_consumers"] = sorted(consumer_index.get(m, set()) & {rec["name"]})
        stars = sorted(star_importers.get(m, set()))
        rec["star_imported_from"] = stars
        rec["is_star_reexport"] = bool(stars) and not rec["name"].startswith("_")
        rec["is_reexport"] = bool(rec["reexport_consumers"]) or rec["is_star_reexport"]

    json.dump(
        {
            "root": root,
            "files_scanned": len(files),
            "unused_count": len(all_unused),
            "records": all_unused,
        },
        sys.stdout,
        indent=None,
    )


if __name__ == "__main__":
    main()
