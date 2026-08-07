"""Build the canonical PY-W2000 inventory CSV from the AST scan."""

import csv
import json
import sys

if len(sys.argv) < 4:
    sys.exit(
        "usage: build_inventory.py <ast_scan.json|-> <out.csv> <commit-sha>\n"
        "       ('-' reads the scan JSON from stdin)"
    )

SCAN = sys.argv[1]
OUT = sys.argv[2]
COMMIT = sys.argv[3]

# Findings the audit established must NOT be deleted, keyed by (path-suffix, name).
KEEP = {
    ("app/api/routes/__init__.py", None): (
        "KEEP-REEXPORT",
        "Imported by app/api/main.py by name and passed to include_router(); "
        "deleting breaks backend import. Fix = add to __all__.",
    ),
    ("alembic/env.py", None): (
        "KEEP-SUPPRESS",
        "Redundant today (app.db.base already registers all tables) but is the "
        "backup strand for Alembic autogenerate metadata. Suppress, do not delete.",
    ),
    ("app/broker/ops.py", "Frame"): (
        "KEEP-ANNOTATION",
        'Used only in string annotations "asyncio.Queue[Frame]" (ops.py:121-122) '
        "under `from __future__ import annotations`; needed by get_type_hints().",
    ),
    ("app/db/__init__.py", "Base"): (
        "KEEP-REEXPORT",
        "Intentional re-export; add __all__ = ['Base'] rather than deleting.",
    ),
}

DEFER = {
    "scripts/spikes/": (
        "DEFER-SPIKE-REMOVAL",
        "Located under scripts/spikes/, which is scheduled for removal; do not "
        "remediate these imports separately.",
    ),
}


def classify(rec):
    path = rec["path"]
    name = rec["name"]

    for prefix, (disp, why) in DEFER.items():
        if prefix in path:
            return disp, why

    for (suffix, keyname), (disp, why) in KEEP.items():
        if path.endswith(suffix) and (keyname is None or keyname == name):
            return disp, why

    if rec["is_reexport"]:
        return (
            "REVIEW-REEXPORT",
            "Another module imports this name through here: "
            + ", ".join(rec["reexport_consumers"]),
        )

    if rec["has_noqa"] or rec["has_pylint_disable"]:
        pragmas = []
        if rec["has_noqa"]:
            pragmas.append("# noqa")
        if rec["has_pylint_disable"]:
            pragmas.append("# pylint: disable=unused-import")
        # A pragma proves prior suppression, not present intent. If nothing
        # consumes the name through this module (neither an explicit
        # `from M import <name>` nor a star-import of M), the suppression has
        # nothing left to protect and is stale.
        return (
            "REMOVE-STALE-PRAGMA",
            "Carries " + " and ".join(pragmas) + " but has zero consumers "
            "(no explicit through-import, no star-import of this module), so the "
            "suppression protects nothing. Remove the name AND its now-pointless "
            "pragma. If the pragma sits on a shared multi-name block, keep the "
            "block comment for the siblings that are still re-exported.",
        )

    return "REMOVE", "No consumer, no pragma, no string reference."


def area(path):
    if "/tests/" in path:
        return "tests"
    if "/scripts/" in path:
        return "scripts"
    if "/alembic/" in path:
        return "alembic"
    if "/app/services/" in path:
        return "app/services"
    if "/app/api/routes/" in path:
        return "app/api/routes"
    if "/app/broker/" in path:
        return "app/broker"
    if "/app/db/" in path:
        return "app/db"
    if "/app/" in path:
        return "app/other"
    return "other"


def main():
    if SCAN == "-":
        data = json.load(sys.stdin)
    else:
        with open(SCAN, encoding="utf-8") as fh:
            data = json.load(fh)
    rows = []
    for rec in data["records"]:
        disp, why = classify(rec)
        rows.append(
            {
                "path": rec["path"],
                "name_line": rec["name_line"],
                "stmt_line": rec["stmt_line"],
                "name": rec["name"],
                "imported_from": rec["from_module"] or rec["orig"],
                "area": area(rec["path"]),
                "disposition": disp,
                "is_reexport": rec["is_reexport"],
                "reexport_kind": (
                    "explicit+star"
                    if rec["reexport_consumers"] and rec.get("is_star_reexport")
                    else "explicit"
                    if rec["reexport_consumers"]
                    else "star"
                    if rec.get("is_star_reexport")
                    else ""
                ),
                "reexport_consumers": ";".join(rec["reexport_consumers"]),
                "star_imported_from": ";".join(rec.get("star_imported_from", [])),
                "has_noqa": rec["has_noqa"],
                "has_pylint_disable": rec["has_pylint_disable"],
                "deepsource_would_report": not rec["has_noqa"],
                "pylint_would_report": not rec["has_pylint_disable"],
                "rationale": why,
                "commit": COMMIT,
            }
        )

    rows.sort(key=lambda r: (r["area"], r["path"], r["name_line"], r["name"]))

    # lineterminator="\n": csv defaults to RFC-4180 CRLF, which git normalises on
    # commit and which would make every regeneration look like a whole-file diff.
    with open(OUT, "w", newline="", encoding="utf-8") as fh:
        w = csv.DictWriter(fh, fieldnames=list(rows[0].keys()), lineterminator="\n")
        w.writeheader()
        w.writerows(rows)

    from collections import Counter

    print(f"wrote {len(rows)} rows -> {OUT}\n")
    print("disposition totals")
    for k, v in sorted(Counter(r["disposition"] for r in rows).items(), key=lambda x: -x[1]):
        print(f"  {k:20s} {v}")
    print("\nby area x disposition")
    c = Counter((r["area"], r["disposition"]) for r in rows)
    for (a, d), n in sorted(c.items()):
        print(f"  {a:16s} {d:20s} {n}")
    print("\nanalyzer views")
    print(f"  DeepSource would report : {sum(1 for r in rows if r['deepsource_would_report'])}")
    print(f"  pylint would report     : {sum(1 for r in rows if r['pylint_would_report'])}")
    print(f"  total unused bindings   : {len(rows)}")


if __name__ == "__main__":
    main()
