# PY-W2000 canonical inventory

**Artifact:** `py-w2000-inventory.csv` (303 rows, 17 columns)
**Generated at commit:** `620b45960fd3521ef1cffcd6d2f582c57eb402c3`
**Scope:** `backend/**/*.py`, 707 files scanned.

## Why this exists

Three independent counts of "unused imports in backend/" disagreed:

| Source | Count | Scope / commit |
| --- | --- | --- |
| DeepSource PY-W2000 | 254 | commit `4a76d124` |
| Local pylint W0611 | 267 | excludes `__init__.py` and alembic |
| This AST pass | 303 | all bindings, current HEAD |

None could be reconciled by inspection, so remediation was gated on producing a
single name-level inventory. This is that inventory.

## Why the three counts differ

The dominant cause is **pragma handling**, and the two analyzers honour opposite
pragmas:

- DeepSource honours `# noqa` but **not** `# pylint: disable=unused-import`.
- pylint honours `# pylint: disable=unused-import` but **not** `# noqa`.

`backend/app/db/models.py` is where this bites: it carries 28 deliberate
model-registration imports, and the block at lines 72-74 carries **both**
pragmas while lines 70-71 carry **only** the pylint one. That is precisely why
DeepSource flagged 70-71 and skipped the rest of the block.

Applying each analyzer's rule to this pass reproduces both numbers closely:

- drop `# noqa` rows -> **274** (DeepSource reported 254 on an older tree)
- drop pylint-disable rows -> **269** (local pylint reported 267)

A residual gap of about 20 against DeepSource remains and is **not** claimed to
be reconciled. It is attributable to commit drift, since the DeepSource baseline
predates two commits that touch files in scope, plus possible analyzer
differences. Closing it requires a fresh DeepSource run at HEAD. See step 1.

## Columns

| Column | Meaning |
| --- | --- |
| `path`, `name_line` | Location of the **name**, not the opening paren of a multi-line import |
| `stmt_line` | Line of the `import` / `from ... import (` statement |
| `name`, `imported_from` | The bound name and its source module |
| `disposition` | See table below |
| `is_reexport`, `reexport_kind` | Whether another module consumes this name through here, and how (`explicit` / `star` / `explicit+star`) |
| `reexport_consumers` | The specific names consumed via explicit through-import |
| `star_imported_from` | Files doing `from <this module> import *` |
| `has_noqa`, `has_pylint_disable` | Pragmas on the name or statement line |
| `deepsource_would_report`, `pylint_would_report` | Per-analyzer visibility, for reconciliation |
| `rationale` | Why this disposition |

## Dispositions

| Disposition | Count | Meaning |
| --- | --- | --- |
| `REMOVE` | 248 | No consumer, no pragma, no string reference. Safe for scoped per-name removal. |
| `REVIEW-REEXPORT` | 28 | Another module consumes the name through here. Human decision. |
| `KEEP-REEXPORT` | 10 | Load-bearing re-export. Deleting breaks import. |
| `REMOVE-STALE-PRAGMA` | 7 | Carries a pragma but has **zero** consumers, so the suppression protects nothing. |
| `DEFER-SPIKE-REMOVAL` | 7 | Under `scripts/spikes/`, which is scheduled for removal. Do not remediate. |
| `KEEP-SUPPRESS` | 3 | `alembic/env.py` metadata-registration backup strand. Suppress, never delete. |

### A pragma is not intent

An earlier revision of this classifier defaulted every pragma-carrying row to
"keep". That was wrong: **a pragma proves prior suppression, not present
intent.** The classifier now derives the answer instead. If nothing consumes the
name through its module (neither an explicit `from M import <name>` nor a
star-import of `M`), the suppression has nothing left to protect and the row is
`REMOVE-STALE-PRAGMA`.

All seven such rows were verified to have zero through-import consumers:

| Row | Note |
| --- | --- |
| `app/api/routes/auth.py:7` `List` | Blanket pragma on a 4-name `typing` import |
| `app/api/routes/auth.py:23` `RoleAssignment` | Isolated on its own line *with* a pragma, so it looks intentional, but it has no consumers. Real use is `routes/users.py`. |
| `app/api/routes/auth.py:31` `verify_admin` | Same shape, same finding |
| `app/api/routes/systems.py:8` `ipaddress` | Validation is pydantic `IPvAnyAddress` |
| `app/api/routes/vault/vault.py:14` `VaultConnectionError` | `vault/__init__.py` imports from the source module, not through here |
| `app/api/routes/vault/vault.py:21` `VaultHealthResponse` | Health endpoint moved to `vault/__init__.py` |
| `app/services/patch_execution_dispatch_service.py:81` `AUDIT_EXECUTION_CANCELED` | **Nuance:** the block's `# noqa: F401  (re-export friendliness)` is legitimate, because 10+ test files import siblings such as `AUDIT_EXECUTION_PAUSED` from this module. Only this one name has no consumer; its test imports it from `patch_execution_service` directly. Remove the name, keep the block comment. |

## Named traps

1. **`app/api/routes/__init__.py` (9 rows, `KEEP-REEXPORT`).** `app/api/main.py`
   imports all nine by name and passes them to `include_router()`. Deleting any
   makes `import app.api.main` raise `ImportError`, and the backend will not
   boot. Roughly 102 endpoints are affected. **Fix is to add the nine names to
   the existing `__all__`**, which already has 74 entries; the nine flagged
   names are exactly the set missing from it.

2. **`alembic/env.py` (3 rows, `KEEP-SUPPRESS`).** Redundant today, because
   `app.db.base` already registers all 139 tables, verified empirically. It is
   the backup strand. `app/db/base.py` defines only the `DeclarativeBase` with
   an id/created_at/updated_at mixin and **zero** concrete models, so if both
   this and `app/db/__init__.py`'s star-imports are ever cut, `Base.metadata`
   holds **zero** tables and `alembic revision --autogenerate` would emit
   `op.drop_table()` for every live table.

3. **Two different `Frame` imports.** `app/broker/ops.py:47` is load-bearing,
   used in the string annotations `"asyncio.Queue[Frame]"` at ops.py:121-122
   under `from __future__ import annotations`, and is **deliberately absent from
   this inventory**: the scanner treats any name appearing inside a string
   literal as used, so it never flagged it. `app/broker/handlers.py:54` is a
   genuinely dead `Frame` and **is** listed as `REMOVE`. Do not confuse them.

4. **Line numbers are per-name, not per-statement.** DeepSource reports the
   opening paren of a multi-line `from x import (`; this inventory resolves the
   actual line the name sits on. Several statements have many names of which
   only some are unused. One test module has a 24-name import with 3 unused.
   **Never delete a flagged line wholesale.** Use per-name removal.

## Recommended sequence

1. Re-run DeepSource analysis at HEAD and export PY-W2000, then diff against
   this CSV to close the residual.
2. Add the nine router names to `__all__` in `app/api/routes/__init__.py`.
3. Add explicit suppressions to `alembic/env.py` and confirm `ops.py:Frame`.
4. Decide the 28 `REVIEW-REEXPORT` rows in `app/db/models.py`: intentional
   registration documentation, or reducible.
5. Run scoped per-name removal over `REMOVE` and `REMOVE-STALE-PRAGMA` rows
   only: `ruff check --select F401 --fix <paths>`, then black and isort
   in-container. Delete the now-pointless pragmas alongside their names.
6. Verify: backend import/startup, `alembic upgrade head`, full pytest, and a
   fresh DeepSource run.
7. Add a dedicated F401/W0611 CI gate with explicit exceptions for the
   re-export and side-effect imports above.

## Reproducing

Both scripts are pure-stdlib AST passes with no project dependencies and no
hard-coded paths. From anywhere:

```
python3 scan_unused_imports.py /path/to/backend > ast_scan.json
python3 build_inventory.py ast_scan.json py-w2000-inventory.csv <commit-sha>
```

`build_inventory.py` also accepts `-` to read the scan JSON from stdin, so the
two stages can be piped. Output is byte-identical whether the scanner is given a
relative or an absolute root.

The scanner is deliberately conservative: any textual appearance of a name
inside a string literal counts as a use, so forward references, `__all__`
entries and `monkeypatch.setattr("mod.Name", ...)` targets can only suppress a
finding, never create one.

### Known limitations

- **Star-import re-exports are approximated.** If module `M` is star-imported
  anywhere, every non-underscore unused binding in `M` is marked
  `reexport_kind=star`. This is deliberately over-inclusive: it cannot tell
  which names a downstream module actually uses, so it flags for review rather
  than risking a destructive removal. 17 rows are star-only.
- **Dynamic imports are invisible.** `importlib.import_module()` and
  `__import__()` targets are not tracked.
- **Consumers outside this repository are not scanned.** External packages
  importing from `backend/app` may not appear in this inventory.
