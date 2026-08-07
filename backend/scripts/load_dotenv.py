#!/usr/bin/env python3
"""PRA-265: safe dotenv loader for the container entrypoints.

The old entrypoints shell-evaluated the filtered contents of the env file, so a
value such as ``DATABASE_URL=$(touch /tmp/pwned)`` executed as a shell command at
container boot. This helper parses the file as **dotenv data** with
``python-dotenv`` — command substitutions, backticks, ``;``/``&&``/``|``, quotes,
and redirection are all treated as ordinary characters and exported literally,
never executed.

Usage (from a shell entrypoint)::

    exec python /app/scripts/load_dotenv.py /app/.env -- bash "$0" "$@"

It parses each ENV_FILE (before ``--``), merges the values into the environment,
then ``exec``s the command after ``--`` with that environment. A missing env file
is a silent no-op so the orchestrator-only path (no mounted ``.env``) is
unaffected.

Precedence: parsed ``.env`` values OVERRIDE any already-set environment variable,
preserving the previous ``set -a`` shell-evaluation behavior. (Flip the
``os.environ[...]`` assignment to ``os.environ.setdefault`` to make orchestrator
env authoritative.)

Secrets safety: values are never printed. Only invalid *keys* are reported, and
only by name shape, never with their value.
"""

from __future__ import annotations

import os
import re
import sys

# A POSIX-ish environment variable name. Anything else (embedded spaces, shell
# metacharacters, a leading digit) is skipped as malformed rather than injected
# into the environment under a bogus name.
_VALID_KEY = re.compile(r"[A-Za-z_][A-Za-z0-9_]*")

# The entrypoints (start.prod.sh / start.sh) set PRAXIS_DOTENV_LOADED=1 before
# re-execing themselves through this loader, as an exec-loop guard. Because parsed
# .env values OVERRIDE the environment, a hostile/misconfigured .env line
# `PRAXIS_DOTENV_LOADED=` could otherwise clear that guard and make the re-exec'd
# shell re-enter the loader forever, never reaching the DB wait / migrations. This
# key is therefore RESERVED: a value for it in .env is ignored, and the guard is
# reasserted before exec.
DOTENV_GUARD_KEY = "PRAXIS_DOTENV_LOADED"
RESERVED_KEYS = frozenset({DOTENV_GUARD_KEY})


def parse_env_file(path: str) -> "dict[str, str]":
    """Return the valid KEY->VALUE pairs from a dotenv file.

    Uses ``python-dotenv`` so the file is parsed as data (comments, blank lines,
    quoted values, ``export`` prefixes, CRLF endings, and ``${VAR}`` interpolation
    are handled; ``$(...)``/backticks are left literal and never executed). Keys
    that are not valid environment variable names, and bare keys with no value,
    are skipped. Never raises on individual bad lines — python-dotenv is lenient;
    a genuinely unreadable file raises OSError to the caller.
    """
    from dotenv import dotenv_values

    if not os.path.isfile(path):
        return {}

    result: "dict[str, str]" = {}
    for key, value in dotenv_values(path).items():
        if value is None:
            # Bare "KEY" with no "=" — nothing to export.
            continue
        if not _VALID_KEY.fullmatch(key or ""):
            sys.stderr.write("load_dotenv: skipping malformed .env key\n")
            continue
        result[key] = value
    return result


def load_into_environ(path: str) -> int:
    """Parse ``path`` and merge its values into ``os.environ`` (override). Reserved
    keys (the entrypoint exec-loop guard) are never applied from ``.env``. Returns
    the number of variables applied."""
    values = parse_env_file(path)
    applied = 0
    for key, value in values.items():
        if key in RESERVED_KEYS:
            # A .env file must not be able to clear the entrypoint's exec-loop
            # guard (would loop startup forever). Ignore any value it supplies.
            sys.stderr.write("load_dotenv: ignoring reserved .env key\n")
            continue
        os.environ[key] = value
        applied += 1
    return applied


def main(argv: "list[str]") -> int:
    if "--" not in argv:
        sys.stderr.write(
            "load_dotenv: usage: load_dotenv.py ENV_FILE [ENV_FILE...] -- CMD [ARGS...]\n"
        )
        return 2
    sep = argv.index("--")
    env_files = argv[:sep]
    command = argv[sep + 1 :]
    if not command:
        sys.stderr.write("load_dotenv: no command to exec after --\n")
        return 2

    for env_file in env_files:
        try:
            load_into_environ(env_file)
        except OSError:
            # Do not echo the file or its contents (secrets). Fail closed so a
            # broken env mount surfaces at boot instead of silently starting with
            # partial config.
            sys.stderr.write("load_dotenv: could not read env file; aborting startup\n")
            return 1

    # Reassert the exec-loop guard so the re-exec'd entrypoint never re-enters the
    # loader, no matter what .env contained (belt-and-suspenders with RESERVED_KEYS).
    os.environ[DOTENV_GUARD_KEY] = "1"

    # Replace this process with the real entrypoint, carrying the merged env.
    os.execvp(command[0], command)
    return 127  # unreachable unless execvp fails to find the command


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
