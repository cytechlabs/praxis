#!/bin/bash
# PRA-233: enforce the 1.0 single-worker invariant for browser interactive
# SSH sessions.
#
# The interactive session runtime (a Paramiko transport + PTY channel plus its
# recording writer) is process-local: POST /sessions opens it in one worker's
# memory, and /sessions/{id}/ws attaches by looking it up in that same
# process-local registry. With more than one Uvicorn worker the REST open and
# the WebSocket attach can land on different workers, so the attach fails with
# "runtime missing". A distributed/sticky session runtime is out of scope for
# 1.0.
#
# This guard fails fast when production is configured for multiple workers,
# unless an operator explicitly opts into the unsupported mode. It reads only
# the environment (UVICORN_WORKERS, ALLOW_UNSAFE_MULTIWORKER_SESSIONS) so it is
# trivially unit-testable in isolation from the full prod entrypoint.
set -euo pipefail

workers="${UVICORN_WORKERS:-1}"
override="${ALLOW_UNSAFE_MULTIWORKER_SESSIONS:-0}"

if ! printf '%s' "$workers" | grep -qE '^[0-9]+$' || [ "$workers" -lt 1 ]; then
  echo "ERROR: UVICORN_WORKERS must be a positive integer (got '${workers}')." >&2
  exit 1
fi

if [ "$workers" -gt 1 ] && [ "$override" != "1" ]; then
  echo "ERROR: UVICORN_WORKERS=${workers} is unsupported for browser interactive SSH sessions in 1.0." >&2
  echo "The interactive session runtime is process-local; with more than one worker the" >&2
  echo "terminal WebSocket attach can land on a worker that did not open the SSH session" >&2
  echo "(the '/sessions/{id}/ws' handler closes with 'runtime missing')." >&2
  echo "" >&2
  echo "Run a single worker: UVICORN_WORKERS=1 (the default)." >&2
  echo "Only if you do not use browser interactive SSH sessions may you override this with" >&2
  echo "ALLOW_UNSAFE_MULTIWORKER_SESSIONS=1 — this is unsupported for interactive sessions." >&2
  exit 1
fi

exit 0
