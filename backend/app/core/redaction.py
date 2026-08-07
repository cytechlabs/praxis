"""Secret redaction for support/diagnostic artifacts (PRA-310).

A single, conservative redaction pass applied to every text that goes into an
admin-generated support bundle. It is defense-in-depth: bundle sections are already
built from curated queries / allowlisted config, but every emitted file is also run
through ``redact_text`` so a stray secret in a log line or free-form field never
leaves the box. Fail-safe: patterns over-match rather than under-match.
"""

from __future__ import annotations

import re
from typing import List, Tuple

_REDACTED = "«redacted»"

# Ordered most-specific first. Each pattern maps a secret shape to a placeholder.
_PATTERNS: List[Tuple[re.Pattern, str]] = [
    # PEM private key blocks (SSH/TLS/agent keys).
    (
        re.compile(
            r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY-----.*?-----END [A-Z0-9 ]*PRIVATE KEY-----",
            re.DOTALL,
        ),
        "«redacted-private-key»",
    ),
    # HashiCorp Vault tokens: v1 `hvs.<...>`, batch `hvb.<...>`, recovery `hvr.<...>`.
    # (external/legacy Vault deployments still connect through the same VAULT_ADDR.)
    (re.compile(r"\bhv[sbr]\.[A-Za-z0-9._-]{8,}"), "«redacted-vault-token»"),
    # OpenBao (bundled secrets runtime, PRA-311) + legacy Vault tokens: service
    # `s.<...>`, batch `b.<...>`, recovery `r.<...>`. OpenBao does NOT use the `hv*`
    # prefixes — it emits `s.`/`b.`/`r.` — so we must not assume only the HashiCorp
    # shapes. The 20+ char floor keeps this from matching ordinary `s.`/`b.` prose.
    (re.compile(r"\b[sbr]\.[A-Za-z0-9._-]{20,}"), "«redacted-vault-token»"),
    # JWTs (license tokens, access/refresh tokens): three base64url segments.
    (
        re.compile(r"\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+"),
        "«redacted-jwt»",
    ),
    # Authorization: Bearer <token>.
    (re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._-]+"), "Bearer «redacted»"),
    # key=value / key: value for sensitive keys (password, token, secret, etc.).
    (
        re.compile(
            r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|"
            r"unseal[_-]?key|root[_-]?token|private[_-]?key|access[_-]?token|"
            r"refresh[_-]?token|client[_-]?secret|vault[_-]?token|secret[_-]?key)"
            r"(\"?\s*[=:]\s*\"?)([^\s\"',}]+)"
        ),
        lambda m: f"{m.group(1)}{m.group(2)}{_REDACTED}",
    ),
    # Postgres/DSN URLs with inline credentials: scheme://user:pass@host -> user:«redacted»@host.
    (
        re.compile(r"(?i)\b([a-z][a-z0-9+.-]*://[^\s:/@]+:)[^\s@/]+(@)"),
        lambda m: f"{m.group(1)}{_REDACTED}{m.group(2)}",
    ),
]


def redact_text(text: str) -> str:
    """Redact known secret shapes from ``text``. Idempotent and total (never raises;
    non-str is returned unchanged)."""
    if not isinstance(text, str) or not text:
        return text
    for pattern, repl in _PATTERNS:
        text = pattern.sub(repl, text)
    return text
