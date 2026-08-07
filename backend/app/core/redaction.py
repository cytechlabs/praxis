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

# Sensitive key names. A compound key is matched on its sensitive suffix, so
# `agent_token`, `totp_secret` and `my-password` are covered by `token`, `secret`
# and `password` without enumerating every prefix. The surrounding prefix is left
# outside the match and therefore preserved in the output.
_SENSITIVE_KEY = (
    r"password|passwd|pwd|secret|token|api[_-]?key|apikey|authorization|"
    r"unseal[_-]?key|root[_-]?token|private[_-]?key|access[_-]?token|"
    r"refresh[_-]?token|client[_-]?secret|vault[_-]?token|secret[_-]?key"
)

# Sensitive `key = value` / `key: value` assignments in log lines, JSON dumps and
# free-form config text.
#
# The left boundary is a negative alphanumeric lookbehind rather than `\b`:
# `_` and `-` are the delimiters that join compound key names, and `_` is a regex
# word character, so `\b` cannot match the sensitive suffix in `agent_token` at
# all. Requiring a non-alphanumeric character to the left keeps `mytoken` and
# ordinary words from matching while allowing every delimiter-joined form.
#
# The value alternation handles double-quoted, single-quoted and bare values.
# Quoted values are matched to their closing quote so a value containing spaces or
# punctuation is redacted whole, and escaped quotes inside do not end it early.
# A bare value stops at whitespace or a structural character, so neighboring
# fields, list/object syntax and trailing separators survive. A value that opens a
# container (`{`, `[`) is not a scalar secret and is left alone so structure is not
# destroyed.
_SENSITIVE_ASSIGNMENT = re.compile(
    r"(?<![A-Za-z0-9])"
    r"(?P<key>" + _SENSITIVE_KEY + r")"
    r"(?P<key_quote>[\"']?)"
    r"(?P<sep>[ \t]*(?:=>|[=:])[ \t]*)"
    r"(?:"
    r"\"(?P<dq>(?:[^\"\\]|\\.)*)\""
    r"|'(?P<sq>(?:[^'\\]|\\.)*)'"
    r"|(?P<bare>[^\s,;{}()\[\]]+)"
    r")",
    re.IGNORECASE,
)


def _redact_assignment(m: re.Match) -> str:
    """Replace only the value of a sensitive assignment, keeping the key, any
    quote that closed the key, and the separator so the line stays readable.

    The original quoting style is re-emitted around the placeholder, which is what
    makes a second pass a no-op: the placeholder itself is matched by the same
    branch that produced it.
    """
    head = f"{m.group('key')}{m.group('key_quote')}{m.group('sep')}"
    if m.group("dq") is not None:
        return f'{head}"{_REDACTED}"'
    if m.group("sq") is not None:
        return f"{head}'{_REDACTED}'"
    return f"{head}{_REDACTED}"


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
    # key=value / key: value for sensitive keys (password, token, secret, etc.),
    # including compound keys and quoted mapping forms.
    (_SENSITIVE_ASSIGNMENT, _redact_assignment),
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
