"""PRA-366: request-log URL sanitization.

Auth endpoints carry the refresh token as a query param (``/auth/logout`` and
``/auth/refresh`` both take ``token_refresh``). The request-logging middleware
must not write those token values into backend logs.
"""

import app.api.main as main
from app.api.main import sanitize_url_for_log


def test_sanitize_redacts_sensitive_query_values():
    out = sanitize_url_for_log("http://h/auth/logout?token_refresh=supersecret")
    assert "supersecret" not in out
    assert "token_refresh=REDACTED" in out


def test_sanitize_redacts_regardless_of_token_format():
    # By-key redaction holds even for a non-JWT opaque value.
    out = sanitize_url_for_log("http://h/auth/refresh?token_refresh=not-a-jwt")
    assert "not-a-jwt" not in out
    assert "token_refresh=REDACTED" in out


def test_sanitize_preserves_non_sensitive_params():
    out = sanitize_url_for_log("http://h/api/items?limit=50&status=failed")
    assert out == "http://h/api/items?limit=50&status=failed"


def test_sanitize_no_query_is_unchanged():
    assert sanitize_url_for_log("http://h/auth/me") == "http://h/auth/me"


def test_request_logging_routes_url_through_sanitizer(client, admin_user, monkeypatch):
    """End-to-end wiring: the request-logging middleware passes the raw request
    URL through ``sanitize_url_for_log`` before logging, so a logout carrying a
    token query param is redacted in the log line.

    Asserting on the wiring (spy on the sanitizer) rather than capturing the log
    record itself: pytest's logging plugin leaves a stale ``Logger.isEnabledFor``
    cache after a prior test, which suppresses live ``caplog`` capture of the
    middleware's ``logger.info`` non-deterministically. The spy is deterministic;
    the redaction behavior itself is covered by the unit tests above.
    """
    seen: list[str] = []
    real = main.sanitize_url_for_log

    def _spy(url: str) -> str:
        seen.append(url)
        return real(url)

    monkeypatch.setattr(main, "sanitize_url_for_log", _spy)
    client.post("/auth/logout?token_refresh=SENTINEL-REFRESH-TOKEN-VALUE")

    logout_urls = [u for u in seen if "/auth/logout" in u]
    assert logout_urls, "middleware did not route the logout URL through the sanitizer"
    # The middleware hands the sanitizer the raw URL (token present)...
    assert any("token_refresh=SENTINEL-REFRESH-TOKEN-VALUE" in u for u in logout_urls)
    # ...and what actually gets logged (the sanitizer's output) is redacted.
    assert all("SENTINEL-REFRESH-TOKEN-VALUE" not in real(u) for u in logout_urls)
