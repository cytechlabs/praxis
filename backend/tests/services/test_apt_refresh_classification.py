"""Characterization of classify_apt_refresh across a fixed output corpus.

Pins the exact (state, detail) for inputs that exercise per-source parsing,
diagnostic collection, the clean-exit-without-a-refreshed-source rule,
credential redaction, and the detail caps, so the classifier can be
restructured without changing what operators see.
"""

import pytest

from app.services.package_service import (
    APT_DETAIL_MAX_CHARS,
    APT_FAILED,
    APT_FRESH,
    classify_apt_refresh,
)

HIT = "Hit:1 http://deb.debian.org/debian trixie InRelease\n"
MANY = "".join(
    f"Err:{i} https://r{i}.example.com/repo trixie InRelease\n  404  Not Found [IP: 203.0.113.{i} 443]\n"
    for i in range(2, 10)
)
CORPUS = {
    "clean": (HIT + "Get:2 http://sec.example.com/s t InRelease\n", "", 0),
    "clean_none": ("Reading package lists...\n", "", 0),
    "clean_none_none_stdout": (None, None, 0),
    "none_exit": (HIT, "", None),
    "nonzero_empty": ("", "", 100),
    "err_multiline_reason": (
        HIT + "Err:2 https://u:Sekret99@ent.example.com:8443/d/pve trixie InRelease\n"
        "\n  \n  401  Unauthorized [IP: 203.0.113.9 443]\n  second line ignored\n"
        "Reading package lists...\n",
        "E: Failed to fetch https://ent.example.com/x  401  Unauthorized\n"
        "E: Some index files failed to download. They have been ignored.\n",
        100,
    ),
    "err_no_reason": (HIT + "Err:2 http://a.example.com/x ./ Packages\n", "", 0),
    "err_duplicate_url": (
        HIT + "Err:2 http://a.example.com/x ./ Packages\n  404  Not Found\n"
        "Err:3 http://a.example.com/x ./ Sources\n  403  Forbidden\n",
        "",
        100,
    ),
    "err_only_failed_source_same_url_as_hit": (
        "Hit:1 http://a.example.com/x\nErr:2 http://a.example.com/x ./ Packages\n  404  Not Found\n",
        "",
        100,
    ),
    "many_failed": (HIT + MANY, "", 100),
    "many_failed_exit0": (HIT + MANY, "", 0),
    "all_failed": (MANY, "", 100),
    "privilege": ("", "E: Could not open lock file /var/lib/apt/lists/lock\n", 100),
    "privilege_with_ok_source": (
        HIT,
        "E: Unable to lock directory /var/lib/apt/lists/\n",
        100,
    ),
    "sudo_password": (HIT, "sudo: a password is required\n", 1),
    "unsigned_exit100": (
        HIT,
        "E: The repository 'http://x ./ Release' is not signed.\n",
        100,
    ),
    "unsigned_exit0": (
        HIT,
        "W: GPG error: http://x ./ InRelease: NO_PUBKEY ABCDEF\n",
        0,
    ),
    "benign_warning": (HIT, "W: Target Packages is configured multiple times\n", 0),
    "benign_warning_nonzero": (
        HIT,
        "W: Target Packages is configured multiple times\n",
        100,
    ),
    "diag_on_stdout": (
        HIT
        + "E: Failed to fetch http://x.example.com/y  Could not connect [IP: 1.2.3.4 80]\n",
        "",
        0,
    ),
    "diag_many": (
        HIT,
        "".join(
            f"W: Failed to fetch http://h{i}.example.com/i  Could not connect\n"
            for i in range(6)
        )
        + "W: Some index files failed to download. They have been ignored.\n",
        0,
    ),
    "diag_non_fetch_only": (HIT, "E: Something odd " + "x" * 700 + "\n", 100),
    "diag_non_fetch_exit0": (HIT, "E: Something odd happened\n", 0),
    "generic_only": (
        HIT,
        "E: Some index files failed to download. They have been ignored.\n",
        100,
    ),
    "network": (HIT, "E: Failed to fetch http://x/y  Could not resolve 'x'\n", 100),
    "indented_diag_stdout": (HIT + "  E: indented\n", "", 0),
    "stderr_indented": (HIT, "  W: Failed to fetch http://z/y  timed out\n", 0),
    "secret_in_diag": (
        HIT,
        "E: Failed to fetch https://deploy:SentinelPw8f2c@h.example.com/d  401  Unauthorized\n",
        100,
    ),
    "long_label": (
        HIT
        + "Err:2 https://h.example.com/"
        + "p" * 700
        + " trixie InRelease\n  404  Not Found\n",
        "",
        100,
    ),
}

EXPECTED = {
    "clean": ("fresh", ""),
    "clean_none": (
        "failed",
        "apt-get update refreshed no source; no enabled APT source reported in. Enable a "
        "source on the host, or treat the cached lists as unverified.",
    ),
    "clean_none_none_stdout": (
        "failed",
        "apt-get update refreshed no source; no enabled APT source reported "
        "in. Enable a source on the host, or treat the cached lists as "
        "unverified.",
    ),
    "none_exit": (
        "failed",
        "apt-get update exited with status None. Run apt-get update on the host to see the "
        "full error.",
    ),
    "nonzero_empty": (
        "failed",
        "apt-get update exited with status 100. Run apt-get update on the host to see "
        "the full error.",
    ),
    "err_multiline_reason": (
        "partial",
        "1 source(s) failed to refresh: ent.example.com:8443/d/pve trixie "
        "InRelease. Run apt-get update on the host to see the full error.",
    ),
    "err_no_reason": (
        "partial",
        "1 source(s) failed to refresh: a.example.com/x ./ Packages. Run apt-get update "
        "on the host to see the full error.",
    ),
    "err_duplicate_url": (
        "partial",
        "1 source(s) failed to refresh: a.example.com/x ./ Packages (404 Not "
        "Found). The source may have been removed or the suite renamed; fix or "
        "disable it.",
    ),
    "err_only_failed_source_same_url_as_hit": (
        "failed",
        "1 source(s) failed to refresh: a.example.com/x ./ "
        "Packages (404 Not Found). The source may have been "
        "removed or the suite renamed; fix or disable it.",
    ),
    "many_failed": (
        "partial",
        "8 source(s) failed to refresh: r2.example.com/repo trixie InRelease (404 Not "
        "Found); r3.example.com/repo trixie InRelease (404 Not Found); "
        "r4.example.com/repo trixie InRelease (404 Not Found); r5.example.com/repo trixie "
        "InRelease (404 Not Found); r6.example.com/repo trixie InRelease (404 Not Found); "
        "and 3 more. The source may have been removed or the suite renamed; fix or "
        "disable it.",
    ),
    "many_failed_exit0": (
        "partial",
        "8 source(s) failed to refresh: r2.example.com/repo trixie InRelease (404 "
        "Not Found); r3.example.com/repo trixie InRelease (404 Not Found); "
        "r4.example.com/repo trixie InRelease (404 Not Found); r5.example.com/repo "
        "trixie InRelease (404 Not Found); r6.example.com/repo trixie InRelease "
        "(404 Not Found); and 3 more. The source may have been removed or the suite "
        "renamed; fix or disable it.",
    ),
    "all_failed": (
        "failed",
        "8 source(s) failed to refresh: r2.example.com/repo trixie InRelease (404 Not "
        "Found); r3.example.com/repo trixie InRelease (404 Not Found); r4.example.com/repo "
        "trixie InRelease (404 Not Found); r5.example.com/repo trixie InRelease (404 Not "
        "Found); r6.example.com/repo trixie InRelease (404 Not Found); and 3 more. The "
        "source may have been removed or the suite renamed; fix or disable it.",
    ),
    "privilege": (
        "failed",
        "apt-get update reported: Could not open lock file /var/lib/apt/lists/lock. "
        "Refreshing APT metadata needs root or passwordless sudo on the host; set the "
        "credential's sudo method, or scan cached-only.",
    ),
    "privilege_with_ok_source": (
        "failed",
        "apt-get update reported: Unable to lock directory "
        "/var/lib/apt/lists/. Refreshing APT metadata needs root or "
        "passwordless sudo on the host; set the credential's sudo method, or "
        "scan cached-only.",
    ),
    "sudo_password": (
        "failed",
        "apt-get update exited with status 1. Run apt-get update on the host to see the "
        "full error.",
    ),
    "unsigned_exit100": (
        "failed",
        "apt-get update reported: The repository 'http://x ./ Release' is not "
        "signed.. Verify the repository signing key and that the source is signed.",
    ),
    "unsigned_exit0": (
        "partial",
        "apt-get update reported: GPG error: http://x ./ InRelease: NO_PUBKEY ABCDEF. "
        "Verify the repository signing key and that the source is signed.",
    ),
    "benign_warning": ("fresh", ""),
    "benign_warning_nonzero": (
        "failed",
        "apt-get update reported: Target Packages is configured multiple "
        "times. Run apt-get update on the host to see the full error.",
    ),
    "diag_on_stdout": (
        "partial",
        "apt-get update reported: Failed to fetch http://x.example.com/y Could not "
        "connect. Run apt-get update on the host to see the full error.",
    ),
    "diag_many": (
        "partial",
        "apt-get update reported: Failed to fetch http://h0.example.com/i Could not "
        "connect; Failed to fetch http://h1.example.com/i Could not connect; Failed to "
        "fetch http://h2.example.com/i Could not connect. Run apt-get update on the host to "
        "see the full error.",
    ),
    "diag_non_fetch_only": (
        "failed",
        "apt-get update reported: Something odd "
        "xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx...",
    ),
    "diag_non_fetch_exit0": ("fresh", ""),
    "generic_only": (
        "failed",
        "apt-get update reported: Some index files failed to download. They have been "
        "ignored.. Run apt-get update on the host to see the full error.",
    ),
    "network": (
        "failed",
        "apt-get update reported: Failed to fetch http://x/y Could not resolve 'x'. Run "
        "apt-get update on the host to see the full error.",
    ),
    "indented_diag_stdout": ("fresh", ""),
    "stderr_indented": (
        "partial",
        "apt-get update reported: Failed to fetch http://z/y timed out. Run apt-get "
        "update on the host to see the full error.",
    ),
    "secret_in_diag": (
        "failed",
        "apt-get update reported: Failed to fetch "
        "https://deploy:\xabredacted\xbb@h.example.com/d 401 Unauthorized. Run apt-get "
        "update on the host to see the full error.",
    ),
    "long_label": (
        "partial",
        "1 source(s) failed to refresh: "
        "h.example.com/pppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppppp...",
    ),
}


@pytest.mark.parametrize("name", sorted(CORPUS))
def test_classification_is_unchanged(name):
    assert classify_apt_refresh(*CORPUS[name]) == EXPECTED[name]


def test_clean_exit_with_no_refreshed_source_never_certifies_cached_lists():
    for stdout in ("", "Reading package lists...\n", "Ign:1 http://x/y InRelease\n"):
        state, detail = classify_apt_refresh(stdout, "", 0)
        assert state == APT_FAILED
        assert "refreshed no source" in detail
    assert classify_apt_refresh(HIT, "", 0) == (APT_FRESH, "")


def test_detail_is_redacted_and_bounded():
    for name in CORPUS:
        _, detail = classify_apt_refresh(*CORPUS[name])
        assert "Sekret99" not in detail
        assert "SentinelPw8f2c" not in detail
        assert "203.0.113" not in detail
        assert len(detail) <= APT_DETAIL_MAX_CHARS
    _, long_detail = classify_apt_refresh(*CORPUS["long_label"])
    assert long_detail.endswith("...")
    assert len(long_detail) == APT_DETAIL_MAX_CHARS


def test_privilege_failure_outranks_a_healthy_source():
    out = HIT + "Err:2 http://x.example.com/y ./ Packages\n  403  Forbidden\n"
    err = "E: Could not open lock file /var/lib/apt/lists/lock\n"
    for code in (0, 100):
        state, detail = classify_apt_refresh(out, err, code)
        assert state == APT_FAILED
        assert "root or passwordless sudo" in detail
