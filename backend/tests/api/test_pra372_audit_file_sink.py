"""PRA-372: local-file audit sinks are confined to the audit file sink root.

Covers the whole boundary rather than one layer:

* the guard's root and target rules, including sensitive-root rejection and a
  configured root that is, or sits behind, a symlink;
* confined delivery, including symlinked components, a symlink swapped in after
  validation (a resolve-then-open implementation would follow it), and a record
  completed across partial writes;
* the ``/audit/sinks`` create and update routes, including rejection of
  already-existing symlinked components and that http and syslog targets keep
  their existing behavior;
* a legacy absolute-path row failing visibly instead of being rewritten,
  redirected, or written anywhere; and
* the Compose wiring that supplies the root and its backend-only volume.
"""

import errno
import os
import re
import socket
from pathlib import Path

import pytest

from app.db.access_models import AuditSink, AuditSinkDelivery
from app.services import audit_event_service as aes
from app.services import audit_file_sink_guard as guard

REPO = Path(__file__).resolve().parents[3]
COMPOSE = REPO / "docker-compose.yml"
COMPOSE_PROD = REPO / "docker-compose.prod.yml"
DOCKERFILE_PROD = REPO / "backend" / "Dockerfile.prod"

# The http sink guard resolves DNS; map a fake public name so the http
# regression tests never depend on live resolution.
_REAL_GETADDRINFO = socket.getaddrinfo
_NAMES = {"collector.audit.test": "93.184.216.34"}


def _fake_getaddrinfo(host, *args, **kwargs):
    if host in _NAMES:
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", (_NAMES[host], 0))]
    return _REAL_GETADDRINFO(host, *args, **kwargs)


@pytest.fixture(autouse=True)
def _patch_dns(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", _fake_getaddrinfo)


@pytest.fixture
def sink_root(tmp_path, monkeypatch):
    """An isolated, configured audit file sink root."""
    root = tmp_path / "audit-sinks"
    root.mkdir()
    monkeypatch.setenv(guard.ROOT_ENV, str(root))
    return root


def _file_sink(target, name="pra372-file"):
    return AuditSink(
        name=name, kind="file", target=target, enabled=True, config_json="{}"
    )


def _create(client, kind, target, name="pra372-sink"):
    return client.post(
        "/audit/sinks",
        json={"name": name, "kind": kind, "target": target, "enabled": True},
    )


# ---- root policy -----------------------------------------------------------


def test_default_root_is_the_dedicated_volume_path(monkeypatch):
    monkeypatch.delenv(guard.ROOT_ENV, raising=False)
    assert guard.configured_root() == Path("/data/praxis/audit-sinks")


def test_root_is_read_from_the_environment_on_every_call(tmp_path, monkeypatch):
    # No import-time frozen value: changing the variable changes the answer.
    first = tmp_path / "one"
    second = tmp_path / "two"
    monkeypatch.setenv(guard.ROOT_ENV, str(first))
    assert guard.configured_root() == first
    monkeypatch.setenv(guard.ROOT_ENV, str(second))
    assert guard.configured_root() == second


@pytest.mark.parametrize(
    "root",
    [
        "/",
        "/app",
        "/app/data",
        "/vault",
        "/vault/data/audit",
        "/etc",
        "/etc/praxis",
        "/proc/self",
        "/sys/kernel",
        "/dev/shm",
        "/run/praxis",
        "/root/audit",
        "/boot",
        "/data/praxis/../../etc/audit",
        "/data/./praxis/audit",
        "relative/path",
        "",
    ],
)
def test_sensitive_or_malformed_root_is_rejected(root, monkeypatch):
    monkeypatch.setenv(guard.ROOT_ENV, root)
    if root == "":
        # An empty value falls back to the default, which must stay usable.
        assert guard.configured_root() == Path(guard.DEFAULT_ROOT)
        return
    with pytest.raises(guard.FileSinkTargetError):
        guard.configured_root()


def test_default_root_is_not_itself_a_rejected_location(monkeypatch):
    monkeypatch.setenv(guard.ROOT_ENV, guard.DEFAULT_ROOT)
    assert guard.configured_root() == Path(guard.DEFAULT_ROOT)


# ---- symlinked root and root ancestor --------------------------------------


@pytest.fixture
def symlinked_root(tmp_path, monkeypatch):
    """A configured root that is itself a symlink to a real directory."""
    real = tmp_path / "real-root"
    real.mkdir()
    link = tmp_path / "linked-root"
    link.symlink_to(real, target_is_directory=True)
    monkeypatch.setenv(guard.ROOT_ENV, str(link))
    return real


@pytest.fixture
def symlinked_root_ancestor(tmp_path, monkeypatch):
    """A configured root that sits behind a symlinked ancestor directory."""
    real = tmp_path / "real-parent"
    (real / "sinks").mkdir(parents=True)
    (tmp_path / "linked-parent").symlink_to(real, target_is_directory=True)
    monkeypatch.setenv(guard.ROOT_ENV, str(tmp_path / "linked-parent" / "sinks"))
    return real / "sinks"


def test_symlinked_root_is_refused_at_delivery(symlinked_root):
    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("audit.jsonl", '{"event":1}')
    assert list(symlinked_root.iterdir()) == []


def test_symlinked_root_is_refused_at_validation(symlinked_root):
    with pytest.raises(guard.FileSinkTargetError):
        guard.validate("audit.jsonl")
    assert list(symlinked_root.iterdir()) == []


def test_symlinked_root_is_refused_at_the_route(authed_client, symlinked_root):
    res = _create(authed_client, "file", "audit.jsonl", name="pra372-root-link")
    assert res.status_code == 400, res.text
    assert "symlink" in res.json()["detail"]
    assert list(symlinked_root.iterdir()) == []


def test_symlinked_root_ancestor_is_refused_at_delivery(symlinked_root_ancestor):
    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("audit.jsonl", '{"event":1}')
    assert list(symlinked_root_ancestor.iterdir()) == []


def test_symlinked_root_ancestor_is_refused_at_the_route(
    authed_client, symlinked_root_ancestor
):
    res = _create(authed_client, "file", "audit.jsonl", name="pra372-anc-link")
    assert res.status_code == 400, res.text
    assert "symlink" in res.json()["detail"]
    assert list(symlinked_root_ancestor.iterdir()) == []


def test_missing_root_is_created_on_first_use(tmp_path, monkeypatch):
    root = tmp_path / "made" / "on" / "demand"
    monkeypatch.setenv(guard.ROOT_ENV, str(root))
    guard.append_line("audit.jsonl", '{"event":1}')
    assert (root / "audit.jsonl").read_text(encoding="utf-8") == '{"event":1}\n'


# ---- target shape ----------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "audit.jsonl",
        "exports/audit.jsonl",
        "exports/2026/audit.jsonl",
    ],
)
def test_valid_relative_targets_are_accepted(target, sink_root):
    guard.validate(target)


@pytest.mark.parametrize(
    "target",
    [
        "/etc/cron.d/praxis",  # absolute
        "/audit.jsonl",  # absolute, inside-looking
        "",  # empty
        "   ",  # whitespace only
        ".",  # dot
        "..",  # dot-dot
        "./audit.jsonl",  # leading dot segment
        "../audit.jsonl",  # traversal
        "exports/../../etc/passwd",  # traversal through a valid prefix
        "exports/./audit.jsonl",  # interior dot segment
        "exports//audit.jsonl",  # empty segment
        "exports/",  # directory, no file
        "audit.jsonl\x00.txt",  # embedded NUL
    ],
)
def test_invalid_targets_are_rejected(target, sink_root):
    with pytest.raises(guard.FileSinkTargetError):
        guard.validate(target)


def test_rejection_message_bounds_a_long_target(sink_root):
    long_target = "/" + ("a" * 1000) + ".jsonl"
    with pytest.raises(guard.FileSinkTargetError) as excinfo:
        guard.validate(long_target)
    assert len(str(excinfo.value)) < 300


# ---- existing components at validation time --------------------------------


def test_validate_accepts_a_target_whose_directories_do_not_exist_yet(sink_root):
    # Nested directories are created on first delivery, so a missing chain is
    # valid. Validation must not create it either.
    guard.validate("exports/2026/audit.jsonl")
    assert list(sink_root.iterdir()) == []


def test_validate_accepts_an_existing_regular_file_target(sink_root):
    (sink_root / "audit.jsonl").write_text("prior\n", encoding="utf-8")
    guard.validate("audit.jsonl")


def test_validate_rejects_an_existing_symlinked_parent(sink_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (sink_root / "exports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(guard.FileSinkTargetError) as excinfo:
        guard.validate("exports/audit.jsonl")
    assert "symlink" in str(excinfo.value)


def test_validate_rejects_an_existing_symlinked_final_target(sink_root, tmp_path):
    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched\n", encoding="utf-8")
    (sink_root / "audit.jsonl").symlink_to(outside)

    with pytest.raises(guard.FileSinkTargetError) as excinfo:
        guard.validate("audit.jsonl")
    assert "symlink" in str(excinfo.value)
    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_validate_rejects_a_parent_that_is_not_a_directory(sink_root):
    (sink_root / "exports").write_text("a file, not a directory\n", encoding="utf-8")
    with pytest.raises(guard.FileSinkTargetError) as excinfo:
        guard.validate("exports/audit.jsonl")
    assert "not a directory" in str(excinfo.value)


def test_validate_rejects_a_final_target_that_is_not_a_regular_file(sink_root):
    (sink_root / "audit.jsonl").mkdir()
    with pytest.raises(guard.FileSinkTargetError) as excinfo:
        guard.validate("audit.jsonl")
    assert "regular file" in str(excinfo.value)


# ---- confined delivery -----------------------------------------------------


def test_top_level_target_appends_jsonl_under_the_root(sink_root):
    guard.append_line("audit.jsonl", '{"event":1}')
    guard.append_line("audit.jsonl", '{"event":2}\n')
    assert (sink_root / "audit.jsonl").read_text(encoding="utf-8") == (
        '{"event":1}\n{"event":2}\n'
    )


def test_nested_target_creates_missing_directories_under_the_root(sink_root):
    guard.append_line("exports/2026/audit.jsonl", '{"event":1}')
    written = sink_root / "exports" / "2026" / "audit.jsonl"
    assert written.read_text(encoding="utf-8") == '{"event":1}\n'
    assert (sink_root / "exports").is_dir()


def test_symlinked_parent_component_is_rejected(sink_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (sink_root / "exports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("exports/audit.jsonl", '{"event":1}')
    assert list(outside.iterdir()) == []


def test_symlinked_deep_parent_component_is_rejected(sink_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    (sink_root / "exports").mkdir()
    (sink_root / "exports" / "2026").symlink_to(outside, target_is_directory=True)

    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("exports/2026/audit.jsonl", '{"event":1}')
    assert list(outside.iterdir()) == []


def test_symlinked_final_target_is_rejected(sink_root, tmp_path):
    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched\n", encoding="utf-8")
    (sink_root / "audit.jsonl").symlink_to(outside)

    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("audit.jsonl", '{"event":1}')
    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_symlink_swapped_in_after_validation_cannot_escape(sink_root, tmp_path):
    # Time-of-check to time-of-use: the target validates cleanly, then the final
    # component becomes a symlink before the write. Pinning the parent directory
    # and opening the file no-follow is what makes the swap lose.
    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched\n", encoding="utf-8")
    guard.validate("audit.jsonl")
    (sink_root / "audit.jsonl").symlink_to(outside)

    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("audit.jsonl", '{"event":1}')
    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_parent_directory_swapped_to_symlink_cannot_escape(sink_root, tmp_path):
    outside = tmp_path / "outside"
    outside.mkdir()
    guard.append_line("exports/audit.jsonl", '{"event":1}')

    (sink_root / "exports" / "audit.jsonl").unlink()
    (sink_root / "exports").rmdir()
    (sink_root / "exports").symlink_to(outside, target_is_directory=True)

    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("exports/audit.jsonl", '{"event":2}')
    assert list(outside.iterdir()) == []


def test_directory_target_is_rejected_at_delivery(sink_root):
    (sink_root / "exports").mkdir()
    with pytest.raises(guard.FileSinkTargetError):
        guard.append_line("exports", '{"event":1}')


def test_append_finishes_a_record_across_partial_writes(sink_root, monkeypatch):
    # os.write may accept fewer bytes than offered. The append must loop until
    # the whole record lands rather than leaving a truncated JSON line behind.
    record = b'{"event":1}\n'
    real_write = os.write
    accepted = []

    def chunked_write(fd, data):
        chunk = bytes(data)
        if chunk and chunk in record:
            accepted.append(len(chunk))
            return real_write(fd, memoryview(data)[:3])
        return real_write(fd, data)

    monkeypatch.setattr(guard.os, "write", chunked_write)
    guard.append_line("audit.jsonl", '{"event":1}')
    monkeypatch.undo()

    assert accepted == [12, 9, 6, 3]
    assert (sink_root / "audit.jsonl").read_text(encoding="utf-8") == '{"event":1}\n'


def test_append_raises_when_a_write_makes_no_progress(sink_root, monkeypatch):
    record = b'{"event":1}\n'
    real_write = os.write

    def stalled_write(fd, data):
        if bytes(data) == record:
            return 0
        return real_write(fd, data)

    monkeypatch.setattr(guard.os, "write", stalled_write)
    with pytest.raises(OSError) as excinfo:
        guard.append_line("audit.jsonl", '{"event":1}')
    monkeypatch.undo()

    assert not isinstance(excinfo.value, guard.FileSinkTargetError)
    assert excinfo.value.errno == errno.EIO
    assert (sink_root / "audit.jsonl").read_text(encoding="utf-8") == ""


def test_send_file_reports_a_rejected_target_as_an_audit_error(sink_root):
    sink = _file_sink("../escape.jsonl")
    with pytest.raises(aes.AuditError) as excinfo:
        aes._send_file(sink, '{"event":1}')
    assert "file sink target rejected" in str(excinfo.value)


def test_send_file_writes_a_valid_relative_target(sink_root):
    aes._send_file(_file_sink("exports/audit.jsonl"), '{"event":1}')
    assert (sink_root / "exports" / "audit.jsonl").read_text(encoding="utf-8") == (
        '{"event":1}\n'
    )


# ---- delivery-path behavior for stored rows --------------------------------


def _queued_delivery(db, sink, action):
    event = aes.emit(db, action=action)
    return (
        db.query(AuditSinkDelivery)
        .filter(
            AuditSinkDelivery.sink_id == sink.id,
            AuditSinkDelivery.event_id == event.id,
        )
        .first()
    )


def test_legacy_absolute_row_fails_visibly_without_writing(db, sink_root, tmp_path):
    # A row that predates the confinement rules keeps its stored target. Delivery
    # must fail with an actionable error and must not write or redirect.
    legacy_path = tmp_path / "legacy.jsonl"
    sink = _file_sink(str(legacy_path), name="pra372-legacy")
    db.add(sink)
    db.commit()

    delivery = _queued_delivery(db, sink, "test.legacy")
    aes._deliver_one(db, delivery)
    db.refresh(delivery)
    db.refresh(sink)

    assert delivery.status == "pending"
    assert delivery.attempts == 1
    assert "file sink target rejected" in (delivery.last_error or "")
    assert len(delivery.last_error) < 500
    assert not legacy_path.exists()
    assert list(sink_root.iterdir()) == []
    # The stored target is untouched: no migration, no silent rewrite.
    assert sink.target == str(legacy_path)


def test_legacy_absolute_row_dead_letters_rather_than_writing(db, sink_root, tmp_path):
    legacy_path = tmp_path / "legacy-dead.jsonl"
    sink = _file_sink(str(legacy_path), name="pra372-legacy-dead")
    db.add(sink)
    db.commit()

    delivery = _queued_delivery(db, sink, "test.legacy.dead")
    delivery.attempts = aes.MAX_ATTEMPTS - 1
    db.commit()

    aes._deliver_one(db, delivery)
    db.refresh(delivery)
    assert delivery.status == "dead_letter"
    assert not legacy_path.exists()


def test_delivery_revalidates_after_the_stored_target_changes(db, sink_root):
    sink = _file_sink("audit.jsonl", name="pra372-retarget")
    db.add(sink)
    db.commit()

    first = _queued_delivery(db, sink, "test.retarget.ok")
    aes._deliver_one(db, first)
    db.refresh(first)
    assert first.status == "delivered"

    # The row changes to an unsafe target outside the route boundary.
    sink.target = "../escape.jsonl"
    db.commit()

    second = _queued_delivery(db, sink, "test.retarget.bad")
    aes._deliver_one(db, second)
    db.refresh(second)
    assert second.status == "pending"
    assert "file sink target rejected" in (second.last_error or "")
    assert not (sink_root.parent / "escape.jsonl").exists()


def test_delivery_revalidates_after_the_root_changes(db, sink_root, monkeypatch):
    sink = _file_sink("audit.jsonl", name="pra372-reroot")
    db.add(sink)
    db.commit()

    first = _queued_delivery(db, sink, "test.reroot.ok")
    aes._deliver_one(db, first)
    db.refresh(first)
    assert first.status == "delivered"

    # The operator repoints the root at a sensitive location.
    monkeypatch.setenv(guard.ROOT_ENV, "/etc/praxis-audit")
    second = _queued_delivery(db, sink, "test.reroot.bad")
    aes._deliver_one(db, second)
    db.refresh(second)
    assert second.status == "pending"
    assert "file sink target rejected" in (second.last_error or "")


# ---- route boundary --------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "/etc/cron.d/praxis",
        "",
        "..",
        "../audit.jsonl",
        "exports/../../etc/passwd",
        "exports/",
        "./audit.jsonl",
    ],
)
def test_create_rejects_invalid_file_target(authed_client, sink_root, target):
    res = _create(authed_client, "file", target, name="pra372-bad")
    assert res.status_code == 400, res.text


def test_create_accepts_valid_relative_file_target(authed_client, sink_root):
    res = _create(authed_client, "file", "exports/audit.jsonl", name="pra372-ok")
    assert res.status_code == 200, res.text
    assert res.json()["sink"]["target"] == "exports/audit.jsonl"


def test_create_rejects_file_target_when_root_is_sensitive(authed_client, monkeypatch):
    monkeypatch.setenv(guard.ROOT_ENV, "/etc/praxis-audit")
    res = _create(authed_client, "file", "audit.jsonl", name="pra372-bad-root")
    assert res.status_code == 400, res.text


def test_update_rejects_invalid_file_target(authed_client, sink_root):
    created = _create(authed_client, "file", "audit.jsonl", name="pra372-upd")
    assert created.status_code == 200, created.text
    sink_id = created.json()["sink"]["id"]

    res = authed_client.patch(
        f"/audit/sinks/{sink_id}", json={"target": "../escape.jsonl"}
    )
    assert res.status_code == 400, res.text

    # The stored target is unchanged by the rejected update.
    listed = authed_client.get("/audit/sinks")
    stored = [s for s in listed.json()["sinks"] if s["id"] == sink_id][0]
    assert stored["target"] == "audit.jsonl"


def test_update_accepts_valid_relative_file_target(authed_client, sink_root):
    created = _create(authed_client, "file", "audit.jsonl", name="pra372-upd-ok")
    sink_id = created.json()["sink"]["id"]
    res = authed_client.patch(
        f"/audit/sinks/{sink_id}", json={"target": "exports/audit.jsonl"}
    )
    assert res.status_code == 200, res.text
    assert res.json()["sink"]["target"] == "exports/audit.jsonl"


# ---- route rejects existing symlinked components ---------------------------


def test_create_rejects_a_symlinked_parent_component(
    authed_client, sink_root, tmp_path
):
    outside = tmp_path / "outside"
    outside.mkdir()
    (sink_root / "exports").symlink_to(outside, target_is_directory=True)

    res = _create(authed_client, "file", "exports/audit.jsonl", name="pra372-link-dir")
    assert res.status_code == 400, res.text
    # The 400 comes from the confinement guard, not an earlier layer.
    assert "symlink" in res.json()["detail"]
    assert list(outside.iterdir()) == []


def test_create_rejects_a_symlinked_final_target(authed_client, sink_root, tmp_path):
    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched\n", encoding="utf-8")
    (sink_root / "audit.jsonl").symlink_to(outside)

    res = _create(authed_client, "file", "audit.jsonl", name="pra372-link-file")
    assert res.status_code == 400, res.text
    assert "symlink" in res.json()["detail"]
    assert outside.read_text(encoding="utf-8") == "untouched\n"


def test_create_rejects_a_parent_that_is_not_a_directory(authed_client, sink_root):
    (sink_root / "exports").write_text("a file, not a directory\n", encoding="utf-8")
    res = _create(authed_client, "file", "exports/audit.jsonl", name="pra372-notdir")
    assert res.status_code == 400, res.text
    assert "not a directory" in res.json()["detail"]


def test_create_rejects_a_final_target_that_is_not_a_regular_file(
    authed_client, sink_root
):
    (sink_root / "audit.jsonl").mkdir()
    res = _create(authed_client, "file", "audit.jsonl", name="pra372-notfile")
    assert res.status_code == 400, res.text
    assert "regular file" in res.json()["detail"]


def test_update_rejects_a_symlinked_parent_and_keeps_the_stored_target(
    authed_client, sink_root, tmp_path
):
    created = _create(authed_client, "file", "audit.jsonl", name="pra372-upd-link-dir")
    assert created.status_code == 200, created.text
    sink_id = created.json()["sink"]["id"]

    outside = tmp_path / "outside"
    outside.mkdir()
    (sink_root / "exports").symlink_to(outside, target_is_directory=True)

    res = authed_client.patch(
        f"/audit/sinks/{sink_id}", json={"target": "exports/audit.jsonl"}
    )
    assert res.status_code == 400, res.text
    assert "symlink" in res.json()["detail"]

    listed = authed_client.get("/audit/sinks")
    stored = [s for s in listed.json()["sinks"] if s["id"] == sink_id][0]
    assert stored["target"] == "audit.jsonl"
    assert list(outside.iterdir()) == []


def test_update_rejects_a_symlinked_final_target_and_keeps_the_stored_target(
    authed_client, sink_root, tmp_path
):
    created = _create(authed_client, "file", "audit.jsonl", name="pra372-upd-link-file")
    assert created.status_code == 200, created.text
    sink_id = created.json()["sink"]["id"]

    outside = tmp_path / "outside.jsonl"
    outside.write_text("untouched\n", encoding="utf-8")
    (sink_root / "swapped.jsonl").symlink_to(outside)

    res = authed_client.patch(
        f"/audit/sinks/{sink_id}", json={"target": "swapped.jsonl"}
    )
    assert res.status_code == 400, res.text
    assert "symlink" in res.json()["detail"]

    listed = authed_client.get("/audit/sinks")
    stored = [s for s in listed.json()["sinks"] if s["id"] == sink_id][0]
    assert stored["target"] == "audit.jsonl"
    assert outside.read_text(encoding="utf-8") == "untouched\n"


# ---- other sink kinds are untouched ----------------------------------------


def test_syslog_target_is_unaffected_by_file_confinement(authed_client, sink_root):
    res = _create(authed_client, "syslog", "siem.example.com:6514", name="pra372-sys")
    assert res.status_code == 200, res.text
    assert res.json()["sink"]["target"] == "siem.example.com:6514"


def test_syslog_target_shaped_like_a_rejected_file_path_still_saves(
    authed_client, sink_root
):
    # File-path rules must not leak onto syslog targets.
    res = _create(authed_client, "syslog", "/var/run/syslog", name="pra372-sys-path")
    assert res.status_code == 200, res.text


def test_http_target_keeps_its_ssrf_behavior(authed_client, sink_root, monkeypatch):
    monkeypatch.delenv("AUDIT_SINK_ALLOW_PRIVATE_TARGETS", raising=False)
    allowed = _create(
        authed_client, "http", "https://collector.audit.test/audit", name="pra372-http"
    )
    assert allowed.status_code == 200, allowed.text

    blocked = _create(
        authed_client, "http", "http://127.0.0.1/audit", name="pra372-http-bad"
    )
    assert blocked.status_code == 400, blocked.text


# ---- deployment wiring -----------------------------------------------------


def _service_code(text: str, name: str) -> str:
    """A compose service block with comment lines stripped, so a comment cannot
    satisfy an assertion."""
    header = re.compile(rf"^  {re.escape(name)}:\s*$")
    next_two_space = re.compile(r"^  \S")
    out = []
    in_block = False
    for line in text.splitlines():
        if not in_block:
            if header.match(line):
                in_block = True
            continue
        if next_two_space.match(line) or (
            line and not line.startswith(" ") and line.rstrip().endswith(":")
        ):
            break
        out.append(line)
    return "\n".join(ln for ln in out if not ln.lstrip().startswith("#"))


@pytest.mark.skipif(
    not COMPOSE.exists() or not COMPOSE_PROD.exists(),
    reason="compose files not available",
)
def test_compose_supplies_the_audit_file_sink_root_and_volume():
    base = COMPOSE.read_text()
    backend = _service_code(base, "backend")
    assert "AUDIT_FILE_SINK_ROOT=${AUDIT_FILE_SINK_ROOT:-/data/praxis/audit-sinks}" in (
        backend
    ), "base backend must supply the audit file sink root"
    assert (
        "audit_sink_data:/data/praxis/audit-sinks" in backend
    ), "base backend must mount the dedicated audit sink volume"
    assert re.search(
        r"^volumes:\n(?:.*\n)*?  audit_sink_data:\s*$", base, re.MULTILINE
    ), "audit_sink_data must be declared as a named volume"


@pytest.mark.skipif(
    not COMPOSE.exists() or not COMPOSE_PROD.exists(),
    reason="compose files not available",
)
def test_prod_overlay_keeps_the_audit_sink_volume():
    # The prod overlay replaces the base volume list, so the mount must repeat.
    backend = _service_code(COMPOSE_PROD.read_text(), "backend")
    assert "volumes: !override" in backend
    assert (
        "audit_sink_data:/data/praxis/audit-sinks" in backend
    ), "prod backend must keep the audit sink volume"


@pytest.mark.skipif(
    not COMPOSE.exists() or not COMPOSE_PROD.exists(),
    reason="compose files not available",
)
def test_audit_sink_volume_is_backend_only():
    for text in (COMPOSE.read_text(), COMPOSE_PROD.read_text()):
        for service in ("agent-broker", "frontend", "db", "db_backup", "caddy"):
            block = _service_code(text, service)
            assert (
                "audit_sink_data" not in block
            ), f"{service} must not mount the audit sink volume"


@pytest.mark.skipif(
    not DOCKERFILE_PROD.exists(), reason="production Dockerfile not available"
)
def test_production_image_owns_the_default_root_for_the_runtime_user():
    dockerfile = DOCKERFILE_PROD.read_text()
    mkdir = re.search(
        r"RUN mkdir -p [^\n]*/data/praxis/audit-sinks[^\n]*\n(?:[^\n]*\n)?",
        dockerfile,
    )
    assert mkdir, "the production image must pre-create the audit sink mount point"
    assert "chown -R praxis:praxis /data" in mkdir.group(0)
    assert dockerfile.index(mkdir.group(0)) < dockerfile.index("USER praxis")
