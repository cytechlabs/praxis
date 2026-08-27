"""PRA-416: a programmatic Alembic run must not disable existing application loggers.

``alembic/env.py`` configures Python logging from ``alembic.ini``. Migrations also
run in-process, from tests and from maintenance tooling, so that configuration
lands in a process where ``app.*`` loggers already exist. The standard-library
default for ``logging.config.fileConfig`` disables every logger the ini file does
not name, which silently mutes those loggers for the rest of the process: records
are never created at all, so redaction, diagnostic, and error-handling assertions
have nothing left to observe.

These tests pin both sides of the contract. An application logger that existed
before the run stays enabled and keeps reaching a handler attached to it, and the
``alembic`` and ``sqlalchemy.engine`` loggers the ini file does configure keep
their levels without accumulating handlers or duplicating records.

The migration run here is offline over an empty ``head:head`` range: env.py
executes exactly as it does for a real migration, but renders SQL instead of
connecting and applies no revision, so the logging setup is the only behavior
under test.
"""

from __future__ import annotations

import io
import logging
from contextlib import contextmanager
from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from alembic.script import ScriptDirectory

from app.services import patch_approval_service

BACKEND_ROOT = Path(__file__).resolve().parents[2]
ALEMBIC_INI = BACKEND_ROOT / "alembic.ini"
ALEMBIC_DIR = BACKEND_ROOT / "alembic"

# A logger a production module creates at import time, and a synthetic sibling.
# Both are ordinary ``app.*`` loggers, which is the whole population at risk.
PRODUCTION_LOGGER = patch_approval_service.logger.name
SYNTHETIC_LOGGER = "app.tests.alembic_logger_preservation"


class _CaptureHandler(logging.Handler):
    """Collect records so a test can assert on what a logger actually emitted."""

    def __init__(self) -> None:
        super().__init__()
        self.records: list[logging.LogRecord] = []

    def emit(self, record: logging.LogRecord) -> None:
        self.records.append(record)

    def messages(self) -> list[str]:
        """Return the formatted message of every record seen, in order."""
        return [record.getMessage() for record in self.records]


@contextmanager
def _isolated_logging_state():
    """Snapshot and restore the process-wide logging configuration.

    Reading ``alembic.ini`` reconfigures the root logger for the whole process,
    and creating a logger adds it to a registry that outlives the test. Both are
    undone here so these tests do not change what any other test in the lane
    observes.

    Cleanup covers three things: the registry regains exactly the entries it had,
    so a logger created inside the block cannot go on receiving records through a
    handler attached inside it; every logger object that already existed is the
    same object afterwards, with its level, propagation, disabled flag and
    handlers restored; and the root logger and the global disable threshold go
    back to their previous values. Nothing outside that snapshot is touched.
    """
    manager = logging.Logger.manager
    root = logging.getLogger()
    saved_disable = manager.disable
    saved_root_level = root.level
    saved_root_handlers = list(root.handlers)
    registry: dict[str, object] = dict(manager.loggerDict)
    saved_loggers: dict[str, tuple[int, bool, bool, list[logging.Handler]]] = {}
    saved_placeholders: dict[str, dict] = {}
    for name, entry in registry.items():
        if isinstance(entry, logging.Logger):
            saved_loggers[name] = (
                entry.level,
                entry.propagate,
                entry.disabled,
                list(entry.handlers),
            )
        else:
            saved_placeholders[name] = dict(entry.loggerMap)
    try:
        yield
    finally:
        # Drop the entries the block added, then put the original objects back at
        # their own names. Pre-existing loggers are restored, never replaced.
        for name in [n for n in manager.loggerDict if n not in registry]:
            del manager.loggerDict[name]
        manager.loggerDict.update(registry)
        # A placeholder tracks the child loggers below it, so one that outlived a
        # removed child needs that link dropped too.
        for name, logger_map in saved_placeholders.items():
            entry = manager.loggerDict[name]
            if isinstance(entry, logging.PlaceHolder):
                entry.loggerMap = dict(logger_map)
        for name, (level, propagate, disabled, handlers) in saved_loggers.items():
            entry = manager.loggerDict[name]
            if isinstance(entry, logging.Logger):
                entry.setLevel(level)
                entry.propagate = propagate
                entry.disabled = disabled
                entry.handlers = handlers
        root.setLevel(saved_root_level)
        root.handlers = saved_root_handlers
        # setLevel and disable both invalidate the cached isEnabledFor results.
        logging.disable(saved_disable)


@pytest.fixture
def offline_database_url(monkeypatch):
    """Supply the explicit database URL env.py requires before it will run.

    env.py refuses to build a URL when none is configured. Offline mode never
    opens a connection, so a fixed unroutable address with no password keeps the
    test independent of local configuration.
    """
    monkeypatch.setenv("DATABASE_URL", "postgresql://praxis@127.0.0.1:1/praxis")


def _run_alembic_env() -> None:
    """Execute ``alembic/env.py`` the way a migration run does, without a database."""
    config = Config(str(ALEMBIC_INI), output_buffer=io.StringIO())
    config.set_main_option("script_location", str(ALEMBIC_DIR))
    head = ScriptDirectory.from_config(config).get_current_head()
    command.upgrade(config, f"{head}:{head}", sql=True)


@pytest.mark.parametrize("logger_name", [PRODUCTION_LOGGER, SYNTHETIC_LOGGER])
def test_existing_app_logger_still_emits_after_migration_logging_setup(
    offline_database_url, logger_name
):
    """A warning emitted after the run still reaches a handler attached before it."""
    with _isolated_logging_state():
        logger = logging.getLogger(logger_name)
        # Establish the precondition the run must not destroy. Everything the
        # test asserts is measured after the run, never repaired after it.
        logging.disable(logging.NOTSET)
        logger.disabled = False
        logger.setLevel(logging.WARNING)
        capture = _CaptureHandler()
        logger.addHandler(capture)

        _run_alembic_env()

        assert logger.disabled is False
        assert logger.isEnabledFor(logging.WARNING)

        logger.warning("visible after migration logging setup")

        assert capture.messages() == ["visible after migration logging setup"]


def test_migration_logging_stays_configured_without_duplicates(offline_database_url):
    """Alembic and SQLAlchemy logging survives repeat runs with one record per emit."""
    with _isolated_logging_state():
        # Same precondition discipline as above: set the starting state before
        # the run, then assert only on what the run left behind.
        logging.disable(logging.NOTSET)

        _run_alembic_env()
        _run_alembic_env()

        assert logging.getLogger("alembic").level == logging.INFO
        assert logging.getLogger("sqlalchemy.engine").level == logging.WARNING
        # The ini file gives those loggers no handlers of their own, and repeat
        # runs replace the root console handler rather than stacking another.
        assert logging.getLogger("alembic").handlers == []
        assert logging.getLogger("sqlalchemy.engine").handlers == []
        assert len(logging.getLogger().handlers) == 1

        root_capture = _CaptureHandler()
        logging.getLogger().addHandler(root_capture)
        logging.getLogger("alembic.runtime.migration").info("single migration record")

        assert root_capture.messages() == ["single migration record"]


def test_isolation_context_removes_the_loggers_it_created():
    """A logger made inside the isolation block does not outlive it.

    The block above attaches a capture handler to a logger it creates. If that
    logger stayed in the registry, every later test asking for the same name
    would get it back with the handler still attached, which is the leak the
    helper exists to prevent. The whole body runs inside an outer block so this
    test's own probe is cleaned up the same way.
    """
    name = "app.tests.alembic_logger_isolation_probe"
    leaked = _CaptureHandler()

    with _isolated_logging_state():
        logging.disable(logging.NOTSET)
        assert name not in logging.Logger.manager.loggerDict

        with _isolated_logging_state():
            created = logging.getLogger(name)
            created.setLevel(logging.WARNING)
            created.addHandler(leaked)
            created.warning("emitted inside the context")

        assert leaked.messages() == ["emitted inside the context"]
        assert name not in logging.Logger.manager.loggerDict

        # A later caller gets a new logger object, so the handler attached inside
        # the block is unreachable and observes nothing emitted after it.
        replacement = logging.getLogger(name)
        replacement.setLevel(logging.WARNING)
        observed = _CaptureHandler()
        replacement.addHandler(observed)
        replacement.warning("emitted after cleanup")

        assert replacement is not created
        assert observed.messages() == ["emitted after cleanup"]
        assert leaked.messages() == ["emitted inside the context"]
