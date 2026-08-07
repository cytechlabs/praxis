"""Database session management and Prometheus metrics (PRA-301).

Supported 1.0 backend exporter contract. All series below are emitted by normal
production code paths (``get_db`` request sessions and ``DatabaseSessionManager``).
Labels are low-cardinality and non-sensitive — no user/system IDs, hostnames,
SQL/command text, request paths, credentials, or exception strings ever appear.

    db_operations_total{operation_type}   Counter   one increment per DB session at
                                                     close; operation_type is the
                                                     bounded set {"success","error"}.
    db_operation_latency_seconds          Histogram observed once per DB session:
                                                     open-to-close duration.
    db_connections_in_use                 Gauge     connections currently checked out
                                                     of the pool (a true current gauge).
    db_connections_created_total          Counter   physical connections established
                                                     over the process lifetime.

The scrape listener binds a single port (``backend:9090``) for the supported
single-worker deployment — see ``start_metrics_server``. It is started explicitly
from the FastAPI lifecycle, not as an import side effect.
"""

import threading
import time
from typing import Generator, Optional

from prometheus_client import Counter, Gauge, Histogram, start_http_server
from sqlalchemy import create_engine, event
from sqlalchemy.orm import Session, sessionmaker
from sqlalchemy.pool import QueuePool

from .config import DatabaseSettings

# ------------------------------------------------------------------ metrics

DB_OPERATIONS = Counter(
    "db_operations_total",
    "Database sessions completed, by outcome (one increment per session at close).",
    ["operation_type"],  # bounded: "success" | "error"
)

DB_OPERATION_LATENCY = Histogram(
    "db_operation_latency_seconds",
    "Database session duration in seconds (open to close).",
    buckets=(0.1, 0.25, 0.5, 0.75, 1.0, 2.5, 5.0, 7.5, 10.0),
)

# Current pool state — a real gauge: checkout increments, checkin decrements.
DB_CONNECTIONS_IN_USE = Gauge(
    "db_connections_in_use",
    "Database connections currently checked out of the pool.",
)

# Cumulative lifetime event — a counter with a cumulative name.
DB_CONNECTIONS_CREATED = Counter(
    "db_connections_created_total",
    "Physical database connections established over the process lifetime.",
)


def _record_session(started_at: float, outcome: str) -> None:
    """Record a completed DB session's duration + outcome. ``outcome`` is a bounded
    label ("success"/"error"), never a free-form/exception string."""
    DB_OPERATION_LATENCY.observe(time.perf_counter() - started_at)
    DB_OPERATIONS.labels(operation_type=outcome).inc()


# ------------------------------------------------------------------ engine

settings = DatabaseSettings()

engine = create_engine(
    settings.sync_database_url,
    poolclass=QueuePool,
    pool_size=20,
    max_overflow=10,
    pool_timeout=30,
    pool_recycle=1800,
    pool_pre_ping=True,
)

SessionLocal = sessionmaker(
    autocommit=False,
    autoflush=False,
    bind=engine,
    expire_on_commit=False,
)


class DatabaseSessionManager:
    """Context manager for database sessions with per-instance timing.

    Each instance holds its OWN start time, so overlapping sessions never corrupt
    one another's latency/outcome observation (unlike the old shared tracker).
    """

    def __init__(self):
        self.db: Optional[Session] = None
        self._started_at: Optional[float] = None

    def __enter__(self) -> Session:
        self.db = SessionLocal()
        self._started_at = time.perf_counter()
        return self.db

    def __exit__(self, exc_type, exc_value, traceback):
        if self.db is None:
            return
        outcome = "success" if exc_type is None else "error"
        try:
            if exc_type is None:
                self.db.commit()
            else:
                self.db.rollback()
        finally:
            self.db.close()
            if self._started_at is not None:
                _record_session(self._started_at, outcome)
                self._started_at = None


def get_db() -> Generator[Session, None, None]:
    """FastAPI dependency that provides a database session.

    Records ``db_operations_total`` (with the request outcome) and
    ``db_operation_latency_seconds`` for every request session. Timing is LOCAL to
    the call — no shared process state — so concurrent requests cannot corrupt one
    another's observations.
    """
    db = SessionLocal()
    started_at = time.perf_counter()
    outcome = "success"
    try:
        yield db
    except Exception:  # pylint: disable=broad-except
        # The route handler raised; FastAPI throws it into this generator.
        outcome = "error"
        raise
    finally:
        db.close()
        _record_session(started_at, outcome)


# ---------------------------------------------------- connection pool events


@event.listens_for(engine, "checkout")
def _on_checkout(*_args):
    """A connection was checked out of the pool → in-use count rises."""
    DB_CONNECTIONS_IN_USE.inc()


@event.listens_for(engine, "checkin")
def _on_checkin(*_args):
    """A connection was returned to the pool → in-use count falls."""
    DB_CONNECTIONS_IN_USE.dec()


@event.listens_for(engine, "connect")
def _on_connect(*_args):
    """A new physical connection was established → cumulative counter rises."""
    DB_CONNECTIONS_CREATED.inc()


# ------------------------------------------------------- scrape listener

_metrics_server_started = False
_metrics_lock = threading.Lock()


def start_metrics_server(port: int = 9090) -> bool:
    """Start the Prometheus scrape listener for the supported single-worker backend.

    Idempotent: the first call binds ``0.0.0.0:<port>`` and returns True; subsequent
    calls are no-ops and return False. Praxis 1.0 assumes a single backend worker, so
    exactly one listener binds ``backend:9090`` — this is NOT a multi-worker
    aggregation solution. Called explicitly from the FastAPI startup lifecycle rather
    than as an import side effect, so tests are deterministic.
    """
    global _metrics_server_started  # pylint: disable=global-statement
    with _metrics_lock:
        if _metrics_server_started:
            return False
        start_http_server(port)
        _metrics_server_started = True
        return True
