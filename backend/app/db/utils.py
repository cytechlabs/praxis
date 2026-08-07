"""Database utility functions."""

from contextlib import contextmanager

from app.db.session import get_db


@contextmanager
def get_db_context():
    """Context manager wrapper for get_db."""
    db = get_db()
    try:
        yield db
    finally:
        db.close()
