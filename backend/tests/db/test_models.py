import os

from sqlalchemy import create_engine, inspect


def get_inspector():
    url = os.environ["DATABASE_URL"]
    engine = create_engine(url)
    return inspect(engine)


def test_user_model_exists():
    inspector = get_inspector()
    assert "user" in inspector.get_table_names()


def test_role_model_exists():
    inspector = get_inspector()
    assert "role" in inspector.get_table_names()


def test_user_role_model_exists():
    inspector = get_inspector()
    assert "user_role" in inspector.get_table_names()
