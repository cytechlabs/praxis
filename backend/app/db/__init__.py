"""Initialize the database module."""

from .base import Base  # This makes Base importable from app.db directly

# Import all models to ensure they're registered with SQLAlchemy
from .models import *  # noqa: F401,F403 - This imports all models from models.py
from .ssh_security_models import *  # noqa: F401,F403 - This imports SSH security models

# Only Base is part of this package's public surface. The star imports above run
# for their registration side effect: they populate Base.metadata so that
# create_all and Alembic autogenerate can see every table. Import model classes
# from their defining module rather than from this package.
__all__ = ["Base"]
