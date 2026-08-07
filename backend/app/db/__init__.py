"""Initialize the database module."""

from .base import Base  # This makes Base importable from app.db directly

# Import all models to ensure they're registered with SQLAlchemy
from .models import *  # noqa: F401,F403 - This imports all models from models.py
from .ssh_security_models import *  # noqa: F401,F403 - This imports SSH security models
