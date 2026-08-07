"""Defines the base class for all database models."""

from datetime import datetime

from sqlalchemy import DateTime, Integer
from sqlalchemy.orm import DeclarativeBase, Mapped, declared_attr, mapped_column


class Base(DeclarativeBase):  # pylint: disable=too-few-public-methods
    """Base class for all database models."""

    @declared_attr
    def __tablename__(cls) -> str:  # pylint: disable=no-self-argument
        """Generate table name automatically."""
        return cls.__name__.lower()

    id: Mapped[int] = mapped_column(Integer, primary_key=True, index=True)
    created_at: Mapped[datetime] = mapped_column(
        DateTime, default=datetime.utcnow, nullable=False
    )
    updated_at: Mapped[datetime] = mapped_column(
        DateTime,
        default=datetime.utcnow,
        onupdate=datetime.utcnow,
        nullable=False,
    )
