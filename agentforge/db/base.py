"""SQLAlchemy declarative base + shared type aliases."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from sqlalchemy import DateTime, MetaData, func
from sqlalchemy.dialects.postgresql import UUID as PG_UUID
from sqlalchemy.orm import DeclarativeBase, mapped_column

NAMING_CONVENTION = {
    "ix": "ix_%(column_0_label)s",
    "uq": "uq_%(table_name)s_%(column_0_name)s",
    "ck": "ck_%(table_name)s_%(constraint_name)s",
    "fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s",
    "pk": "pk_%(table_name)s",
}


class Base(DeclarativeBase):
    """Project-wide declarative base.

    Why: consistent naming conventions make Alembic-generated migrations
    deterministic across machines.
    """

    metadata = MetaData(naming_convention=NAMING_CONVENTION)


# Reusable column type annotations
uuid_pk = Annotated[
    UUID,
    mapped_column(PG_UUID(as_uuid=True), primary_key=True, server_default=func.gen_random_uuid()),
]
timestamp_now = Annotated[
    datetime,
    mapped_column(DateTime(timezone=True), server_default=func.now(), nullable=False),
]
timestamp_opt = Annotated[
    datetime | None,
    mapped_column(DateTime(timezone=True), nullable=True),
]
