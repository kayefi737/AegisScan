"""Database models."""
from __future__ import annotations

import datetime as dt
import uuid

from sqlalchemy import JSON, DateTime, Float, ForeignKey, String, Text, UniqueConstraint
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .database import Base


def _uuid() -> str:
    return uuid.uuid4().hex


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


class User(Base):
    __tablename__ = "users"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    email: Mapped[str] = mapped_column(String(255), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(255))
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    scans: Mapped[list["Scan"]] = relationship(back_populates="user")
    domains: Mapped[list["TrackedDomain"]] = relationship(back_populates="user")


class Scan(Base):
    __tablename__ = "scans"

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    grade: Mapped[str] = mapped_column(String(2))
    score: Mapped[float] = mapped_column(Float)
    # Full structured result (categories, findings, fixes). Portable across SQLite/PG.
    result: Mapped[dict] = mapped_column(JSON)
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now, index=True)

    user_id: Mapped[str | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    user: Mapped["User | None"] = relationship(back_populates="scans")


class TrackedDomain(Base):
    __tablename__ = "tracked_domains"
    __table_args__ = (UniqueConstraint("user_id", "hostname", name="uq_user_hostname"),)

    id: Mapped[str] = mapped_column(String(32), primary_key=True, default=_uuid)
    hostname: Mapped[str] = mapped_column(String(255), index=True)
    note: Mapped[str] = mapped_column(Text, default="")
    created_at: Mapped[dt.datetime] = mapped_column(DateTime(timezone=True), default=_now)

    user_id: Mapped[str] = mapped_column(ForeignKey("users.id"), index=True)
    user: Mapped["User"] = relationship(back_populates="domains")
