from __future__ import annotations

import hashlib
import hmac
from contextlib import contextmanager
from typing import Any

from sqlalchemy import (
    JSON,
    Float,
    Integer,
    String,
    Text,
    UniqueConstraint,
    create_engine,
    event,
    select,
)
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column

from .domain import canonical, stamp


class Base(DeclarativeBase):
    pass


class Event(Base):
    __tablename__ = "events"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(64), index=True)
    source_id: Mapped[str] = mapped_column(String(1024))
    asset: Mapped[str] = mapped_column(String(1024), index=True)
    identity: Mapped[str] = mapped_column(String(1024), index=True)
    observed: Mapped[float] = mapped_column(Float, index=True)
    received: Mapped[str] = mapped_column(String(64))
    fingerprint: Mapped[str] = mapped_column(String(64), index=True)
    data: Mapped[dict] = mapped_column(JSON)


class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    entity: Mapped[str] = mapped_column(String(1024), index=True)
    window: Mapped[int] = mapped_column(Integer)
    data: Mapped[dict] = mapped_column(JSON)
    __table_args__ = (UniqueConstraint("tenant", "entity", "window"),)


class Action(Base):
    __tablename__ = "actions"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    state: Mapped[str] = mapped_column(String(32), index=True)
    fingerprint: Mapped[str] = mapped_column(String(64), unique=True)
    requester: Mapped[str] = mapped_column(String(128))
    approver: Mapped[str | None] = mapped_column(String(128))
    expires: Mapped[float] = mapped_column(Float)
    lease_until: Mapped[float] = mapped_column(Float, default=0)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    plan: Mapped[dict] = mapped_column(JSON)
    approval: Mapped[str | None] = mapped_column(String(64))
    result: Mapped[dict] = mapped_column(JSON, default=dict)


class Investigation(Base):
    __tablename__ = "investigations"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    incident_id: Mapped[str] = mapped_column(String(64), index=True)
    created: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)


class AIBudget(Base):
    __tablename__ = "ai_budgets"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    reserved: Mapped[float] = mapped_column(Float, default=0)


class Nonce(Base):
    __tablename__ = "nonces"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    expires: Mapped[float] = mapped_column(Float)


class SourceState(Base):
    __tablename__ = "source_states"
    id: Mapped[str] = mapped_column(String(64), primary_key=True)
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    source: Mapped[str] = mapped_column(String(64))
    data: Mapped[dict] = mapped_column(JSON)


class Audit(Base):
    __tablename__ = "audit"
    seq: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    tenant: Mapped[str] = mapped_column(String(128), index=True)
    body: Mapped[str] = mapped_column(Text)
    previous: Mapped[str] = mapped_column(String(64))
    signature: Mapped[str] = mapped_column(String(64))


class AuditHead(Base):
    __tablename__ = "audit_heads"
    tenant: Mapped[str] = mapped_column(String(128), primary_key=True)
    signature: Mapped[str] = mapped_column(String(64), default="0" * 64)


class Database:
    def __init__(self, url: str, signing_key: bytes):
        self.key = signing_key
        options: dict[str, Any] = {"pool_pre_ping": True}
        if url.startswith("sqlite"):
            options["connect_args"] = {"check_same_thread": False, "timeout": 30}
        self.engine = create_engine(url, **options)
        if url.startswith("sqlite"):

            @event.listens_for(self.engine, "connect")
            def setup(conn: Any, _: Any) -> None:
                conn.execute("PRAGMA journal_mode=WAL")
                conn.execute("PRAGMA foreign_keys=ON")

        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self):
        with Session(self.engine, expire_on_commit=False) as s, s.begin():
            yield s

    def lock(self, s: Session, tenant: str) -> None:
        # First DB write serializes SQLite writers. PostgreSQL locks this tenant's head.
        if self.engine.dialect.name == "sqlite":
            s.connection().exec_driver_sql("BEGIN IMMEDIATE")
        head = s.get(AuditHead, tenant)
        if head is None:
            if self.engine.dialect.name == "postgresql":
                from sqlalchemy.dialects.postgresql import insert

                s.execute(
                    insert(AuditHead)
                    .values(tenant=tenant, signature="0" * 64)
                    .on_conflict_do_nothing()
                )
            else:
                s.add(AuditHead(tenant=tenant, signature="0" * 64))
            s.flush()
        s.execute(
            select(AuditHead)
            .where(AuditHead.tenant == tenant)
            .with_for_update()
            .execution_options(populate_existing=True)
        ).scalar_one()

    def audit(self, s: Session, tenant: str, actor: str, kind: str, details: dict) -> None:
        head = s.get(AuditHead, tenant)
        if head is None:
            raise RuntimeError("audit transaction must acquire tenant lock")
        body = canonical({"at": stamp(), "actor": actor, "kind": kind, "details": details})
        signature = hmac.new(
            self.key, (tenant + head.signature + body).encode(), hashlib.sha256
        ).hexdigest()
        s.add(Audit(tenant=tenant, body=body, previous=head.signature, signature=signature))
        head.signature = signature
        s.flush()

    def verify_audit(self, tenant: str) -> dict:
        previous = "0" * 64
        count = 0
        with self.session() as s:
            for row in s.scalars(select(Audit).where(Audit.tenant == tenant).order_by(Audit.seq)):
                expected = hmac.new(
                    self.key, (tenant + previous + row.body).encode(), hashlib.sha256
                ).hexdigest()
                if row.previous != previous or not hmac.compare_digest(row.signature, expected):
                    return {"valid": False, "records": count, "broken_at": row.seq}
                previous = row.signature
                count += 1
            head = s.get(AuditHead, tenant)
            valid = head is None and count == 0 or head is not None and head.signature == previous
        checkpoint = {"tenant": tenant, "records": count, "head": previous}
        return {
            "valid": valid,
            **checkpoint,
            "checkpoint_signature": hmac.new(
                self.key, canonical(checkpoint).encode(), hashlib.sha256
            ).hexdigest(),
        }
