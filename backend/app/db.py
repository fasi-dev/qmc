"""SQLite persistence (SQLAlchemy 2.x; schema kept PostgreSQL-compatible: plain columns + JSON)."""
from __future__ import annotations

import logging

from sqlalchemy import JSON, Boolean, Float, Index, Integer, String, create_engine, inspect, text
from sqlalchemy.engine import Engine
from sqlalchemy.orm import DeclarativeBase, Mapped, Session, mapped_column, sessionmaker

from .config import Settings


class Base(DeclarativeBase):
    pass


class ScanRow(Base):
    __tablename__ = "scans"
    id: Mapped[str] = mapped_column(String(36), primary_key=True)
    created_at: Mapped[str] = mapped_column(String(40))
    status: Mapped[str] = mapped_column(String(16))            # ingested | analyzing | analyzed
    original_filename: Mapped[str] = mapped_column(String(120))
    repo_name: Mapped[str] = mapped_column(String(120), default="repo")
    manifest: Mapped[dict] = mapped_column(JSON)               # ingestion summary (no file list)
    analysis: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    token_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)   # sha256 of the per-scan access token


class FindingRow(Base):
    __tablename__ = "findings"
    # One row per finding id per scan: makes a duplicated analysis fail loudly instead of double-counting.
    __table_args__ = (Index("uq_findings_scan_fid", "scan_id", "fid", unique=True),)
    pk: Mapped[int] = mapped_column(Integer, primary_key=True, autoincrement=True)
    scan_id: Mapped[str] = mapped_column(String(36), index=True)
    fid: Mapped[str] = mapped_column(String(16))               # CRYPTO-001
    file: Mapped[str] = mapped_column(String(500))
    algorithm: Mapped[str] = mapped_column(String(40), index=True)
    primitive: Mapped[str] = mapped_column(String(20))
    operation: Mapped[str] = mapped_column(String(24))
    service: Mapped[str] = mapped_column(String(120), index=True)
    confidence_level: Mapped[str] = mapped_column(String(8))
    quantum_vulnerable: Mapped[bool] = mapped_column(Boolean)
    already_pqc: Mapped[bool] = mapped_column(Boolean)
    comment_only: Mapped[bool] = mapped_column(Boolean)
    test_path: Mapped[bool] = mapped_column(Boolean)
    band: Mapped[str | None] = mapped_column(String(16), nullable=True, index=True)
    qmp: Mapped[int | None] = mapped_column(Integer, nullable=True)
    raw: Mapped[float | None] = mapped_column(Float, nullable=True)
    hndl: Mapped[bool] = mapped_column(Boolean, default=False)
    rank: Mapped[int] = mapped_column(Integer, default=0)      # priority order within the scan (1 = first)
    data: Mapped[dict] = mapped_column(JSON)                   # the scanner finding, exactly as emitted
    risk: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    snippet: Mapped[dict | None] = mapped_column(JSON, nullable=True)
    suppressed: Mapped[bool] = mapped_column(Boolean, default=False)
    suppression: Mapped[dict | None] = mapped_column(JSON, nullable=True)


_factories: dict[str, sessionmaker] = {}
log = logging.getLogger("qmc.db")


def upgrade_schema(engine: Engine) -> None:
    """Additive, idempotent upgrades for databases created by older versions (there is no Alembic yet).
    create_all() only creates missing TABLES, so new columns/indexes on existing tables are added here."""
    insp = inspect(engine)
    with engine.begin() as conn:
        if "token_hash" not in {c["name"] for c in insp.get_columns("scans")}:
            conn.execute(text("ALTER TABLE scans ADD COLUMN token_hash VARCHAR(64)"))
            log.info("schema upgrade: added scans.token_hash (existing scans become admin-only)")
    try:
        with engine.begin() as conn:
            conn.execute(text("CREATE UNIQUE INDEX IF NOT EXISTS uq_findings_scan_fid ON findings (scan_id, fid)"))
    except Exception:  # pre-existing duplicate rows: keep serving, but say so
        log.warning("schema upgrade: could not create unique index on findings(scan_id, fid); duplicates exist")


def session_factory(s: Settings) -> sessionmaker:
    path = (s.data_dir / "qmc.db").resolve()
    key = str(path)
    if key not in _factories:
        path.parent.mkdir(parents=True, exist_ok=True)
        engine = create_engine(f"sqlite:///{path}", connect_args={"check_same_thread": False})
        Base.metadata.create_all(engine)
        upgrade_schema(engine)
        _factories[key] = sessionmaker(engine, expire_on_commit=False)
    return _factories[key]


def open_session(s: Settings) -> Session:
    return session_factory(s)()
