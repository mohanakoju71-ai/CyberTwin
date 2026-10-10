"""SQLAlchemy models + session handling. Default: SQLite file in ./data (never deleted automatically)."""
import os
from datetime import datetime, timezone
from pathlib import Path
from sqlalchemy import create_engine, String, Integer, Float, Boolean, DateTime, JSON, Text, ForeignKey, Index
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, sessionmaker

ROOT = Path(__file__).resolve().parent.parent

def _load_env():
    f = ROOT / ".env"
    if f.exists():
        for line in f.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if line and not line.startswith("#") and "=" in line:
                k, v = line.split("=", 1)
                os.environ.setdefault(k.strip(), v.strip().strip('"').strip("'"))
_load_env()

DATA = Path(os.getenv("CYBERTWIN_DATA_DIR") or ROOT / "data")
DATA.mkdir(parents=True, exist_ok=True)
URL = os.getenv("DATABASE_URL") or f"sqlite:///{(DATA / 'cybertwin.db').as_posix()}"
engine = create_engine(URL, connect_args={"check_same_thread": False} if URL.startswith("sqlite") else {}, pool_pre_ping=True)
if URL.startswith("sqlite"):
    from sqlalchemy import event as _sa_event
    @_sa_event.listens_for(engine, "connect")
    def _pragmas(conn, _):  # safer concurrent access for a local demo server
        cur = conn.cursor(); cur.execute("PRAGMA journal_mode=WAL"); cur.execute("PRAGMA busy_timeout=5000"); cur.execute("PRAGMA foreign_keys=ON"); cur.close()
SessionLocal = sessionmaker(bind=engine, expire_on_commit=False)

def utcnow() -> datetime:  # naive UTC, serialised with a trailing Z
    return datetime.now(timezone.utc).replace(tzinfo=None)

def iso(d):
    return d.isoformat(timespec="seconds") + "Z" if d else None

class Base(DeclarativeBase): pass

class Device(Base):
    __tablename__ = "devices"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    os: Mapped[str] = mapped_column(String(60), default="unknown")
    kind: Mapped[str] = mapped_column(String(60), default="demo")
    trust: Mapped[str] = mapped_column(String(12), default="untrusted")  # trusted | untrusted
    isolated_sim: Mapped[bool] = mapped_column(Boolean, default=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class Network(Base):
    __tablename__ = "networks"
    id: Mapped[int] = mapped_column(primary_key=True)
    name: Mapped[str] = mapped_column(String(80), unique=True)
    trust: Mapped[str] = mapped_column(String(12), default="untrusted")  # trusted | known | untrusted
    first_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_seen: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class Event(Base):
    __tablename__ = "events"
    id: Mapped[int] = mapped_column(primary_key=True)
    dedupe_key: Mapped[str] = mapped_column(String(64), unique=True)
    ts: Mapped[datetime] = mapped_column(DateTime, index=True)
    user: Mapped[str] = mapped_column(String(64))
    event_type: Mapped[str] = mapped_column(String(32))
    device_id: Mapped[int] = mapped_column(ForeignKey("devices.id"))
    network_id: Mapped[int] = mapped_column(ForeignKey("networks.id"))
    device_name: Mapped[str] = mapped_column(String(80))
    network_name: Mapped[str] = mapped_column(String(80))
    ip: Mapped[str | None] = mapped_column(String(45), nullable=True)
    application: Mapped[str] = mapped_column(String(80), default="Account sign-in")
    failed_attempts: Mapped[int] = mapped_column(Integer, default=0)
    success: Mapped[bool] = mapped_column(Boolean, default=True)
    mfa_verified: Mapped[bool] = mapped_column(Boolean, default=False)
    device_known: Mapped[bool] = mapped_column(Boolean, default=True)
    network_known: Mapped[bool] = mapped_column(Boolean, default=True)
    source: Mapped[str] = mapped_column(String(40), default="api")
    synthetic: Mapped[bool] = mapped_column(Boolean, default=True)
    baseline_ok: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    score: Mapped[int] = mapped_column(Integer, default=0, index=True)
    severity: Mapped[str] = mapped_column(String(10), default="Low")
    method: Mapped[str] = mapped_column(String(120), default="")
    contributors: Mapped[list] = mapped_column(JSON, default=list)
    features: Mapped[dict] = mapped_column(JSON, default=dict)
    explanation: Mapped[str] = mapped_column(Text, default="")
    uncertainty: Mapped[str] = mapped_column(Text, default="")
    confidence: Mapped[str] = mapped_column(String(10), default="low")
    recommended: Mapped[list] = mapped_column(JSON, default=list)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class Incident(Base):
    __tablename__ = "incidents"
    id: Mapped[int] = mapped_column(primary_key=True)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), unique=True)
    title: Mapped[str] = mapped_column(String(160))
    severity: Mapped[str] = mapped_column(String(10), index=True)
    status: Mapped[str] = mapped_column(String(16), default="open", index=True)  # open|investigating|confirmed|responded|resolved|dismissed
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    updated_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)

class Action(Base):
    __tablename__ = "actions"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    incident_id: Mapped[int | None] = mapped_column(ForeignKey("incidents.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(32))
    label: Mapped[str] = mapped_column(String(80))
    target: Mapped[str] = mapped_column(String(80), default="")
    mode: Mapped[str] = mapped_column(String(16))   # simulated | local-record
    status: Mapped[str] = mapped_column(String(24))  # simulated | recorded_locally
    result: Mapped[str] = mapped_column(Text, default="")
    actor: Mapped[str] = mapped_column(String(40), default="demo-user")

class Feedback(Base):
    __tablename__ = "feedback"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    event_id: Mapped[int] = mapped_column(ForeignKey("events.id"), index=True)
    verdict: Mapped[str] = mapped_column(String(24))  # true_positive | false_positive | benign_expected
    note: Mapped[str] = mapped_column(String(500), default="")

class Audit(Base):
    __tablename__ = "audit"
    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    actor: Mapped[str] = mapped_column(String(40), default="system")
    what: Mapped[str] = mapped_column(String(60))
    detail: Mapped[str] = mapped_column(Text, default="")

class Setting(Base):
    __tablename__ = "settings"
    key: Mapped[str] = mapped_column(String(40), primary_key=True)
    value: Mapped[dict] = mapped_column(JSON, default=dict)

Index("ix_events_ts_score", Event.ts, Event.score)

def init_db():
    Base.metadata.create_all(engine)  # safe: only creates missing tables, never drops

def get_session():
    s = SessionLocal()
    try:
        yield s
    finally:
        s.close()
