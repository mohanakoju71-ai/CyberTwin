"""CyberTwin API. FastAPI serves the API (/api/*) and the static frontend (/)."""
import csv, hashlib, html, io, ipaddress, logging, os, random, sys, uuid
from contextlib import asynccontextmanager
from datetime import datetime, timedelta, timezone
from typing import Literal, Optional
import httpx
from fastapi import Depends, FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import HTMLResponse, JSONResponse, Response
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, field_validator, model_validator
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from . import db, engine as eng
from .db import Action, Audit, Device, Event, Feedback, Incident, Network, Setting, iso, utcnow

log = logging.getLogger("cybertwin")
DET = eng.Detector(db.DATA / "model.joblib")
DEFAULTS = {"medium": 30, "high": 60, "critical": 85, "baseline_min_events": 30, "time_window_hours": 4, "refresh_seconds": 5, "demo_mode": True}
OPEN = ("open", "investigating", "confirmed")

# ---------------------------------------------------------------- schemas
class SettingsIn(BaseModel):
    medium: int = Field(ge=1, le=99); high: int = Field(ge=2, le=100); critical: int = Field(ge=3, le=100)
    baseline_min_events: int = Field(ge=10, le=500); time_window_hours: int = Field(ge=1, le=12)
    refresh_seconds: int = Field(ge=2, le=60); demo_mode: bool = True
    @model_validator(mode="after")
    def ordered(self):
        if not self.medium < self.high < self.critical:
            raise ValueError("Thresholds must satisfy medium < high < critical")
        return self

class IngestIn(BaseModel):
    user: str = Field(min_length=1, max_length=64, pattern=r"^[A-Za-z0-9_.@-]+$")
    event_type: Literal["login", "failed_login", "file_access", "network_connection", "password_reset"] = "login"
    device: str = Field(min_length=1, max_length=80)
    network: str = Field(min_length=1, max_length=80)
    ip: Optional[str] = None
    application: str = Field(default="Account sign-in", max_length=80)
    failed_attempts: int = Field(default=0, ge=0, le=50)
    success: bool = True
    mfa_verified: bool = False
    timestamp: Optional[datetime] = None
    source: str = Field(default="api", max_length=40)
    synthetic: bool = True
    event_id: Optional[str] = Field(default=None, max_length=64)
    @field_validator("ip")
    @classmethod
    def valid_ip(cls, v):
        if v: ipaddress.ip_address(v)
        return v

class ExecIn(BaseModel):
    incident_id: int
    action: Literal["record_alert", "request_verification", "mark_untrusted", "revoke_session", "isolate_device"]
    confirm: bool = False

class FeedbackIn(BaseModel):
    event_id: int
    verdict: Literal["true_positive", "false_positive", "benign_expected"]
    note: str = Field(default="", max_length=500)

class TrustIn(BaseModel):
    trust: Literal["trusted", "untrusted"]
    confirm: bool = False

class StatusIn(BaseModel):
    status: Literal["open", "investigating", "confirmed", "responded", "resolved", "dismissed"]

class InvestigateIn(BaseModel):
    question: str = Field(min_length=3, max_length=500)
    event_id: Optional[int] = None

class ResetIn(BaseModel):
    confirm: str

# ---------------------------------------------------------------- helpers
def audit(s, what, detail="", actor="demo-user"):
    s.add(Audit(what=what, detail=detail[:2000], actor=actor))

def cfg_of(s) -> dict:
    row = s.get(Setting, "app")
    return {**DEFAULTS, **(row.value if row else {})}

def baseline(s, cfg):
    rows = s.execute(select(Event.ts).where(Event.baseline_ok == True, Event.success == True)).all()  # noqa: E712
    hrs = [r[0].hour + r[0].minute / 60 for r in rows]
    hist = [0] * 24
    for h in hrs: hist[int(h) % 24] += 1
    n = len(hrs)
    return {"n": n, "mean_hour": eng.circ_mean(hrs), "hist": hist, "model_trained": DET.ready, "model_samples": DET.n_train,
            "min_events": cfg["baseline_min_events"], "ready": n >= cfg["baseline_min_events"] and DET.ready}

def retrain(s):
    cfg = cfg_of(s)
    rows = s.execute(select(Event).where(Event.baseline_ok == True, Event.success == True)).scalars().all()  # noqa: E712
    ok = DET.train([eng.vec(r.ts.hour + r.ts.minute / 60, r.failed_attempts, r.device_known, r.network_known, r.success) for r in rows], cfg["baseline_min_events"])
    return ok, len(rows)

def ev_out(e, inc=None, fb=None):
    return {"id": e.id, "ts": iso(e.ts), "user": e.user, "event_type": e.event_type, "device": e.device_name, "device_id": e.device_id,
            "network": e.network_name, "network_id": e.network_id, "ip": e.ip, "application": e.application,
            "failed_attempts": e.failed_attempts, "success": e.success, "mfa_verified": e.mfa_verified, "device_known": e.device_known,
            "network_known": e.network_known, "source": e.source, "synthetic": e.synthetic, "score": e.score, "severity": e.severity,
            "method": e.method, "contributors": e.contributors, "features": e.features, "explanation": e.explanation,
            "uncertainty": e.uncertainty, "confidence": e.confidence, "recommended": e.recommended,
            "recommended_labels": [eng.ACTIONS[a][0] for a in e.recommended],
            "origin": "demonstration" if e.synthetic else "user-submitted", "incident_id": inc.id if inc else None, "incident_status": inc.status if inc else None,
            "feedback": fb or []}

def decorate(s, events):
    ids = [e.id for e in events]
    incs = {i.event_id: i for i in s.execute(select(Incident).where(Incident.event_id.in_(ids))).scalars()} if ids else {}
    fbs = {}
    for f in (s.execute(select(Feedback).where(Feedback.event_id.in_(ids)).order_by(Feedback.id)).scalars() if ids else []):
        fbs.setdefault(f.event_id, []).append({"verdict": f.verdict, "note": f.note, "ts": iso(f.ts)})
    return [ev_out(e, incs.get(e.id), fbs.get(e.id, [])) for e in events]

def action_out(a):
    return {"id": a.id, "ts": iso(a.ts), "incident_id": a.incident_id, "action": a.action, "label": a.label, "target": a.target,
            "mode": a.mode, "status": a.status, "result": a.result, "actor": a.actor}

def device_out(d):
    return {"id": d.id, "name": d.name, "os": d.os, "kind": d.kind, "trust": d.trust, "isolated_sim": d.isolated_sim,
            "first_seen": iso(d.first_seen), "last_seen": iso(d.last_seen)}

def get_or_create(s, model, name, **kw):
    row = s.execute(select(model).where(func.lower(model.name) == name.lower())).scalar_one_or_none()
    if row: return row, False
    row = model(name=name, **kw); s.add(row); s.flush(); return row, True

# ---------------------------------------------------------------- pipeline
def process(s: Session, p: IngestIn, baseline_ok=False) -> Event:
    now = utcnow()
    ts = p.timestamp.astimezone(timezone.utc).replace(tzinfo=None) if p.timestamp and p.timestamp.tzinfo else (p.timestamp or now)
    if ts > now + timedelta(minutes=5): raise HTTPException(422, "timestamp is in the future")
    if ts < now - timedelta(days=60): raise HTTPException(422, "timestamp is older than 60 days")
    key = hashlib.sha1((p.event_id or f"{p.user}|{p.event_type}|{p.device}|{p.network}|{p.ip}|{ts:%Y%m%d%H%M%S}").encode()).hexdigest()
    dup = s.execute(select(Event.id).where(Event.dedupe_key == key)).scalar_one_or_none()
    if dup: raise HTTPException(409, f"Duplicate event (existing id {dup})")
    dev, dnew = get_or_create(s, Device, p.device, trust="untrusted", kind="auto-discovered (synthetic)")
    net, nnew = get_or_create(s, Network, p.network, trust="untrusted")
    dev.last_seen = net.last_seen = max(ts, dev.last_seen)
    cfg = cfg_of(s)
    d = eng.assess({"hour": ts.hour + ts.minute / 60, "failed": p.failed_attempts, "device_known": dev.trust == "trusted",
                    "network_known": net.trust in ("trusted", "known"), "success": p.success, "mfa": p.mfa_verified}, baseline(s, cfg), DET, cfg)
    e = Event(dedupe_key=key, ts=ts, user=p.user, event_type=p.event_type, device_id=dev.id, network_id=net.id, device_name=dev.name,
              network_name=net.name, ip=p.ip, application=p.application, failed_attempts=p.failed_attempts, success=p.success,
              mfa_verified=p.mfa_verified, device_known=dev.trust == "trusted", network_known=net.trust in ("trusted", "known"),
              source=p.source, synthetic=p.synthetic, baseline_ok=baseline_ok, score=d["score"], severity=d["severity"], method=d["method"],
              contributors=d["contributors"], features=d["features"], explanation=d["explanation"], uncertainty=d["uncertainty"],
              confidence=d["confidence"], recommended=d["recommended"])
    s.add(e); s.flush()
    if e.severity != "Low":
        s.add(Incident(event_id=e.id, title=f"{e.severity}: {e.event_type.replace('_', ' ')} from {e.device_name}", severity=e.severity))
    audit(s, "ingest", f"event {e.id} score {e.score} {e.severity}", actor="pipeline")
    s.commit()
    return e

SCEN = {
 "normal": ("Normal login, known device", "Trusted laptop on home Wi-Fi at the usual time.", dict(device="Personal Laptop", network="Home Wi-Fi", hour=10)),
 "unknown_device": ("Login from an unknown device", "Unrecognised Linux host on the home network at a normal hour.", dict(device="Unrecognized Linux Host", network="Home Wi-Fi", hour=10)),
 "failed_then_success": ("Failed attempts, then success", "Six failures followed by a successful sign-in on a known device.", dict(device="Personal Laptop", network="Home Wi-Fi", hour=10, failed=6)),
 "unusual_time": ("Login at an unusual time", "Known device and network, but at 03:00 UTC.", dict(device="Personal Laptop", network="Home Wi-Fi", hour=3)),
 "multi_signal": ("New network + other evidence", "Unknown device, unknown network, 03:00 UTC, repeated failures then success.", dict(device="Unrecognized Linux Host", network="Unknown Network (203.0.113.45)", hour=3, failed=4, ip="203.0.113.45")),
 "benign_unusual": ("Benign unusual event", "Trusted laptop on a known network at 02:00 UTC with MFA verified (e.g. late-night work).", dict(device="Personal Laptop", network="College Wi-Fi", hour=2, mfa=True)),
}

def recent_at(hour):
    n = utcnow(); t = n.replace(hour=hour, minute=random.randint(0, 59), second=random.randint(0, 59), microsecond=0)
    return t if t <= n else t - timedelta(days=1)

def seed(s: Session):
    if s.execute(select(func.count(Device.id))).scalar(): return False
    rng = random.Random(42)
    lap = Device(name="Personal Laptop", os="Windows 11", kind="laptop", trust="trusted")
    ph = Device(name="Android Phone", os="Android 15", kind="phone", trust="trusted")
    tv = Device(name="Smart TV", os="Tizen", kind="iot", trust="untrusted")
    hw = Network(name="Home Wi-Fi", trust="trusted"); cw = Network(name="College Wi-Fi", trust="known")
    s.add_all([lap, ph, tv, hw, cw]); s.flush()
    now = utcnow()
    for i in range(60):
        t = (now - timedelta(days=rng.randint(1, 14))).replace(hour=int(max(6, min(14, rng.gauss(10, 1.3)))), minute=rng.randint(0, 59), second=0, microsecond=0)
        dv, nt = (lap if rng.random() < .7 else ph), (hw if rng.random() < .8 else cw)
        s.add(Event(dedupe_key=f"seed-{i}", ts=t, user="aarav", event_type="login", device_id=dv.id, network_id=nt.id, device_name=dv.name,
                    network_name=nt.name, application=rng.choice(["Mail", "Code hosting", "Cloud drive"]), failed_attempts=int(rng.random() < .1),
                    success=True, source="synthetic-seed", synthetic=True, baseline_ok=True, method="baseline", explanation="Seeded baseline event.",
                    features={}, confidence="low", device_known=True, network_known=True))
    s.add(Setting(key="app", value=dict(DEFAULTS)))
    audit(s, "seed", "Synthetic demo dataset created", actor="system"); s.commit()
    retrain(s)
    return True

@asynccontextmanager
async def lifespan(app):
    db.init_db()
    with db.SessionLocal() as s:
        seed(s)
        DET.load()
        if not DET.ready: retrain(s)
    yield

app = FastAPI(title="CyberTwin API", version="2.0", lifespan=lifespan)

@app.exception_handler(RequestValidationError)
async def _422(request: Request, exc: RequestValidationError):
    msg = "; ".join(f"{'.'.join(str(x) for x in e['loc'][1:])}: {e['msg']}" for e in exc.errors())
    return JSONResponse({"detail": msg or "Invalid request"}, status_code=422)

@app.exception_handler(Exception)
async def _500(request: Request, exc: Exception):
    log.exception("Unhandled error on %s", request.url.path)
    return JSONResponse({"detail": "Unexpected server error. Check the server console for details."}, status_code=500)

# ---------------------------------------------------------------- routes
@app.get("/api/health")
def health(s: Session = Depends(db.get_session)):
    s.execute(select(1))
    return {"status": "ok", "ready": True, "python": sys.version.split()[0], "time": iso(utcnow()), "database": "up", "model_trained": DET.ready,
            "claude_configured": bool(os.getenv("ANTHROPIC_API_KEY")), "version": app.version}

@app.get("/api/settings")
def get_settings(s: Session = Depends(db.get_session)): return cfg_of(s)

@app.put("/api/settings")
def put_settings(b: SettingsIn, s: Session = Depends(db.get_session)):
    row = s.get(Setting, "app") or Setting(key="app", value={}); row.value = b.model_dump(); s.merge(row)
    audit(s, "settings", str(b.model_dump())); s.commit(); return cfg_of(s)

@app.get("/api/events")
def events(q: str = "", severity: str = "", source: str = "", sort: Literal["ts", "score"] = "ts", order: Literal["asc", "desc"] = "desc",
           min_score: int = Query(0, ge=0, le=100), limit: int = Query(100, ge=1, le=500), offset: int = Query(0, ge=0), s: Session = Depends(db.get_session)):
    st = select(Event).where(Event.score >= min_score)
    if q:
        like = f"%{q.lower()}%"
        st = st.where(func.lower(Event.device_name + " " + Event.network_name + " " + Event.event_type + " " + Event.user + " " + func.coalesce(Event.ip, "") + " " + Event.explanation).like(like))
    if severity: st = st.where(Event.severity == severity)
    if source: st = st.where(Event.source == source)
    total = s.execute(select(func.count()).select_from(st.subquery())).scalar()
    col = Event.ts if sort == "ts" else Event.score
    rows = s.execute(st.order_by(col.desc() if order == "desc" else col.asc(), Event.id.desc()).limit(limit).offset(offset)).scalars().all()
    return {"total": total, "items": decorate(s, rows)}

@app.get("/api/events/{eid}")
def event_detail(eid: int, s: Session = Depends(db.get_session)):
    e = s.get(Event, eid)
    if not e: raise HTTPException(404, "Event not found")
    out = decorate(s, [e])[0]
    out["actions"] = [action_out(a) for a in s.execute(select(Action).where(Action.incident_id == out["incident_id"]).order_by(Action.id.desc())).scalars()] if out["incident_id"] else []
    return out

@app.post("/api/ingest", status_code=201)
def ingest(p: IngestIn, s: Session = Depends(db.get_session)):
    e = process(s, p); return decorate(s, [e])[0]

@app.get("/api/detections")
def detections(severity: str = "", q: str = "", limit: int = Query(100, ge=1, le=500), s: Session = Depends(db.get_session)):
    return events(q=q, severity=severity, min_score=cfg_of(s)["medium"], limit=limit, sort="ts", order="desc", offset=0, source="", s=s)

@app.get("/api/incidents")
def incidents(status: str = "", s: Session = Depends(db.get_session)):
    st = select(Incident).order_by(Incident.id.desc()).limit(200)
    if status: st = st.where(Incident.status == status)
    out = []
    for i in s.execute(st).scalars():
        e = s.get(Event, i.event_id)
        out.append({"id": i.id, "title": i.title, "severity": i.severity, "status": i.status, "created_at": iso(i.created_at),
                    "updated_at": iso(i.updated_at), "event_id": i.event_id, "score": e.score, "recommended": e.recommended,
                    "recommended_labels": [eng.ACTIONS[a][0] for a in e.recommended], "device": e.device_name})
    return {"items": out}

@app.patch("/api/incidents/{iid}")
def set_incident(iid: int, b: StatusIn, s: Session = Depends(db.get_session)):
    i = s.get(Incident, iid)
    if not i: raise HTTPException(404, "Incident not found")
    i.status, i.updated_at = b.status, utcnow(); audit(s, "incident_status", f"{iid} -> {b.status}"); s.commit()
    return {"id": i.id, "status": i.status}

@app.get("/api/devices")
def devices(s: Session = Depends(db.get_session)):
    out = []
    for d in s.execute(select(Device).order_by(Device.last_seen.desc())).scalars():
        r = device_out(d); r["event_count"] = s.execute(select(func.count(Event.id)).where(Event.device_id == d.id)).scalar()
        r["max_score"] = s.execute(select(func.max(Event.score)).where(Event.device_id == d.id)).scalar() or 0; out.append(r)
    return {"items": out}

@app.post("/api/devices/{did}/trust")
def device_trust(did: int, b: TrustIn, s: Session = Depends(db.get_session)):
    if not b.confirm: raise HTTPException(400, "confirm=true is required")
    d = s.get(Device, did)
    if not d: raise HTTPException(404, "Device not found")
    d.trust = b.trust
    if b.trust == "trusted": d.isolated_sim = False
    audit(s, "device_trust", f"{d.name} -> {b.trust} (local demo record only)"); s.commit()
    return device_out(d)

@app.get("/api/networks")
def networks(s: Session = Depends(db.get_session)):
    out = []
    for n in s.execute(select(Network).order_by(Network.last_seen.desc())).scalars():
        out.append({"id": n.id, "name": n.name, "trust": n.trust, "first_seen": iso(n.first_seen), "last_seen": iso(n.last_seen),
                    "event_count": s.execute(select(func.count(Event.id)).where(Event.network_id == n.id)).scalar(),
                    "max_score": s.execute(select(func.max(Event.score)).where(Event.network_id == n.id)).scalar() or 0})
    return {"items": out}

@app.post("/api/networks/{nid}/trust")
def network_trust(nid: int, b: dict, s: Session = Depends(db.get_session)):
    n = s.get(Network, nid)
    if not n: raise HTTPException(404, "Network not found")
    if b.get("trust") not in ("trusted", "known", "untrusted") or not b.get("confirm"): raise HTTPException(400, "trust must be trusted|known|untrusted and confirm=true")
    n.trust = b["trust"]; audit(s, "network_trust", f"{n.name} -> {n.trust}"); s.commit(); return {"id": n.id, "trust": n.trust}

@app.get("/api/live")
def live(after_id: int = 0, s: Session = Depends(db.get_session)):
    cfg = cfg_of(s); last = s.execute(select(func.max(Event.ts)).where(Event.source != "synthetic-seed")).scalar()
    rows = s.execute(select(Event).where(Event.id > after_id, Event.source != "synthetic-seed").order_by(Event.id.desc()).limit(50)).scalars().all()
    age = (utcnow() - last).total_seconds() if last else None
    return {"server_time": iso(utcnow()), "latest_event_time": iso(last), "age_seconds": age, "stale": age is None or age > 300,
            "refresh_seconds": cfg["refresh_seconds"], "source": "synthetic demo scenarios / API ingest (no OS or network capture)",
            "max_id": s.execute(select(func.max(Event.id))).scalar() or 0, "items": decorate(s, rows)}

@app.get("/api/scenarios")
def scenarios(): return [{"key": k, "title": v[0], "description": v[1]} for k, v in SCEN.items()]

@app.post("/api/scenarios/{key}/run", status_code=201)
def run_scenario(key: str, s: Session = Depends(db.get_session)):
    if key not in SCEN: raise HTTPException(404, "Unknown scenario")
    sp = SCEN[key][2]
    p = IngestIn(user="aarav", event_type="login", device=sp["device"], network=sp["network"], ip=sp.get("ip"), failed_attempts=sp.get("failed", 0),
                 success=True, mfa_verified=sp.get("mfa", False), timestamp=recent_at(sp["hour"]), source="demo-scenario", synthetic=True, event_id=f"scn-{key}-{uuid.uuid4().hex}")
    return decorate(s, [process(s, p)])[0]

@app.get("/api/state")
def state(s: Session = Depends(db.get_session)):
    cfg, now = cfg_of(s), utcnow()
    base = baseline(s, cfg)
    total = s.execute(select(func.count(Event.id))).scalar()
    susp = s.execute(select(func.count(Event.id)).where(Event.score >= cfg["medium"])).scalar()
    open_inc = s.execute(select(Incident).where(Incident.status.in_(OPEN))).scalars().all()
    by_sev = {k: 0 for k in ("Critical", "High", "Medium")}
    for i in open_inc: by_sev[i.severity] += 1
    top = max((s.get(Event, i.event_id).score for i in open_inc), default=0)
    def trend(n, step, fmt):
        out = []; end = now.replace(minute=0, second=0, microsecond=0) if step == 1 else now.replace(hour=0, minute=0, second=0, microsecond=0)
        for k in range(n - 1, -1, -1):
            a = end - timedelta(hours=k) if step == 1 else end - timedelta(days=k); b = a + (timedelta(hours=1) if step == 1 else timedelta(days=1))
            r = s.execute(select(func.max(Event.score), func.count(Event.id)).where(Event.ts >= a, Event.ts < b, Event.source != "synthetic-seed")).one()
            out.append({"label": a.strftime(fmt), "max": r[0] or 0, "count": r[1]})
        return out
    contrib = {}
    for e in s.execute(select(Event).where(Event.score >= cfg["medium"])).scalars():
        for c in e.contributors:
            if c["points"] > 0: contrib[c["factor"]] = contrib.get(c["factor"], 0) + c["points"]
    srcs = []
    for src, n, last in s.execute(select(Event.source, func.count(Event.id), func.max(Event.ts)).group_by(Event.source)).all():
        srcs.append({"name": src, "events": n, "last_event": iso(last), "age_seconds": (now - last).total_seconds(), "kind": "synthetic"})
    devs = s.execute(select(Device)).scalars().all()
    recent = s.execute(select(Event).where(Event.source != "synthetic-seed").order_by(Event.ts.desc()).limit(8)).scalars().all()
    acts = s.execute(select(Action).order_by(Action.id.desc()).limit(6)).scalars().all()
    orig = dict(s.execute(select(Event.synthetic, func.count(Event.id)).group_by(Event.synthetic)).all())
    return {"demo_mode": cfg["demo_mode"], "synthetic_data": orig.get(True, 0) > 0, "origins": {"demonstration": orig.get(True, 0), "user_submitted": orig.get(False, 0)}, "server_time": iso(now), "settings": cfg,
            "risk": {"score": top, "severity": eng.severity_of(top, cfg) if top else "None", "basis": "Highest score among open incidents"},
            "totals": {"events": total, "suspicious": susp, "open_incidents": len(open_inc), "devices_trusted": sum(d.trust == "trusted" for d in devs),
                       "devices_untrusted": sum(d.trust != "trusted" for d in devs)},
            "incidents_by_severity": by_sev, "trend_24h": trend(24, 1, "%H:00"), "trend_7d": trend(7, 24, "%a"),
            "top_contributors": sorted(({"factor": k, "points": v} for k, v in contrib.items()), key=lambda x: -x["points"])[:6],
            "baseline": base, "sources": srcs, "recent_events": decorate(s, recent), "recent_actions": [action_out(a) for a in acts]}

@app.get("/api/twin")
def twin(s: Session = Depends(db.get_session)):
    cfg = cfg_of(s); base = baseline(s, cfg); now = utcnow()
    flagged = s.execute(select(Event).where(Event.score >= cfg["medium"], Event.ts >= now - timedelta(days=30)).order_by(Event.ts.desc())).scalars().all()
    fd, fn = {}, {}
    for e in flagged: fd.setdefault(e.device_id, []).append(e); fn.setdefault(e.network_id, []).append(e)
    cnt = lambda col: dict(s.execute(select(col, func.count(Event.id)).group_by(col)).all())
    dc, nc = cnt(Event.device_id), cnt(Event.network_id)
    def status(trust, fl): return "suspicious" if fl and trust not in ("trusted", "known") else "trusted" if trust in ("trusted", "known") else "unfamiliar"
    nodes = [{"id": "user", "type": "user", "label": "Your twin", "status": "trusted", "plain": "This is your digital twin: a model of how you normally sign in, built only from the events stored in this app."}]; edges = []
    for d in s.execute(select(Device)).scalars().all():
        st = status(d.trust, fd.get(d.id)); n = dc.get(d.id, 0)
        why = {"trusted": "You have marked it trusted.", "unfamiliar": "It is not trusted yet, so activity from it is treated with more care.", "suspicious": "It is untrusted and was involved in unusual activity."}[st]
        nodes.append({"id": f"d{d.id}", "type": "device", "ref": d.id, "label": d.name, "status": st, "trust": d.trust, "last_seen": iso(d.last_seen), "count": n, "plain": f"{d.name} ({d.os}) appears in {n} stored event(s). {why}"})
        edges.append({"from": "user", "to": f"d{d.id}", "count": n})
    for n_ in s.execute(select(Network)).scalars().all():
        st = status(n_.trust, fn.get(n_.id)); n = nc.get(n_.id, 0)
        why = {"trusted": "It counts as familiar.", "unfamiliar": "It is new or untrusted.", "suspicious": "It is untrusted and appeared in unusual activity."}[st]
        nodes.append({"id": f"n{n_.id}", "type": "network", "ref": n_.id, "label": n_.name, "status": st, "trust": n_.trust, "last_seen": iso(n_.last_seen), "count": n, "plain": f"{n_.name} appears in {n} stored event(s). {why}"})
    for did, nid, c in s.execute(select(Event.device_id, Event.network_id, func.count(Event.id)).group_by(Event.device_id, Event.network_id)).all():
        edges.append({"from": f"d{did}", "to": f"n{nid}", "count": c})
    evs = []
    for e in flagged[:6]:
        reasons = [c["factor"] for c in e.contributors if c["points"] > 0]
        evs.append({"id": e.id, "device_id": e.device_id, "network_id": e.network_id, "severity": e.severity, "score": e.score, "ts": iso(e.ts),
                    "reasons": reasons, "plain": f"Sign-in from {e.device_name} on {e.network_name} looked unusual: " + (", ".join(r.lower() for r in reasons) or "see details") + "."})
    latest = flagged[0] if flagged else None
    fb = s.execute(select(Feedback.verdict, func.count(Feedback.id)).group_by(Feedback.verdict)).all(); fbd = dict(fb)
    orig = dict(s.execute(select(Event.synthetic, func.count(Event.id)).group_by(Event.synthetic)).all())
    bsyn = s.execute(select(func.count(Event.id)).where(Event.baseline_ok == True, Event.synthetic == True)).scalar() or 0  # noqa: E712
    open_inc = s.execute(select(func.count(Incident.id)).where(Incident.status.in_(OPEN))).scalar() or 0
    learning = not base["ready"]
    why_learning = (f"Your twin is still learning: it has {base['n']} normal sign-in events and needs at least {cfg['baseline_min_events']}. "
                    "Run the demo profile or add sample events to teach it.") if learning else ""
    conf = min(1.0, base["n"] / (2 * cfg["baseline_min_events"]))
    summary = {"learning": learning, "learning_message": why_learning, "learned_events": base["n"], "baseline_demo_events": bsyn, "baseline_user_events": base["n"] - bsyn,
               "devices": sum(n["type"] == "device" for n in nodes), "networks": sum(n["type"] == "network" for n in nodes), "open_incidents": open_inc,
               "usual_hour_utc": None if base["mean_hour"] is None else round(base["mean_hour"], 1), "time_window_hours": cfg["time_window_hours"],
               "origins": {"demonstration": orig.get(True, 0), "user_submitted": orig.get(False, 0)},
               "feedback": {"total": sum(fbd.values()), "expected": fbd.get("false_positive", 0) + fbd.get("benign_expected", 0), "suspicious": fbd.get("true_positive", 0),
                            "added_to_baseline": s.execute(select(func.count(Event.id)).where(Event.baseline_ok == True, Event.source != "synthetic-seed")).scalar() or 0},  # noqa: E712
               "latest_unusual": None if not latest else {"id": latest.id, "ts": iso(latest.ts), "score": latest.score, "severity": latest.severity, "device": latest.device_name,
                   "network": latest.network_name, "reasons": [c["factor"] for c in latest.contributors if c["points"] > 0], "benign_signals": [c["factor"] for c in latest.contributors if c["points"] < 0],
                   "uncertainty": latest.uncertainty, "confidence": latest.confidence, "method": latest.method, "explanation": latest.explanation,
                   "recommended": [eng.ACTIONS[a][0] for a in latest.recommended], "verify": "Check whether you recognise this device, network and time. If you do, mark it as expected.",
                   "origin": "demonstration" if latest.synthetic else "user-submitted"}}
    return {"nodes": nodes, "edges": edges, "events": evs, "baseline": base, "confidence": round(conf, 2), "summary": summary,
            "profile": {"usual_hour_utc": summary["usual_hour_utc"], "time_window_hours": cfg["time_window_hours"], "synthetic": orig.get(False, 0) == 0,
                        "note": "Built from demonstration seed events plus any events you submit and review. Nothing is collected from your real devices or accounts."}}

@app.post("/api/demo/prepare")
def demo_prepare(s: Session = Depends(db.get_session)):
    """Make the guided demo repeatable: demo-only entities go back to untrusted."""
    for model, name in ((Device, "Unrecognized Linux Host"), (Network, "Unknown Network (203.0.113.45)")):
        row = s.execute(select(model).where(model.name == name)).scalar_one_or_none()
        if row: row.trust = "untrusted"
    if not DET.ready: retrain(s)
    audit(s, "demo_prepare", "demo entities reset to untrusted"); s.commit(); return {"ready": DET.ready}

def baseline_eligible(s, e):
    """Guard so feedback cannot blindly teach the model that suspicious behaviour is normal."""
    if e.baseline_ok: return False, "Already part of the baseline."
    if not e.success: return False, "Failed sign-ins are never added to the baseline."
    if e.severity in ("High", "Critical"): return False, "High-priority events are kept as reviewed history and are not added to the baseline."
    if e.failed_attempts >= 3: return False, "Events with repeated failed sign-ins are not added to the baseline."
    seed_n = s.execute(select(func.count(Event.id)).where(Event.baseline_ok == True, Event.source == "synthetic-seed")).scalar() or 0  # noqa: E712
    added = s.execute(select(func.count(Event.id)).where(Event.baseline_ok == True, Event.source != "synthetic-seed")).scalar() or 0  # noqa: E712
    if added >= max(5, int(0.2 * seed_n)): return False, "Limit reached: at most 20% of the baseline can come from feedback."
    return True, "Added to the baseline and the model was retrained."

@app.post("/api/feedback", status_code=201)
def feedback(b: FeedbackIn, s: Session = Depends(db.get_session)):
    e = s.get(Event, b.event_id)
    if not e: raise HTTPException(404, "Event not found")
    s.add(Feedback(event_id=e.id, verdict=b.verdict, note=b.note))
    inc = s.execute(select(Incident).where(Incident.event_id == e.id)).scalar_one_or_none()
    if inc: inc.status = {"true_positive": "confirmed", "false_positive": "dismissed", "benign_expected": "dismissed"}[b.verdict]; inc.updated_at = utcnow()
    learned, reason = False, "Marked suspicious: never added to the baseline." if b.verdict == "true_positive" else ""
    if b.verdict != "true_positive":
        learned, reason = baseline_eligible(s, e)
        if learned: e.baseline_ok = True
    audit(s, "feedback", f"event {e.id}: {b.verdict}; baseline={learned} ({reason})"); s.commit()
    if learned: retrain(s)
    return {"saved": True, "added_to_baseline": learned, "baseline_note": reason, "incident_status": inc.status if inc else None}

@app.post("/api/response/execute", status_code=201)
def execute(b: ExecIn, s: Session = Depends(db.get_session)):
    if not b.confirm: raise HTTPException(400, "User confirmation (confirm=true) is required")
    inc = s.get(Incident, b.incident_id)
    if not inc: raise HTTPException(404, "Incident not found")
    e = s.get(Event, inc.event_id); label, mode = eng.ACTIONS[b.action]
    if b.action in ("mark_untrusted", "isolate_device"):
        d = s.get(Device, e.device_id); d.trust = "untrusted"
        if b.action == "isolate_device": d.isolated_sim = True
    msg = {"record_alert": "Alert stored in the local database. No notification was sent.",
           "request_verification": "SIMULATED: no verification request was sent to any real account.",
           "mark_untrusted": f"Demo device '{e.device_name}' marked untrusted in the local database only.",
           "revoke_session": "SIMULATED: no real session was revoked.",
           "isolate_device": f"SIMULATED: '{e.device_name}' flagged as isolated in the demo; no real device or network was changed."}[b.action]
    a = Action(incident_id=inc.id, action=b.action, label=label, target=e.device_name, mode=mode, status="simulated" if mode == "simulated" else "recorded_locally", result=msg)
    s.add(a); inc.status, inc.updated_at = "responded", utcnow(); audit(s, "response", f"{b.action} on incident {inc.id} ({mode})"); s.commit()
    return action_out(a)

@app.get("/api/response/actions")
def action_history(s: Session = Depends(db.get_session)):
    return {"items": [action_out(a) for a in s.execute(select(Action).order_by(Action.id.desc()).limit(200)).scalars()],
            "catalog": [{"key": k, "label": v[0], "mode": v[1]} for k, v in eng.ACTIONS.items()]}

def claude_answer(question, evidence):
    key = os.getenv("ANTHROPIC_API_KEY")
    if not key: return None
    try:
        r = httpx.post("https://api.anthropic.com/v1/messages", timeout=15, headers={"x-api-key": key, "anthropic-version": "2023-06-01"},
                       json={"model": os.getenv("CLAUDE_MODEL", "claude-sonnet-5-5"), "max_tokens": 450,
                             "system": "You are a security analyst assistant. Answer ONLY from the supplied evidence, mention uncertainty and benign explanations, never claim compromise is proven, and note that anomaly scores are not probabilities.",
                             "messages": [{"role": "user", "content": f"Evidence:\n{evidence}\n\nQuestion: {question}"}]})
        r.raise_for_status(); t = r.json()["content"][0]["text"]
        return t.strip()[:2500] if isinstance(t, str) and t.strip() else None
    except Exception:
        return None

@app.post("/api/investigate")
def investigate(b: InvestigateIn, s: Session = Depends(db.get_session)):
    cfg = cfg_of(s); q = b.question.lower()
    e = s.get(Event, b.event_id) if b.event_id else s.execute(select(Event).where(Event.score >= cfg["medium"]).order_by(Event.ts.desc())).scalars().first()
    total = s.execute(select(func.count(Event.id))).scalar(); nflag = s.execute(select(func.count(Event.id)).where(Event.score >= cfg["medium"])).scalar()
    evidence = {"Events stored": total, f"Events scored {cfg['medium']}+": nflag, "Data": "demonstration and user-submitted events only"}
    if e:
        evidence = {"Event": f"#{e.id} {e.event_type} at {iso(e.ts)}", "Score / severity": f"{e.score}/100 {e.severity} (triage priority)", "Device": f"{e.device_name} ({'trusted' if e.device_known else 'not trusted'})",
                    "Network": f"{e.network_name} ({'familiar' if e.network_known else 'new'})", "IP": e.ip or "n/a", "Failed attempts": e.failed_attempts, "MFA verified": e.mfa_verified, "Method": e.method,
                    "Contributors": "; ".join(f"{c['factor']} {c['points']:+d}" for c in e.contributors) or "none", "Data origin": "demonstration" if e.synthetic else "user-submitted"}
    pos = [c for c in e.contributors if c["points"] > 0] if e else []; ben = [c for c in e.contributors if c["points"] < 0] if e else []
    if any(w in q for w in ("summar", "recent", "today", "overview")):
        rec = s.execute(select(Event).where(Event.score >= cfg["medium"]).order_by(Event.ts.desc()).limit(3)).scalars().all()
        a = f"Your twin holds {total} stored events; {nflag} scored {cfg['medium']} or higher. " + ("Most recent items to review: " + "; ".join(f"#{x.id} {x.device_name} on {x.network_name} ({x.severity}, {x.score})" for x in rec) + "." if rec else "Nothing currently needs review.")
    elif "mean" in q or "what is a" in q or "risk score" in q:
        a = f"The score runs from 0 to 100 and ranks which activity to look at first. Under {cfg['medium']} is Low, {cfg['medium']}-{cfg['high'] - 1} Medium, {cfg['high']}-{cfg['critical'] - 1} High, {cfg['critical']}+ Critical. It adds up the reasons shown for each event. It is a priority, not the chance that an account is compromised."
    elif not e: a = "No suspicious findings are stored yet. Run a scenario or add a sample event, then ask again."
    elif "compromis" in q: a = f"This cannot be confirmed from the data. The event scores {e.score}/100 ({e.severity}) because of: {', '.join(c['factor'] for c in pos) or 'no risk factors'}. A score ranks priority; it is not the probability of compromise. Check with the account owner (you) whether it was expected."
    elif "caus" in q or "increase" in q or "contribut" in q or "score" in q: a = "Score drivers: " + ("; ".join(f"{c['factor']} ({c['points']:+d})" for c in e.contributors) or "none") + f". Total {e.score}/100."
    elif "benign" in q or "normal" in q or "legit" in q or "expected" in q: a = ("Signals pointing to normal behaviour: " + "; ".join(c["factor"] for c in ben) + ". " if ben else "") + "Possible innocent causes: travel, a new personal device, late-night work. If you recognise it, mark it as expected under Review feedback."
    elif "next" in q or "recommend" in q or "should i" in q or "do" in q.split(): a = "Recommended next steps: " + ("; ".join(eng.ACTIONS[k][0] for k in e.recommended) or "monitor only") + ". First verify whether you recognise the device, network and time. Actions in this demo are simulated or local records."
    else: a = f"{e.explanation} Confidence: {e.confidence}. {e.uncertainty}"
    ai = claude_answer(b.question, "\n".join(f"{k}: {v}" for k, v in evidence.items()))
    return {"mode": "claude" if ai else "deterministic", "answer": ai or a, "evidence": evidence, "event_id": e.id if e else None,
            "note": None if ai else "Deterministic answer from stored data (no Claude API key configured, or the call failed)."}

# ---------------------------------------------------------------- reports
def report_data(s):
    st = state(s); incs = incidents(status="", s=s)["items"]
    evs = events(min_score=0, limit=100, s=s, q="", severity="", source="", sort="ts", order="desc", offset=0)["items"]
    tw = twin(s)["summary"]
    fbs = [{"ts": iso(f.ts), "event_id": f.event_id, "verdict": f.verdict, "note": f.note} for f in s.execute(select(Feedback).order_by(Feedback.id.desc()).limit(30)).scalars()]
    prec = [f"Verify whether you recognise incident #{i['id']} ({i['device']}). Suggested: {', '.join(i['recommended_labels']) or 'monitor'}." for i in incs if i["status"] in OPEN][:8]
    prec += ["General: keep multi-factor authentication on for important accounts.", "General: review devices you no longer use and remove their access."]
    return {"generated_at": iso(utcnow()), "synthetic_data": st["synthetic_data"], "twin": tw, "origins": st["origins"], "baseline": st["baseline"], "feedback": fbs, "precautions": prec,
            "summary": {"risk": st["risk"], "totals": st["totals"], "incidents_by_severity": st["incidents_by_severity"]},
            "incidents": incs, "events": evs, "top_contributors": st["top_contributors"], "actions": action_history(s)["items"][:50]}

@app.get("/api/reports/summary")
def report_json(s: Session = Depends(db.get_session)): return report_data(s)

def safe(v):
    v = "" if v is None else str(v)
    return "'" + v if v[:1] in "=+-@" else v

@app.get("/api/reports/events.csv")
def report_csv(s: Session = Depends(db.get_session)):
    buf = io.StringIO(); w = csv.writer(buf)
    w.writerow(["id", "timestamp_utc", "type", "device", "network", "ip", "source", "synthetic", "score", "severity", "method", "contributors", "recommended", "incident_status"])
    for e in events(min_score=0, limit=500, s=s, q="", severity="", source="", sort="ts", order="desc", offset=0)["items"]:
        w.writerow([safe(x) for x in [e["id"], e["ts"], e["event_type"], e["device"], e["network"], e["ip"], e["source"], e["synthetic"], e["score"], e["severity"], e["method"],
                   "; ".join(f"{c['factor']} {c['points']:+d}" for c in e["contributors"]), "; ".join(e["recommended_labels"]), e["incident_status"]]])
    return Response(buf.getvalue(), media_type="text/csv", headers={"Content-Disposition": "attachment; filename=cybertwin-events.csv"})

@app.get("/api/reports/report.html", response_class=HTMLResponse)
def report_html(s: Session = Depends(db.get_session)):
    d = report_data(s); E = html.escape
    rows = lambda items, cols: "".join("<tr>" + "".join(f"<td>{E(str(f(i)))}</td>" for f in cols) + "</tr>" for i in items)
    return f"""<!doctype html><meta charset=utf-8><title>CyberTwin report</title><style>body{{font:14px system-ui;margin:32px;color:#111}}table{{border-collapse:collapse;width:100%;margin:8px 0 24px}}td,th{{border:1px solid #ccc;padding:6px;text-align:left}}.n{{background:#fff7d6;padding:8px}}@media print{{button{{display:none}}}}</style>
<button onclick=print()>Print / Save as PDF</button><h1>CyberTwin security report</h1><p class=n>Data origin: {d['origins']['demonstration']} demonstration event(s), {d['origins']['user_submitted']} user-submitted. Synthetic demo data is not real telemetry. Generated {E(d['generated_at'])}. Scores are triage priorities, not probabilities of compromise; this report does not prove that an attack occurred or that anything is secure.</p>
<h2>Digital twin overview</h2><p>{'Still learning: ' + E(d['twin']['learning_message']) if d['twin']['learning'] else 'Baseline ready.'} Learned from {d['twin']['learned_events']} events; {d['twin']['devices']} devices and {d['twin']['networks']} networks represented; usual sign-in hour {E(str(d['twin']['usual_hour_utc']))} UTC; {d['twin']['open_incidents']} open incident(s).</p>
<p>Current risk priority: <b>{d['summary']['risk']['score']}</b> ({E(d['summary']['risk']['severity'])}) &middot; events {d['summary']['totals']['events']} &middot; suspicious {d['summary']['totals']['suspicious']} &middot; open incidents {d['summary']['totals']['open_incidents']}</p>
<h2>Incidents</h2><table><tr><th>ID<th>Severity<th>Status<th>Score<th>Device<th>Recommended</tr>{rows(d['incidents'], [lambda i:i['id'], lambda i:i['severity'], lambda i:i['status'], lambda i:i['score'], lambda i:i['device'], lambda i:', '.join(i['recommended_labels'])])}</table>
<h2>Risk contributors</h2><table><tr><th>Factor<th>Total points</tr>{rows(d['top_contributors'], [lambda c:c['factor'], lambda c:c['points']])}</table>
<h2>Recent events</h2><table><tr><th>ID<th>Time (UTC)<th>Type<th>Device<th>Network<th>Score<th>Explanation</tr>{rows(d['events'][:40], [lambda e:e['id'], lambda e:e['ts'], lambda e:e['event_type'], lambda e:e['device'], lambda e:e['network'], lambda e:e['score'], lambda e:e['explanation']])}</table>
<h2>Review feedback history</h2><table><tr><th>Time<th>Event<th>Verdict<th>Note</tr>{rows(d['feedback'], [lambda f:f['ts'], lambda f:'#'+str(f['event_id']), lambda f:f['verdict'], lambda f:f['note']])}</table>
<h2>Recommended precautions</h2><ul>{''.join('<li>'+E(p)+'</li>' for p in d['precautions'])}</ul>
<h2>Response history (simulated actions are labelled)</h2><table><tr><th>Time<th>Action<th>Target<th>Status<th>Result</tr>{rows(d['actions'], [lambda a:a['ts'], lambda a:a['label'], lambda a:a['target'], lambda a:a['status'], lambda a:a['result']])}</table>"""

@app.post("/api/model/retrain")
def model_retrain(s: Session = Depends(db.get_session)):
    ok, n = retrain(s); audit(s, "retrain", f"trained={ok} samples={n}"); s.commit(); return {"trained": ok, "samples": n}

@app.post("/api/admin/reset")
def reset(b: ResetIn):
    if b.confirm != "RESET": raise HTTPException(400, 'Type "RESET" to confirm')
    db.Base.metadata.drop_all(db.engine); db.init_db()
    with db.SessionLocal() as s: seed(s)
    return {"reset": True}

app.mount("/", StaticFiles(directory=db.ROOT / "frontend", html=True), name="ui")
