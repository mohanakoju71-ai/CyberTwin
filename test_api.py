import os, re, tempfile
from pathlib import Path
TMP = tempfile.mkdtemp()
os.environ["CYBERTWIN_DATA_DIR"] = TMP
os.environ.pop("DATABASE_URL", None); os.environ.pop("ANTHROPIC_API_KEY", None)
import pytest
from fastapi.testclient import TestClient
from backend.main import app
from backend import db, main

@pytest.fixture(scope="module")
def c():
    with TestClient(app) as cl: yield cl

def run(c, k): 
    r = c.post(f"/api/scenarios/{k}/run"); assert r.status_code == 201, r.text; return r.json()

def test_health_and_frontend(c):
    assert c.get("/api/health").json()["status"] == "ok"
    r = c.get("/"); assert r.status_code == 200 and "CyberTwin" in r.text
    for f in re.findall(r'(?:src|href)="([^"h][^"]*)"', r.text): assert c.get("/" + f).status_code == 200, f
    assert c.get("/docs").status_code == 200

def test_state_derived_from_db(c):
    s = c.get("/api/state").json()
    assert s["totals"]["events"] >= 60 and s["synthetic_data"] and s["baseline"]["model_trained"]
    assert len(s["trend_24h"]) == 24 and len(s["trend_7d"]) == 7

def test_scenarios_sensible(c):
    n = run(c, "normal"); assert n["severity"] == "Low" and n["incident_id"] is None
    u = run(c, "unknown_device"); assert u["score"] >= 30 and any(x["factor"].startswith("Unknown") for x in u["contributors"])
    m = run(c, "multi_signal"); assert m["score"] >= 60 and m["incident_id"]
    b = run(c, "benign_unusual"); assert b["score"] < m["score"] and any(x["kind"] == "benign" for x in b["contributors"])
    for k in ("failed_then_success", "unusual_time"): assert run(c, k)["score"] >= 30
    assert all(0 <= e["score"] <= 100 for e in c.get("/api/events?limit=500").json()["items"])

def test_validation_and_duplicates(c):
    bad = {"user": "a b!", "device": "x", "network": "y"}
    assert c.post("/api/ingest", json=bad).status_code == 422
    assert c.post("/api/ingest", json={"user": "a", "device": "x", "network": "y", "ip": "999.1.1.1"}).status_code == 422
    assert c.post("/api/ingest", json={"user": "a", "device": "x", "network": "y", "failed_attempts": -1}).status_code == 422
    p = {"user": "a", "device": "Personal Laptop", "network": "Home Wi-Fi", "event_id": "dup-1"}
    assert c.post("/api/ingest", json=p).status_code == 201 and c.post("/api/ingest", json=p).status_code == 409
    assert c.post("/api/ingest", json={**p, "event_id": "f", "timestamp": "2099-01-01T00:00:00Z"}).status_code == 422

def test_feedback_response_device_flow(c):
    e = run(c, "multi_signal")
    assert c.post("/api/response/execute", json={"incident_id": e["incident_id"], "action": "isolate_device"}).status_code == 400
    a = c.post("/api/response/execute", json={"incident_id": e["incident_id"], "action": "isolate_device", "confirm": True}).json()
    assert a["status"] == "simulated" and "SIMULATED" in a["result"]
    a2 = c.post("/api/response/execute", json={"incident_id": e["incident_id"], "action": "mark_untrusted", "confirm": True}).json()
    assert a2["status"] == "recorded_locally"
    assert c.post("/api/feedback", json={"event_id": e["id"], "verdict": "true_positive", "note": "x"}).status_code == 201
    d = c.get(f"/api/events/{e['id']}").json(); assert d["feedback"][0]["verdict"] == "true_positive" and len(d["actions"]) == 2
    dev = next(x for x in c.get("/api/devices").json()["items"] if x["name"] == "Unrecognized Linux Host")
    assert c.post(f"/api/devices/{dev['id']}/trust", json={"trust": "trusted"}).status_code == 400
    assert c.post(f"/api/devices/{dev['id']}/trust", json={"trust": "trusted", "confirm": True}).json()["trust"] == "trusted"
    c.post(f"/api/devices/{dev['id']}/trust", json={"trust": "untrusted", "confirm": True})

def test_dashboard_updates_after_event(c):
    before = c.get("/api/state").json()["totals"]["events"]; run(c, "unknown_device")
    assert c.get("/api/state").json()["totals"]["events"] == before + 1

def test_settings(c):
    s = c.get("/api/settings").json()
    assert c.put("/api/settings", json={**s, "medium": 70, "high": 60}).status_code == 422
    assert c.put("/api/settings", json={**s, "refresh_seconds": 9}).json()["refresh_seconds"] == 9

def test_reports_and_investigation(c):
    assert "Personal Laptop" in c.get("/api/reports/events.csv").text
    h = c.get("/api/reports/report.html").text; assert "Synthetic demo data" in h
    r = c.post("/api/investigate", json={"question": "Is my account compromised?"}).json()
    assert r["mode"] == "deterministic" and "probability" in r["answer"]
    assert c.get("/api/reports/summary").json()["synthetic_data"] is True

def test_persistence_and_safe_init(c):
    n = c.get("/api/state").json()["totals"]["events"]
    db.init_db()
    with db.SessionLocal() as s: assert main.seed(s) is False
    assert c.get("/api/state").json()["totals"]["events"] == n
    with TestClient(app) as c2: assert c2.get("/api/state").json()["totals"]["events"] == n  # simulated restart

def test_reset_requires_confirmation(c):
    assert c.post("/api/admin/reset", json={"confirm": "no"}).status_code == 400
    assert c.post("/api/admin/reset", json={"confirm": "RESET"}).json()["reset"] is True
    assert c.get("/api/state").json()["totals"]["events"] == 60


# ---------------- v3 additions ----------------
def test_twin_summary_is_derived_and_labelled(c):
    c.post("/api/admin/reset", json={"confirm": "RESET"})
    t = c.get("/api/twin").json(); S = t["summary"]
    assert S["learned_events"] == 60 and S["devices"] >= 3 and S["origins"]["demonstration"] == 60 and S["latest_unusual"] is None
    assert all(n["plain"] for n in t["nodes"]) and t["profile"]["synthetic"] is True
    run(c, "multi_signal")
    t = c.get("/api/twin").json()
    assert t["summary"]["latest_unusual"]["reasons"] and t["events"] and any(n["status"] == "suspicious" for n in t["nodes"])
    assert t["summary"]["open_incidents"] >= 1

def test_learning_state_when_baseline_small(c):
    s = c.get("/api/settings").json(); c.put("/api/settings", json={**s, "baseline_min_events": 500})
    S = c.get("/api/twin").json()["summary"]; assert S["learning"] and "still learning" in S["learning_message"]
    c.put("/api/settings", json={**s, "baseline_min_events": 30})

def test_user_submitted_event_is_labelled(c):
    r = c.post("/api/ingest", json={"user": "aarav", "device": "Personal Laptop", "network": "Home Wi-Fi", "synthetic": False, "source": "user-form", "event_id": "u-1"})
    assert r.status_code == 201 and r.json()["origin"] == "user-submitted"
    st = c.get("/api/state").json(); assert st["origins"]["user_submitted"] >= 1

def test_feedback_cannot_teach_suspicious_events(c):
    e = run(c, "multi_signal"); assert e["severity"] in ("High", "Critical")
    r = c.post("/api/feedback", json={"event_id": e["id"], "verdict": "false_positive"}).json()
    assert r["added_to_baseline"] is False and r["baseline_note"]
    sus = run(c, "failed_then_success")
    assert c.post("/api/feedback", json={"event_id": sus["id"], "verdict": "true_positive"}).json()["added_to_baseline"] is False
    ok = run(c, "benign_unusual"); r = c.post("/api/feedback", json={"event_id": ok["id"], "verdict": "benign_expected"}).json()
    assert r["added_to_baseline"] is True and c.get("/api/twin").json()["summary"]["feedback"]["added_to_baseline"] >= 1

def test_demo_prepare_and_assistant_questions(c):
    assert c.post("/api/demo/prepare").json()["ready"] is True
    run(c, "unknown_device")
    for q in ["Why was this sign-in flagged?", "What does this risk score mean?", "Could this activity be normal?", "What should I do next?", "Summarize my recent security activity."]:
        r = c.post("/api/investigate", json={"question": q}); assert r.status_code == 200 and r.json()["mode"] == "deterministic" and len(r.json()["answer"]) > 30, q
    assert "not the chance" in c.post("/api/investigate", json={"question": "What does this risk score mean?"}).json()["answer"]

def test_report_has_new_sections(c):
    h = c.get("/api/reports/report.html").text
    for w in ("Digital twin overview", "Review feedback history", "Recommended precautions", "does not prove"): assert w in h
    j = c.get("/api/reports/summary").json(); assert j["twin"] and j["feedback"] is not None and j["precautions"]

def test_paging_and_errors(c):
    p1 = c.get("/api/events?limit=5&offset=0").json(); p2 = c.get("/api/events?limit=5&offset=5").json()
    assert p1["total"] == p2["total"] and not {x["id"] for x in p1["items"]} & {x["id"] for x in p2["items"]}
    assert c.get("/api/events/999999").status_code == 404 and c.get("/api/nope").status_code in (404, 405)

def test_health_reports_ready(c):
    h = c.get("/api/health").json(); assert h["ready"] and h["python"]

def test_launcher_module_and_js_syntax():
    import importlib.util, shutil, subprocess
    spec = importlib.util.spec_from_file_location("launch", Path(__file__).resolve().parent.parent / "scripts" / "launch.py"); m = importlib.util.module_from_spec(spec); spec.loader.exec_module(m)
    assert m.URL.startswith("http://127.0.0.1:") and callable(m.main)
    if shutil.which("node"):
        assert subprocess.run(["node", "--check", str(Path(__file__).resolve().parent.parent / "frontend" / "app.js")]).returncode == 0
