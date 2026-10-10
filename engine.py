"""Detection engine: feature extraction, Isolation Forest, deterministic rules, bounded risk score, explanation."""
import math
import joblib
import numpy as np
from sklearn.ensemble import IsolationForest

# Fixed feature order, shared by training and inference.
FEATURES = ["hour_sin", "hour_cos", "failed_attempts", "device_known", "network_known", "success"]

ACTIONS = {  # key: (label, mode)
    "record_alert": ("Record security alert", "local-record"),
    "request_verification": ("Request additional verification", "simulated"),
    "mark_untrusted": ("Mark demo device untrusted", "local-record"),
    "revoke_session": ("Simulate session revocation", "simulated"),
    "isolate_device": ("Simulate device isolation", "simulated"),
}

def vec(hour, failed, device_known, network_known, success):
    return [math.sin(2 * math.pi * hour / 24), math.cos(2 * math.pi * hour / 24),
            min(int(failed), 20), int(bool(device_known)), int(bool(network_known)), int(bool(success))]

def circ_dist(a, b):
    d = abs(a - b) % 24
    return min(d, 24 - d)

def circ_mean(hours):
    if not hours: return None
    s = sum(math.sin(2 * math.pi * h / 24) for h in hours); c = sum(math.cos(2 * math.pi * h / 24) for h in hours)
    return (math.atan2(s, c) * 24 / (2 * math.pi)) % 24

class Detector:
    def __init__(self, path):
        self.path, self.model, self.n_train = path, None, 0
    @property
    def ready(self): return self.model is not None
    def load(self):
        try:
            d = joblib.load(self.path)
            if d.get("features") == FEATURES:
                self.model, self.n_train = d["model"], d["n"]
        except Exception:
            self.model = None
    def train(self, X, min_events):
        if len(X) < max(20, min_events):
            self.model, self.n_train = None, len(X); return False
        self.model = IsolationForest(n_estimators=150, contamination="auto", random_state=42).fit(np.array(X, float))
        self.n_train = len(X)
        joblib.dump({"model": self.model, "features": FEATURES, "n": self.n_train}, self.path)
        return True
    def anomaly(self, x):
        """0..1 relative anomaly measure from IsolationForest.decision_function. NOT a probability of compromise."""
        if not self.ready: return None
        df = float(self.model.decision_function(np.array([x], float))[0])
        return float(np.clip((0.05 - df) / 0.25, 0, 1))

def severity_of(score, cfg):
    return "Critical" if score >= cfg["critical"] else "High" if score >= cfg["high"] else "Medium" if score >= cfg["medium"] else "Low"

def assess(ev, base, det, cfg):
    """ev: hour, failed, device_known, network_known, success, mfa. base: n, mean_hour. Returns detection dict."""
    c, notes, rules = [], [], []
    def add(factor, pts, detail, kind): c.append({"factor": factor, "points": pts, "detail": detail, "kind": kind})
    if not ev["device_known"]:
        add("Unknown or untrusted device", 30, "The device is not in this profile's trusted device set.", "rule"); rules.append("unknown_device")
    if not ev["network_known"]:
        add("New or untrusted network", 15, "The network is not trusted or previously known.", "rule"); rules.append("new_network")
    base_ready = base["n"] >= cfg["baseline_min_events"] and base["mean_hour"] is not None
    if base_ready:
        d = circ_dist(ev["hour"], base["mean_hour"])
        if d > cfg["time_window_hours"]:
            pts = min(25, round(14 + 2 * (d - cfg["time_window_hours"])))
            add("Unusual activity time", pts, f"{d:.1f} h from the usual centre ({base['mean_hour']:.1f}h UTC); window is ±{cfg['time_window_hours']} h.", "rule"); rules.append("unusual_time")
    else:
        notes.append(f"Time-of-day rule skipped: only {base['n']} baseline events (need {cfg['baseline_min_events']}).")
    if ev["failed"] >= 3:
        add("Repeated failed attempts", min(20, ev["failed"] * 4), f"{ev['failed']} failed attempts before this event.", "rule"); rules.append("repeated_failures")
        if ev["success"]:
            add("Success after repeated failures", 15, "A successful sign-in followed several failures (possible guessing).", "correlation"); rules.append("success_after_failures")
    x = vec(ev["hour"], ev["failed"], ev["device_known"], ev["network_known"], ev["success"])
    a = det.anomaly(x)
    if a is None:
        notes.append("Isolation Forest unavailable (not enough baseline events); rules only.")
    elif a > 0.2:
        add("Behaviour deviation (Isolation Forest)", round(15 * a), f"Relative anomaly measure {a:.2f} (0 = typical, 1 = most unusual). Not a probability of compromise.", "model")
    if ev["mfa"] and ev["device_known"]:
        add("MFA verified on trusted device", -15, "Benign evidence: verified second factor on a trusted device.", "benign"); rules.append("mfa_trusted_device")
    score = int(max(0, min(100, sum(f["points"] for f in c))))
    sev = severity_of(score, cfg)
    method = ("Isolation Forest + " if det.ready else "") + "deterministic rules"
    risky = [f for f in c if f["points"] > 0]
    expl = ("Flagged because: " + "; ".join(f["factor"].lower() for f in risky) + "." if risky else "Consistent with the learned baseline; no rule matched.")
    if any(f["kind"] == "benign" for f in c): expl += " Benign evidence lowered the score."
    full = base_ready and det.ready
    unc = ("Baseline is synthetic and small; scores are triage priorities, not proof of compromise. " +
           "Benign explanations: travel, new personal device, late-night work. " + " ".join(notes)).strip()
    rec = {"Low": [], "Medium": ["record_alert"], "High": ["request_verification"], "Critical": ["revoke_session", "isolate_device"]}[sev][:]
    if sev in ("Medium", "High", "Critical") and not ev["device_known"]: rec.append("mark_untrusted")
    return {"score": score, "severity": sev, "method": method, "contributors": c, "explanation": expl, "uncertainty": unc,
            "confidence": "moderate" if full else "low", "recommended": rec, "rules": rules, "anomaly": a,
            "features": dict(zip(FEATURES, [round(v, 4) for v in x]))}
