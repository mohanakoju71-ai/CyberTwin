# Changelog

## 3.0 - Twin-first redesign and startup fix
**Startup / "reload error" (diagnosed)**
- Cause found in the old `run_cybertwin.bat`: the browser was opened after a fixed 4-second `timeout`, but a cold start takes about 3-6 s here (scikit-learn import, DB creation, model training) and longer on Windows with antivirus scanning. The browser therefore showed Chrome's "site can't be reached - Reload" page. `timeout` inside `start /b cmd /c` can also return instantly because it does not support redirected input. The old script and README also ran `--reload`, which watches the whole project folder including `.venv`.
- Not reproduced: an actual reload loop (`--reload` was stable on Linux), import errors, redirect loops, route or static-file problems.
- Fix: `scripts/launch.py` starts Uvicorn, waits for `/api/health`, then opens the browser; reload is off by default (`run_cybertwin_dev.bat` / `--reload --reload-dir backend` only for development); Python 3.10-3.13 check (3.12 preferred); import verification; port-conflict message; `stop_cybertwin.bat`.
- Frontend: 12 s request timeout, bounded automatic retry (5x) with a clear "waiting for the server" message, stale-render protection for overlapping requests, refresh guard.

**Experience**
- 9-item navigation with sub-tabs; every earlier page is preserved as a sub-page.
- New Home, My Digital Twin (interactive SVG: twin, devices, networks, event markers, plain-language details, seven expandable questions), Add-a-sample-event form, welcome dialog, 12-step guided demo.
- Backend `/api/twin` now returns a derived plain-language summary; `/api/demo/prepare` makes the demo repeatable.

**Detection & safety**
- Feedback guard: suspicious/high-priority/failed-login events are never added to the baseline; feedback is capped at 20% of the baseline; the reason is returned and shown.
- Assistant answers the five suggested questions from stored data; Claude optional (backend only).
- Data origin (`demonstration` / `user-submitted`) on every event; reports include twin overview, baseline readiness, feedback history, precautions.
- SQLite WAL + busy timeout; generic 500 handler logs server-side without exposing details.
- Tests: 19 backend tests, optional jsdom UI smoke test (`tests/ui_smoke.js`).

## 2.0
Database persistence, detection pipeline, scenarios, reports.
