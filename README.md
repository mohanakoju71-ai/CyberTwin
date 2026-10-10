# CyberTwin - Your Personal Cybersecurity Digital Twin
CyberTwin builds a **digital twin**: a simple, continuously updated model of your sign-in habits (which devices and networks you normally use, and when). It then points out activity that looks different, explains why in plain words, and suggests what to check.

> **All data is demonstration or typed in by you.** CyberTwin does not read your real accounts, passwords, codes, computer or network. Protective actions are simulated or local records. A score is a priority to review, never proof of a problem.

Screenshot checklist (for your presentation): Home, My Digital Twin (graph + "In plain words"), an opened alert with risk contributors, Protection Actions history, Reports.

## Requirements
Windows 10/11 (or Linux/macOS), Python **3.10-3.13** (3.12 recommended), internet access for the first install.

## Windows - one click
1. Install Python 3.12 from https://www.python.org/downloads/ and tick **"Add python.exe to PATH"**.
2. Unzip this folder (avoid very long paths).
3. Double-click **`run_cybertwin.bat`**. First run creates `.venv` and installs packages (a few minutes). The browser opens **only after** the server answers its health check.
4. Stop with CTRL+C in the window, or double-click **`stop_cybertwin.bat`**.
`run_cybertwin_dev.bat` starts with auto-reload for developers only.

## Manual start (any OS), from the project folder
    python -m venv .venv
    .venv\Scripts\activate          (Linux/macOS: source .venv/bin/activate)
    pip install -r requirements.txt
    python -m uvicorn backend.main:app --host 127.0.0.1 --port 8000
- App: http://127.0.0.1:8000  - Health: http://127.0.0.1:8000/api/health  - API docs: http://127.0.0.1:8000/docs
- Development with reload: `python -m uvicorn backend.main:app --reload --reload-dir backend`

## Guided demo (5 minutes)
Open the app and click **Guided demo** (Home, or the top bar). It walks through 12 steps: welcome, what CyberTwin can/cannot see, demo profile, learned baseline, devices and networks, a suspicious demo event, why it differs, score and uncertainty, marking it expected/suspicious, feedback history, recommended (simulated) action, and the report. No manual setup is needed. Start fresh any time: **Settings -> Reset demo data** (type RESET).

## Use your own sample events
Security Activity -> **Add a sample event**. These are labelled *user-submitted* (typed by you, not captured). Never enter passwords or codes.

## Tests
    pip install -r requirements-dev.txt
    python -m pytest -q tests                 # 19 backend tests
    python scripts/evaluate.py                # synthetic evaluation (optimistic; see caveat it prints)
Optional UI smoke test (needs Node.js): `cd tests && npm i jsdom && set BASE=http://127.0.0.1:8000 && node ui_smoke.js`

## Optional AI assistant
Copy `.env.example` to `.env` (the batch file does this) and set `ANTHROPIC_API_KEY=your-key` (and optionally `CLAUDE_MODEL`). The key stays on the server. Without it, the assistant gives deterministic answers from stored data.

## How detection works
Validate -> features (hour, failed attempts, device known, network known, success) -> baseline -> Isolation Forest (anomaly measure, trained on baseline events) + fixed rules + correlation -> 0-100 priority score with listed reasons -> uncertainty note -> stored event/incident. Rule matches, the ML measure and confirmed incidents are shown separately; nothing is "confirmed" unless you mark it so.

## Troubleshooting
- **Browser says "can't be reached"**: use `run_cybertwin.bat` (waits for readiness). Read the window for errors.
- **Port 8000 busy**: run `stop_cybertwin.bat`, or `set PORT=8010` then start again (open http://127.0.0.1:8010).
- **"No compatible Python"**: install Python 3.10-3.13; Python 3.14 is not supported yet by the scientific packages.
- **Install fails**: check internet/proxy, delete the `.venv` folder, run the batch file again.
- **Blank or odd page**: hard refresh (Ctrl+F5); check `/api/health`.
- **Start over**: Settings -> Reset demo data, or delete the `data` folder while the server is stopped.

## Limitations
Single-user, no login (do not expose publicly). Synthetic baseline. No real integrations or real response actions. PDF = browser "Save as PDF" from the printable report. Docker image is provided but was not built here. Windows batch files were written carefully but not executed on Windows in the authoring environment.
