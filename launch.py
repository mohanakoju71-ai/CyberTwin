"""Reliable launcher: starts the server, waits until /api/health answers, THEN opens the browser.
Usage: python scripts/launch.py [--reload] [--no-browser]   (PORT env var overrides 8000)"""
import json, os, socket, subprocess, sys, time, urllib.request, webbrowser
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
HOST, PORT = "127.0.0.1", int(os.getenv("PORT", "8000"))
URL = f"http://{HOST}:{PORT}"

def health():
    try:
        with urllib.request.urlopen(URL + "/api/health", timeout=2) as r:
            return json.load(r).get("status") == "ok"
    except Exception:
        return False

def port_in_use():
    with socket.socket() as s:
        s.settimeout(0.5)
        return s.connect_ex((HOST, PORT)) == 0

def main():
    reload_mode, browser = "--reload" in sys.argv, "--no-browser" not in sys.argv
    os.chdir(ROOT)
    if port_in_use():
        if health():
            print(f"CyberTwin is already running at {URL}"); browser and webbrowser.open(URL); return 0
        print(f"[ERROR] Port {PORT} is used by another program. Close it, or run with another port:  set PORT=8010  then start again.")
        return 2
    cmd = [sys.executable, "-m", "uvicorn", "backend.main:app", "--host", HOST, "--port", str(PORT)]
    if reload_mode: cmd += ["--reload", "--reload-dir", "backend"]
    print("Starting:", " ".join(cmd))
    proc = subprocess.Popen(cmd, cwd=ROOT)
    pidfile = ROOT / "data" / "server.pid"; pidfile.parent.mkdir(exist_ok=True); pidfile.write_text(str(proc.pid))
    try:
        deadline = time.time() + 90
        while time.time() < deadline:
            if proc.poll() is not None:
                print(f"[ERROR] The server stopped during startup (exit code {proc.returncode}). Read the messages above."); return 1
            if health(): break
            time.sleep(0.5)
        else:
            print("[ERROR] The server did not become ready within 90 seconds."); proc.terminate(); return 1
        print(f"\nCyberTwin is ready:  {URL}   (docs: {URL}/docs, health: {URL}/api/health)\nPress CTRL+C to stop.")
        if browser: webbrowser.open(URL)
        return proc.wait()
    except KeyboardInterrupt:
        print("\nStopping..."); proc.terminate()
        try: proc.wait(10)
        except subprocess.TimeoutExpired: proc.kill()
        return 0
    finally:
        try: pidfile.unlink()
        except OSError: pass

if __name__ == "__main__":
    sys.exit(main())
