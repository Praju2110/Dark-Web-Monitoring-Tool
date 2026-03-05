"""
Dark Web Monitor - Flask API Server
"""

from flask import Flask, jsonify, request
from flask_cors import CORS
import json
import sys
import threading
from pathlib import Path
from datetime import datetime

sys.path.insert(0, str(Path(__file__).parent))
from monitor import DarkWebMonitor, REPORT_DIR, CONFIG_PATH

app = Flask(__name__)
CORS(app)

scan_lock = threading.Lock()
scan_status = {"running": False, "last_scan": None}


def get_monitor():
    return DarkWebMonitor(CONFIG_PATH)


def load_latest():
    latest = REPORT_DIR / "latest.json"
    if latest.exists():
        with open(latest) as f:
            return json.load(f)
    return None


# ─── ENDPOINTS ───

@app.route("/api/health")
def health():
    return jsonify({"status": "ok", "time": datetime.utcnow().isoformat()})


@app.route("/api/config", methods=["GET"])
def get_config():
    try:
        m = get_monitor()
        safe = {k: v for k, v in m.config.items() if "key" not in k and "password" not in k}
        return jsonify({"status": "ok", "config": safe})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/config", methods=["POST"])
def save_config():
    try:
        body = request.get_json()
        if not body:
            return jsonify({"status": "error", "message": "No data"}), 400
        CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
        existing = {}
        if CONFIG_PATH.exists():
            with open(CONFIG_PATH) as f:
                existing = json.load(f)
        existing.update(body)
        with open(CONFIG_PATH, "w") as f:
            json.dump(existing, f, indent=2)
        return jsonify({"status": "ok", "message": "Config saved"})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/scan", methods=["POST"])
def run_scan():
    global scan_status
    if scan_status["running"]:
        return jsonify({"status": "busy", "message": "Scan already running"}), 409

    def do_scan():
        global scan_status
        scan_status["running"] = True
        try:
            m = get_monitor()
            m.run_scan()
            scan_status["last_scan"] = datetime.utcnow().isoformat()
        except Exception as e:
            print(f"Scan error: {e}")
        finally:
            scan_status["running"] = False

    t = threading.Thread(target=do_scan, daemon=True)
    t.start()
    return jsonify({"status": "ok", "message": "Scan started"})


@app.route("/api/scan/status")
def scan_status_ep():
    return jsonify({**scan_status, "status": "ok"})


@app.route("/api/results")
def get_results():
    try:
        data = load_latest()
        if not data:
            return jsonify({"status": "ok", "data": None, "message": "No scan run yet"})
        severity = request.args.get("severity")
        source   = request.args.get("source")
        is_new   = request.args.get("new")
        findings = data.get("findings", [])
        if severity:
            findings = [f for f in findings if f["severity"] == severity]
        if source:
            findings = [f for f in findings if f["source"] == source]
        if is_new == "true":
            findings = [f for f in findings if f.get("is_new")]
        data["findings"] = findings
        return jsonify({"status": "ok", "data": data})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/history")
def get_history():
    try:
        reports = sorted(REPORT_DIR.glob("scan_*.json"), reverse=True)[:20]
        history = []
        for r in reports:
            with open(r) as f:
                d = json.load(f)
            history.append({
                "file": r.name,
                "scan_time": d.get("scan_time"),
                "total_findings": d.get("total_findings", 0),
                "new_findings": d.get("new_findings", 0),
                "summary": d.get("summary", {}),
            })
        return jsonify({"status": "ok", "history": history})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


@app.route("/api/assets")
def get_assets():
    try:
        data = load_latest()
        if not data:
            m = get_monitor()
            assets = m.config
        else:
            assets = data.get("monitored_assets", {})
        return jsonify({"status": "ok", "assets": assets})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500


if __name__ == "__main__":
    print("╔══════════════════════════════════════════╗")
    print("║  🕵  Dark Web Monitor API  :5000          ║")
    print("╚══════════════════════════════════════════╝")
    app.run(debug=True, host="0.0.0.0", port=5000)
