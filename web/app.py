import os
import sys
import threading
import uuid
from pathlib import Path
from urllib.parse import urlparse
from flask import Flask, render_template, request
from werkzeug.exceptions import RequestEntityTooLarge
from werkzeug.utils import secure_filename

ROOT_DIR = Path(__file__).resolve().parent.parent
if str(ROOT_DIR) not in sys.path:
    sys.path.insert(0, str(ROOT_DIR))

from malscope.core import analyze_file  # noqa: E402

ALLOWED_EXTENSIONS = {".exe", ".dll", ".sys", ".com"}
MAX_UPLOAD_BYTES = 50 * 1024 * 1024  # 50 MB safe limit
UPLOAD_TEMP_DIR = ROOT_DIR / "output" / ".tmp_uploads"

app = Flask(__name__, template_folder="templates")
app.config["MAX_CONTENT_LENGTH"] = MAX_UPLOAD_BYTES
app.config["ACTIVE_PORT"] = 5000


@app.before_request
def enforce_local_origin():
    """Block DNS rebinding and cross-site request forgery (CSRF) from external websites."""
    port = app.config.get("ACTIVE_PORT", 5000)
    allowed_hosts = {f"127.0.0.1:{port}", f"localhost:{port}", "127.0.0.1", "localhost"}

    host_header = request.headers.get("Host", "").strip().lower()
    if host_header not in allowed_hosts:
        return render_template("index.html", error="Forbidden: Invalid Host header."), 403

    if request.method == "POST":
        origin = request.headers.get("Origin", "").strip()
        if origin:
            origin_host = urlparse(origin).netloc.lower()
            if origin_host not in allowed_hosts:
                return render_template("index.html", error="Forbidden: Cross-site POST request blocked."), 403


@app.errorhandler(RequestEntityTooLarge)
def handle_large_file(_err):
    return render_template("index.html", error="File exceeds the maximum safe limit of 50 MB."), 413


@app.get("/")
def index():
    return render_template("index.html", error=None)


@app.post("/analyze")
def analyze():
    # Server-side authorization gate (cannot be bypassed by disabling JavaScript)
    if request.form.get("consent") != "agree":
        return render_template(
            "index.html",
            error="Authorization required: Please confirm compliance with the Computer Crimes Act 1997 before scanning.",
        ), 400

    uploaded = request.files.get("sample_file")
    if not uploaded or not uploaded.filename:
        return render_template("index.html", error="Please select a file to analyze."), 400

    original_name = secure_filename(uploaded.filename) or "uploaded_sample.bin"
    ext = Path(original_name).suffix.lower()

    if ext not in ALLOWED_EXTENSIONS:
        return render_template(
            "index.html",
            error=f"Unsupported file extension '{ext or 'none'}'. Allowed types: .exe, .dll, .sys, .com",
        ), 400

    # Save using a random filename and delete immediately after static analysis
    UPLOAD_TEMP_DIR.mkdir(parents=True, exist_ok=True)
    temp_path = UPLOAD_TEMP_DIR / f"{uuid.uuid4().hex}{ext}"

    try:
        uploaded.save(temp_path)
        if temp_path.stat().st_size == 0:
            return render_template("index.html", error="Empty file (0 bytes) cannot be analyzed."), 400

        rules_file = ROOT_DIR / "rules.json"
        report = analyze_file(temp_path, rules_path=rules_file)
        report["file"]["name"] = original_name

        entropy_val = float(report["file"]["overall_entropy"])
        entropy_pct = min(100.0, max(0.0, round((entropy_val / 8.0) * 100, 1)))

        return render_template("report.html", report=report, entropy_pct=entropy_pct)
    except (FileNotFoundError, ValueError) as err:
        return render_template("index.html", error=f"Analysis error: {err}"), 500
    finally:
        temp_path.unlink(missing_ok=True)


@app.post("/shutdown")
def shutdown():
    """Web kill switch to safely terminate the local Flask server."""
    threading.Timer(0.4, lambda: os._exit(0)).start()
    return (
        "<html><body style='background:#0b1120;color:#e2e8f0;font-family:system-ui,sans-serif;"
        "display:grid;place-items:center;height:100vh;margin:0'>"
        "<div style='text-align:center'><h2>MalScope Server Stopped</h2>"
        "<p style='color:#94a3b8'>Local session terminated safely. You may close this tab.</p></div>"
        "</body></html>"
    )


def run_web_server(host: str = "127.0.0.1", port: int = 5000):
    """Run Flask strictly on localhost with debug mode disabled."""
    app.config["ACTIVE_PORT"] = port
    print("\n====================================================================")
    print(f"  MALSCOPE LOCAL WEB UI RUNNING AT: http://{host}:{port}")
    print("  Press Ctrl+C in terminal or click 'Stop Server' in UI to exit.")
    print("====================================================================\n")
    app.run(host=host, port=port, debug=False)


if __name__ == "__main__":
    run_web_server()