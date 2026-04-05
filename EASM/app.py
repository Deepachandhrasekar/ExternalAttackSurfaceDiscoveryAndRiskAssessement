from flask import Flask, render_template, request, redirect, url_for, jsonify
from utils.target_check import is_valid_target
from celery.result import AsyncResult
from celery_app import celery
from tasks import run_scan
import openai

app = Flask(__name__)


# ── HOME ──────────────────────────────────────────────────────
@app.route("/", methods=["GET", "POST"])
def index():
    if request.method == "POST":
        target = request.form.get("target", "").strip()
        if not target:
            return render_template("index.html", error="Please enter a domain or IP address.")
        if not is_valid_target(target):
            return render_template("index.html",
                error="Invalid target. Enter a valid public IP (e.g. 8.8.8.8) or domain (e.g. example.com).")
        task = run_scan.delay(target)
        return render_template("scan_progress.html", task_id=task.id, target=target)
    return render_template("index.html")


# ── TASK STATUS (poll endpoint) ───────────────────────────────
@app.route("/status/<task_id>")
def scan_status(task_id):
    task = AsyncResult(task_id, app=celery)
    if task.state == "PENDING":
        return jsonify({"state": "PENDING", "step": "Waiting in queue...", "progress": 0})
    if task.state == "PROGRESS":
        info = task.info or {}
        return jsonify({
            "state":    "PROGRESS",
            "step":     info.get("step", ""),
            "progress": info.get("progress", 0)
        })
    if task.state == "SUCCESS":
        return jsonify({"state": "SUCCESS", "progress": 100})
    if task.state == "FAILURE":
        return jsonify({"state": "FAILURE", "error": str(task.info)})
    return jsonify({"state": task.state})


# ── DASHBOARD ─────────────────────────────────────────────────
@app.route("/dashboard/<task_id>")
def dashboard(task_id):
    task = AsyncResult(task_id, app=celery)
    if task.state != "SUCCESS":
        return redirect(url_for("index"))

    result      = task.result
    scan_results = result.get("scan", {})
    findings    = result.get("findings", [])
    risk        = result.get("risk", {})
    target      = result.get("target", "Unknown")

    ports    = scan_results.get("ports", [])
    services = scan_results.get("services", {})
    dns_data = scan_results.get("dns", {})
    https_data = scan_results.get("http", {})
    ssl_data = scan_results.get("ssl", {})
    ssh_data = scan_results.get("ssh", {})

    # Port table with severity
    SEV_MAP = {
        21: "CRITICAL", 23: "CRITICAL", 3389: "CRITICAL",
        22: "HIGH",      25: "HIGH",     8080: "MEDIUM",
        80: "MEDIUM",   443: "LOW",      53:  "LOW"
    }
    port_table = []
    for p in ports:
        svc = services.get(p) or services.get(str(p), "unknown")
        sev = SEV_MAP.get(p, "LOW")
        if isinstance(svc, str) and svc in ("ftp","telnet"): sev = "CRITICAL"
        elif isinstance(svc, str) and svc == "ssh": sev = "HIGH"
        port_table.append({
            "number": p, "protocol": "TCP",
            "service": svc, "status": "OPEN", "severity": sev
        })

    summary = {
        "total_score": risk.get("total_score", 0),
        "risk_level":  risk.get("risk_level", "LOW"),
        "critical": sum(1 for f in findings if f["severity"] == "CRITICAL"),
        "high":     sum(1 for f in findings if f["severity"] == "HIGH"),
        "medium":   sum(1 for f in findings if f["severity"] == "MEDIUM"),
        "low":      sum(1 for f in findings if f["severity"] == "LOW"),
    }

    service_dist = {}
    for p in ports:
        svc = services.get(p) or services.get(str(p), "unknown")
        service_dist[str(svc)] = service_dist.get(str(svc), 0) + 1
    
    print(scan_results)
    print(ports)

    return render_template("dashboard.html",
        scan_target=target,
        scan_summary=summary,
        scan_ports=port_table,
        service_dist=service_dist,
        dns_data=dns_data,
        https_data=https_data,
        ssl=ssl_data,
        ssh=ssh_data,
        findings=findings,
        task_id=task_id,
    )


#---------AI-----------

openai.api_key = "YOUR_API_KEY"

@app.route("/ai_remediation", methods=["POST"])
def ai_remediation():
    data = request.json
    prompt = data.get("prompt")

    try:
        response = openai.ChatCompletion.create(
            model="gpt-4o-mini",
            messages=[{"role": "user", "content": prompt}],
            max_tokens=800
        )

        return jsonify({
            "output": response.choices[0].message.content
        })

    except Exception as e:
        return jsonify({"error": str(e)})
    
    
# ── RULES PAGE ────────────────────────────────────────────────
@app.route("/rules")
def rules():
    from risk_engine.rules import RULES
    return render_template("rules.html", rules=RULES)


if __name__ == "__main__":
    app.run(debug=True, host="0.0.0.0", port=5000)
