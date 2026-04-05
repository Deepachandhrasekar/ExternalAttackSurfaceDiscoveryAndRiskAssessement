import json
import logging
import socket
from celery_app import celery
from scanner.port_scan import scan_ports
from scanner.dns_enum import dns_enum
from scanner.ssl_tls import scan_ssl
from scanner.ssh_check import ssh_check
from scanner.http_headers import check_http_security
from risk_engine.rules import apply_rules
from risk_engine.scorer import calculate_risk_score

log = logging.getLogger(__name__)

# ─── Pretty banner helpers ─────────────────────────────────────────────────────
SEP  = "=" * 64
SEP2 = "-" * 64

def _jdump(obj):
    return json.dumps(obj, indent=2, default=str)

def _log_section(title, data):
    log.info(f"\n{SEP2}\n  {title}\n{SEP2}")
    log.info(_jdump(data))


@celery.task(bind=True, name="tasks.run_scan")
def run_scan(self, target):

    log.info(f"\n{SEP}")
    log.info(f"  EASM SCAN STARTED")
    log.info(f"  Target : {target}")
    log.info(SEP)

    scan_results = {}

    # ── 1. PORT SCAN ──────────────────────────────────────────
    self.update_state(state="PROGRESS", meta={"step": "Port Scanning", "progress": 10})
    log.info("\n[1/5]  PORT SCANNING ...")
    ports, services = scan_ports(target)
    scan_results["ports"]    = ports
    scan_results["services"] = services
    _log_section("PORT SCAN RESULT", {
        "open_ports": ports,
        "services":   {str(k): v for k, v in services.items()}
    })

    # ── 2. DNS ENUMERATION ────────────────────────────────────
    self.update_state(state="PROGRESS", meta={"step": "DNS Enumeration", "progress": 28})
    log.info("\n[2/5]  DNS ENUMERATION ...")
    try:
        dns_data = dns_enum(target)
        
        scan_results["dns"] = dns_data
    except Exception as e:
        scan_results["dns"] = {
            "ip": target, "domain": None,
            "records": {}, "email_security": {}, "error": str(e)
        }
    _log_section("DNS RESULT", scan_results["dns"])

    # ── 3. SSL / TLS ──────────────────────────────────────────
    self.update_state(state="PROGRESS", meta={"step": "SSL/TLS Analysis", "progress": 50})
    log.info("\n[3/5]  SSL/TLS ANALYSIS ...")
    try:
        scan_results["ssl"] = scan_ssl(target)
    except Exception as e:
        scan_results["ssl"] = {"enabled": False, "error": str(e)}
    _log_section("SSL/TLS RESULT", scan_results["ssl"])

    # ── 4. SSH ────────────────────────────────────────────────
    self.update_state(state="PROGRESS", meta={"step": "SSH Detection", "progress": 65})
    log.info("\n[4/5]  SSH DETECTION ...")
    try:
        scan_results["ssh"] = ssh_check(target)
    except Exception as e:
        scan_results["ssh"] = {"open": False, "error": str(e)}
    _log_section("SSH RESULT", scan_results["ssh"])

    # ── 5. HTTP HEADERS ───────────────────────────────────────
    self.update_state(state="PROGRESS", meta={"step": "HTTP Security", "progress": 80})
    log.info("\n[5/5]  HTTP SECURITY HEADERS ...")
    try:
        scan_results["http"] = check_http_security(target)
    except Exception as e:
        scan_results["http"] = {"enabled": False, "error": str(e)}
    _log_section("HTTP RESULT", scan_results["http"])

    # ── RULE ENGINE + SCORING ─────────────────────────────────
    self.update_state(state="PROGRESS", meta={"step": "Analysing risk", "progress": 93})
    log.info("\n  RUNNING RULE ENGINE + RISK SCORING ...")
    findings = apply_rules(scan_results)
    risk     = calculate_risk_score(findings)

    final = {
        "target":   target,
        "scan":     scan_results,
        "findings": findings,
        "risk":     risk,
    }

    # ── FINAL JSON OUTPUT ─────────────────────────────────────
    log.info(f"\n{SEP}")
    log.info(f"  SCAN COMPLETE  —  {target}")
    log.info(f"  Risk Score : {risk['total_score']}  |  Level : {risk['risk_level']}")
    log.info(f"  Findings   : {len(findings)}  (critical={sum(1 for f in findings if f['severity']=='CRITICAL')}, "
             f"high={sum(1 for f in findings if f['severity']=='HIGH')}, "
             f"medium={sum(1 for f in findings if f['severity']=='MEDIUM')}, "
             f"low={sum(1 for f in findings if f['severity']=='LOW')})")
    log.info(SEP)
    log.info("\n  FULL JSON RESULT:\n")
    log.info(_jdump(final))
    log.info(f"\n{SEP}\n")

    return final
