# ================= MODULE WEIGHTS =================
MODULE_WEIGHTS = {
    "network": 1.2,
    "ssl": 1.1,
    "ssh": 1.2,
    "http": 1.0,
    "dns": 0.8
}


# ================= ATTACK MAP =================
ATTACK_MAP = {

    "NET-TELNET": ("Credential Theft", "Plaintext credentials can be intercepted"),
    "NET-FTP": ("Credential Theft", "FTP transmits credentials in plaintext"),
    "NET-RDP": ("Remote Compromise", "RDP brute-force or exploit risk"),
    "NET-SSH": ("Brute Force Attack", "SSH login attempts can compromise system"),
    "NET-DNS": ("DNS Enumeration", "Attackers may perform DNS amplification or recon"),
    "NET-DNS-TLS": ("DNS Enumeration", "Encrypted DNS service increases attack surface"),
    "NET-HTTPS": ("Attack Surface Exposure", "Public HTTPS service increases attack surface"),

    "SSL-INVALID": ("Spoofing / MITM", "Users may trust fake or compromised site"),
    "SSL-WEAK": ("MITM Attack", "Weak encryption can be broken"),
    "SSL-EXPIRING": ("Certificate Expiry", "Certificate expiry may cause outages"),

    "HTTP-CSP": ("XSS Attack", "Missing Content Security Policy"),
    "HTTP-HSTS": ("MITM Attack", "Missing HSTS allows downgrade attacks"),
    "HTTP-XFO": ("Clickjacking", "Missing X-Frame-Options"),
    "HTTP-XCTO": ("MIME Sniffing", "Missing X-Content-Type-Options"),
    "HTTP-REFERRER": ("Information Leakage", "Missing Referrer Policy"),

    "DNS-SPF": ("Email Spoofing", "Attackers can forge domain emails"),
    "DNS-DMARC": ("Phishing Campaign", "No policy to block fraudulent emails")
}


# ================= RULE ENGINE =================
def apply_rules(scan):

    findings = []

    services = scan.get("services", {}) or {}
    ssl = scan.get("ssl", {}) or {}
    http = scan.get("http", {}) or {}
    dns = scan.get("dns", {}) or {}

    domain = dns.get("domain")
    missing_headers = http.get("missing", [])

    # ================= NETWORK RULES =================
    for port, service in services.items():

        try:
            port = int(port)
        except:
            continue

        if port == 23:
            findings.append(_make("network","NET-TELNET",
                "Telnet exposed","CRITICAL",50,
                "Disable Telnet immediately"))

        elif port == 21:
            findings.append(_make("network","NET-FTP",
                "FTP exposed","CRITICAL",45,
                "Disable FTP or use FTPS"))

        elif port == 3389:
            findings.append(_make("network","NET-RDP",
                "RDP exposed","CRITICAL",45,
                "Restrict RDP via VPN"))

        elif port == 22:
            findings.append(_make("network","NET-SSH",
                "SSH exposed publicly","HIGH",30,
                "Restrict SSH access"))

        elif port == 53 and service != "domain":
            findings.append(_make("network","NET-DNS",
                "Suspicious DNS service detected","LOW",8,
                "Verify DNS configuration"))

        elif port == 853:
            findings.append(_make("network","NET-DNS-TLS",
                "DNS-over-TLS service detected","LOW",5,
                "Verify DNS-over-TLS configuration"))

        elif port == 443 and not ssl.get("valid"):
            findings.append(_make("network","NET-HTTPS",
                "HTTPS running without valid SSL","MEDIUM",12,
                "Fix TLS configuration"))

    # ================= SSL RULES =================
    if ssl.get("error"):
        findings.append(_make("ssl","SSL-INVALID",
            "Invalid SSL certificate","CRITICAL",40,
            "Install a valid certificate"))

    if ssl.get("tls_version") in ["TLSv1","TLSv1.1"]:
        findings.append(_make("ssl","SSL-WEAK",
            "Weak TLS version detected","HIGH",25,
            "Upgrade to TLS1.2+"))

    days_left = ssl.get("days_left")

    if days_left and days_left < 15:
        findings.append(_make("ssl","SSL-EXPIRING",
            "SSL certificate expiring soon","MEDIUM",15,
            "Renew certificate"))
    
    if ssl.get("weak_cipher"):
        findings.append(_make(
            "ssl",
            "SSL-WEAK-CIPHER",
            "Weak cipher detected",
            "HIGH",
            25,
            "Disable weak cipher suites"
        ))

    if ssl.get("expired"):
        findings.append(_make(
            "ssl",
            "SSL-EXPIRED",
            "SSL certificate expired",
            "CRITICAL",
            40,
            "Renew SSL certificate immediately"
        ))

    # ================= HTTP HEADER RULES =================
    if "Content-Security-Policy" in missing_headers:
        findings.append(_make("http","HTTP-CSP",
            "Missing Content Security Policy",
            "MEDIUM",15,
            "Implement CSP header"))

    if "Strict-Transport-Security" in missing_headers:
        findings.append(_make("http","HTTP-HSTS",
            "Missing HSTS header",
            "MEDIUM",15,
            "Enable HSTS"))

    if "X-Frame-Options" in missing_headers:
        findings.append(_make("http","HTTP-XFO",
            "Missing X-Frame-Options header",
            "LOW",8,
            "Add X-Frame-Options"))

    if "X-Content-Type-Options" in missing_headers:
        findings.append(_make("http","HTTP-XCTO",
            "Missing X-Content-Type-Options header",
            "LOW",8,
            "Add nosniff header"))

    if "Referrer-Policy" in missing_headers:
        findings.append(_make("http","HTTP-REFERRER",
            "Missing Referrer Policy header",
            "LOW",6,
            "Define Referrer-Policy"))

    # ================= DNS RULES =================
    email_sec = dns.get("email_security", {})

    # Only check if it is a real domain
    if domain and "." in domain:

        if not email_sec.get("spf"):
            findings.append(_make("dns","DNS-SPF",
                "Missing SPF record","MEDIUM",15,
                "Configure SPF record"))

        if not email_sec.get("dmarc"):
            findings.append(_make("dns","DNS-DMARC",
                "Missing DMARC policy","MEDIUM",15,
                "Implement DMARC"))

    return findings


# ================= HELPER =================
def _make(module, rule_id, issue, severity, base_score, fix):

    multiplier = MODULE_WEIGHTS.get(module, 1.0)
    adjusted_score = base_score * multiplier

    attack, impact = ATTACK_MAP.get(
        rule_id,
        ("Unknown Attack", "Security risk detected")
    )

    return {
        "module": module,
        "rule_id": rule_id,
        "issue": issue,
        "severity": severity,
        "weight": round(adjusted_score, 2),
        "attack": attack,
        "impact": impact,
        "fix": fix
    }

# ================= RULES LIST (for /rules page) =================
RULES = [
    {"id": "NET-TELNET",     "name": "Telnet Exposed",               "severity": "CRITICAL", "score": 60},
    {"id": "NET-FTP",        "name": "FTP Exposed",                  "severity": "CRITICAL", "score": 54},
    {"id": "NET-RDP",        "name": "RDP Exposed",                  "severity": "CRITICAL", "score": 54},
    {"id": "NET-SSH",        "name": "SSH Publicly Accessible",      "severity": "HIGH",     "score": 36},
    {"id": "NET-DNS",        "name": "Suspicious DNS Service",       "severity": "LOW",      "score": 9.6},
    {"id": "NET-DNS-TLS",    "name": "DNS-over-TLS Detected",        "severity": "LOW",      "score": 6},
    {"id": "NET-HTTPS",      "name": "HTTPS Without Valid SSL",      "severity": "MEDIUM",   "score": 14.4},
    {"id": "SSL-INVALID",    "name": "Invalid SSL Certificate",      "severity": "CRITICAL", "score": 44},
    {"id": "SSL-WEAK",       "name": "Weak TLS Version",             "severity": "HIGH",     "score": 27.5},
    {"id": "SSL-EXPIRING",   "name": "Certificate Expiring Soon",    "severity": "MEDIUM",   "score": 16.5},
    {"id": "SSL-WEAK-CIPHER","name": "Weak Cipher Suite",            "severity": "HIGH",     "score": 27.5},
    {"id": "SSL-EXPIRED",    "name": "SSL Certificate Expired",      "severity": "CRITICAL", "score": 44},
    {"id": "HTTP-CSP",       "name": "Missing Content-Security-Policy","severity": "MEDIUM", "score": 15},
    {"id": "HTTP-HSTS",      "name": "Missing HSTS Header",          "severity": "MEDIUM",   "score": 15},
    {"id": "HTTP-XFO",       "name": "Missing X-Frame-Options",      "severity": "LOW",      "score": 8},
    {"id": "HTTP-XCTO",      "name": "Missing X-Content-Type-Options","severity": "LOW",     "score": 8},
    {"id": "HTTP-REFERRER",  "name": "Missing Referrer-Policy",      "severity": "LOW",      "score": 6},
    {"id": "DNS-SPF",        "name": "Missing SPF Record",           "severity": "MEDIUM",   "score": 12},
    {"id": "DNS-DMARC",      "name": "Missing DMARC Policy",         "severity": "MEDIUM",   "score": 12},
]
