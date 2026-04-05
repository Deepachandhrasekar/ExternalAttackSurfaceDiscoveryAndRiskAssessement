import socket
import ssl

COMMON_SUBDOMAINS = [
    "www", "mail", "api", "dev",
    "test", "staging", "admin",
    "vpn", "portal", "blog"
]

def brute_force_subdomains(domain):
    discovered = []

    for sub in COMMON_SUBDOMAINS:
        full_domain = f"{sub}.{domain}"
        try:
            socket.gethostbyname(full_domain)
            discovered.append(full_domain)
        except:
            pass

    return discovered

def extract_ssl_subdomains(domain):
    discovered = []

    try:
        context = ssl.create_default_context()
        with socket.create_connection((domain, 443), timeout=5) as sock:
            with context.wrap_socket(sock, server_hostname=domain) as ssock:
                cert = ssock.getpeercert()

        for ext in cert.get("subjectAltName", []):
            if ext[0] == "DNS":
                discovered.append(ext[1])

    except:
        pass

    return discovered

def discover_subdomains(domain):
    brute = brute_force_subdomains(domain)
    ssl_subs = extract_ssl_subdomains(domain)

    all_subs = list(set(brute + ssl_subs))

    return all_subs