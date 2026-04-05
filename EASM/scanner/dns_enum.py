import dns.resolver
import socket


def dns_enum(target):

    result = {
        "ip": None,
        "domain": None,
        "records": {},
        "email_security": {
            "spf": False,
            "dmarc": False,
            "dkim": False
        }
    }

    domain = None
    ip = None

    # ================= DOMAIN → IP =================
    try:
        ip = socket.gethostbyname(target)
        result["ip"] = ip
        domain = target
    except:
        ip = target
        result["ip"] = ip

    # ================= IP → DOMAIN =================
    # Keep original domain FIRST
    if "." in target and not target.replace(".", "").isdigit():
        domain = target
        result["domain"] = domain
    else:
        domain = None

        
    #  Store reverse DNS separately (DON'T overwrite)
    try:
        reverse_domain = socket.gethostbyaddr(ip)[0]
        result["reverse_dns"] = reverse_domain
    except:
        pass
    
    if not domain:
        return result

    # ================= DNS RECORD TYPES =================
    record_types = [
        "A",
        "AAAA",
        "MX",
        "NS",
        "TXT",
        "CNAME",
        "SOA",
        "CAA"
    ]

    for rtype in record_types:

        result["records"][rtype] = {
            "found": False,
            "values": []
        }

        try:

            answers = dns.resolver.resolve(domain, rtype)

            values = []

            for r in answers:
                values.append(str(r))

            result["records"][rtype]["found"] = True
            result["records"][rtype]["values"] = values

        except:
            pass

    # ================= EMAIL SECURITY =================

    # SPF detection
    txt_records = result["records"]["TXT"]["values"]

    for txt in txt_records:

        if "v=spf1" in txt.lower():
            result["email_security"]["spf"] = True

        if "v=dmarc1" in txt.lower():
            result["email_security"]["dmarc"] = True

    # DKIM detection
    try:
        dkim = dns.resolver.resolve(
            f"default._domainkey.{domain}",
            "TXT"
        )

        if dkim:
            result["email_security"]["dkim"] = True

    except:
        pass

    return result