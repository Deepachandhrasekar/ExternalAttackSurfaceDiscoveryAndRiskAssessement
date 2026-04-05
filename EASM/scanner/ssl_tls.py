import socket
import ssl
from datetime import datetime


def scan_ssl(target, port=443):

    data = {
        "enabled": False,
        "protocol": None,
        "cipher": None,
        "issuer": None,
        "expires": None,
        "days_left": None,
        "weak_cipher": False,
        "expired": False,
        "error": None
    }

    try:

        context = ssl.create_default_context()

        with socket.create_connection((target, port), timeout=5) as sock:

            with context.wrap_socket(sock, server_hostname=target) as ssock:

                cert = ssock.getpeercert()

                data["enabled"] = True
                data["protocol"] = ssock.version()

                cipher = ssock.cipher()
                data["cipher"] = cipher[0]

                # Check weak cipher
                if "RC4" in cipher[0] or "DES" in cipher[0]:
                    data["weak_cipher"] = True

                # Certificate issuer
                issuer = dict(x[0] for x in cert["issuer"])
                data["issuer"] = issuer.get("organizationName")

                # Expiry date
                expire = cert["notAfter"]
                data["expires"] = expire

                expire_date = datetime.strptime(
                    expire, "%b %d %H:%M:%S %Y %Z"
                )

                days_left = (expire_date - datetime.utcnow()).days

                data["days_left"] = days_left

                if days_left < 0:
                    data["expired"] = True

    except Exception as e:

        data["error"] = str(e)

    return data