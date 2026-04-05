import ipaddress
import re

def is_valid_target(target):
    """
    Accept both public IP addresses and valid domain names.
    Blocks private/loopback IPs.
    """
    target = target.strip()
    if not target:
        return False

    # Try as IP address first
    try:
        ip = ipaddress.ip_address(target)
        if ip.is_private or ip.is_loopback or ip.is_reserved:
            return False
        return True
    except ValueError:
        pass

    # Validate as domain name
    # Must have at least one dot, no spaces, valid characters
    domain_re = re.compile(
        r'^(?:[a-zA-Z0-9]'
        r'(?:[a-zA-Z0-9\-]{0,61}[a-zA-Z0-9])?\.)'
        r'+[a-zA-Z]{2,}$'
    )
    if domain_re.match(target):
        return True

    return False
