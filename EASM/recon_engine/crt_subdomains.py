import requests

def crtsh_subdomains(domain):

    subdomains = set()

    try:
        url = f"https://crt.sh/?q=%25.{domain}&output=json"

        response = requests.get(url, timeout=10)

        if response.status_code != 200:
            return []

        data = response.json()

        for entry in data:

            name_value = entry.get("name_value", "")

            for sub in name_value.split("\n"):

                sub = sub.strip()

                if sub.endswith(domain):
                    subdomains.add(sub)

    except Exception:
        pass

    return sorted(subdomains)