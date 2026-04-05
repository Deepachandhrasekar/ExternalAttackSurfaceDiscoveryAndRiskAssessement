import requests


def check_http_security(target):

    data = {
        "enabled": False,
        "status_code": None,
        "headers": {},
        "server": None,
        "content_preview": None,
        "csp": False,
        "hsts": False,
        "x_frame_options": False,
        "error": None
    }

    urls = [
        f"https://{target}",
        f"http://{target}"
    ]

    for url in urls:

        try:

            r = requests.get(url, timeout=5)

            data["enabled"] = True
            data["status_code"] = r.status_code
            data["headers"] = dict(r.headers)

            data["server"] = r.headers.get("Server")

            data["csp"] = "Content-Security-Policy" in r.headers
            data["hsts"] = "Strict-Transport-Security" in r.headers
            data["x_frame_options"] = "X-Frame-Options" in r.headers

            data["content_preview"] = r.text[:1000]

            return data

        except Exception as e:
            data["error"] = str(e)

    return data