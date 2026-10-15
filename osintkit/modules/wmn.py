"""WhatsMyName integration — the community username-detection dataset behind
osintframework.com's username section (github.com/WebBreacher/WhatsMyName).

Each site defines an "exists" signal (e_code + e_string) and a "missing" signal
(m_code + m_string). Anything matching neither is reported as inconclusive.
"""

import json
import os
import time

from ..net import get, q, request

DATA_URL = "https://raw.githubusercontent.com/WebBreacher/WhatsMyName/main/wmn-data.json"
CACHE = os.path.join(os.path.expanduser("~"), ".cache", "osintkit", "wmn-data.json")
MAX_AGE = 7 * 86400


def load_sites():
    """Return the WMN site list, refreshing the local cache weekly."""
    fresh = os.path.exists(CACHE) and time.time() - os.path.getmtime(CACHE) < MAX_AGE
    if not fresh:
        try:
            r = get(DATA_URL, timeout=30)
            if r.ok:
                os.makedirs(os.path.dirname(CACHE), exist_ok=True)
                with open(CACHE, "w") as f:
                    f.write(r.text)
        except Exception:
            pass  # fall back to a stale cache if we have one
    if not os.path.exists(CACHE):
        raise RuntimeError("could not download WhatsMyName data")
    with open(CACHE) as f:
        return [s for s in json.load(f)["sites"] if s.get("valid", True) is not False]


def check(site, username):
    u = username
    for ch in site.get("strip_bad_char", ""):
        u = u.replace(ch, "")
    url = site["uri_check"].replace("{account}", q(u))
    pretty = site.get("uri_pretty", site["uri_check"]).replace("{account}", q(u))
    headers = site.get("headers", {})
    if site.get("post_body"):
        r = request(url, method="POST", headers=headers, data=site["post_body"].replace("{account}", u), timeout=8, retries=0)
    else:
        r = request(url, headers=headers, timeout=8, retries=0)
    if r.status == site["e_code"] and site["e_string"] in r.text:
        return {"found": True, "url": pretty, "category": site.get("cat")}
    if r.status == site["m_code"] and site["m_string"] in r.text:
        return {"found": False, "category": site.get("cat")}
    if r.status == site["m_code"] and site["m_code"] != site["e_code"]:
        return {"found": False, "category": site.get("cat")}
    return {"found": None, "http": r.status, "category": site.get("cat")}
