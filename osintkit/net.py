"""Tiny stdlib HTTP + DNS-over-HTTPS helpers shared by every module."""

import gzip
import json
import os
import zlib
import urllib.error
import urllib.parse
import urllib.request
from dataclasses import dataclass, field

UA = (
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 14_0) AppleWebKit/537.36 "
    "(KHTML, like Gecko) Chrome/126.0 Safari/537.36"
)
DEFAULT_TIMEOUT = float(os.environ.get("OSINT_TIMEOUT", "12"))
MAX_BODY = 3_000_000


@dataclass
class Response:
    status: int
    url: str
    headers: dict = field(default_factory=dict)
    text: str = ""

    def json(self):
        return json.loads(self.text)

    @property
    def ok(self):
        return 200 <= self.status < 300


def _decode(raw, headers):
    """Decompress gzip/deflate bodies (some servers send them even unasked) and decode to text."""
    enc = {k.lower(): v for k, v in headers.items()}.get("content-encoding", "").lower()
    try:
        if "gzip" in enc or raw[:2] == b"\x1f\x8b":
            raw = gzip.decompress(raw)
        elif "deflate" in enc:
            raw = zlib.decompress(raw, -zlib.MAX_WBITS)
    except (OSError, zlib.error, EOFError):
        pass
    return raw.decode("utf-8", "replace")


def request(url, method="GET", headers=None, data=None, timeout=None, retries=1):
    """HTTP request that returns a Response for any status (no raise on 4xx/5xx).

    Network-level failures (DNS, timeout, TLS) are retried `retries` times,
    then raised; the runner records them as errors for that source.
    """
    for attempt in range(retries + 1):
        try:
            return _request(url, method, headers, data, timeout)
        except (urllib.error.URLError, TimeoutError, ConnectionError, OSError) as e:
            if isinstance(e, urllib.error.HTTPError) or attempt == retries:
                raise


def _request(url, method, headers, data, timeout):
    hdrs = {"User-Agent": UA, "Accept": "*/*"}
    hdrs.update(headers or {})
    body = None
    if data is not None:
        if isinstance(data, (dict, list)):
            body = json.dumps(data).encode()
            hdrs.setdefault("Content-Type", "application/json")
        else:
            body = data if isinstance(data, bytes) else str(data).encode()
    req = urllib.request.Request(url, data=body, headers=hdrs, method=method)
    try:
        with urllib.request.urlopen(req, timeout=timeout or DEFAULT_TIMEOUT) as r:
            raw = r.read(MAX_BODY)
            return Response(r.status, r.geturl(), dict(r.headers), _decode(raw, dict(r.headers)))
    except urllib.error.HTTPError as e:
        try:
            raw = e.read(MAX_BODY)
        except Exception:
            raw = b""
        return Response(e.code, url, dict(e.headers or {}), _decode(raw, dict(e.headers or {})))


def get(url, **kw):
    return request(url, **kw)


def get_json(url, **kw):
    """GET and parse JSON. Returns (status, data_or_None)."""
    headers = {"Accept": "application/json", **kw.pop("headers", {})}
    r = request(url, headers=headers, **kw)
    try:
        return r.status, r.json()
    except ValueError:
        return r.status, None


def q(s):
    return urllib.parse.quote(str(s), safe="")


# --- DNS over HTTPS (Google) -------------------------------------------------

DNS_TYPES = {1: "A", 2: "NS", 5: "CNAME", 6: "SOA", 12: "PTR", 15: "MX", 16: "TXT", 28: "AAAA", 257: "CAA"}


def dns(name, rtype="A"):
    """Resolve via DNS-over-HTTPS. Returns a list of answer strings."""
    status, data = get_json(f"https://dns.google/resolve?name={q(name)}&type={rtype}")
    if status != 200 or not data:
        raise RuntimeError(f"DoH lookup failed (HTTP {status})")
    want = rtype.upper()
    out = []
    for ans in data.get("Answer", []) or []:
        if DNS_TYPES.get(ans.get("type")) == want:
            out.append(ans.get("data", "").strip().strip('"') if want == "TXT" else ans.get("data", "").rstrip("."))
    return out


def reverse_dns(ip):
    import ipaddress

    return dns(ipaddress.ip_address(ip).reverse_pointer, "PTR")
