"""Domain intelligence: WHOIS/RDAP, DNS, subdomains (CT logs), archives, web fingerprint."""

import os
import re
import socket
import ssl
from concurrent.futures import ThreadPoolExecutor

from ..net import dns, get, get_json, q
from ..runner import Skip, run_checks

RECORD_TYPES = ("A", "AAAA", "MX", "NS", "TXT", "CNAME", "SOA", "CAA")
SECURITY_HEADERS = (
    "strict-transport-security", "content-security-policy", "x-frame-options",
    "x-content-type-options", "referrer-policy", "permissions-policy",
)


def rdap_whois(d):
    status, j = get_json(f"https://rdap.org/domain/{q(d)}", timeout=20)
    if status == 404:
        return {"registered": False}
    if status != 200 or not j:
        raise RuntimeError(f"RDAP HTTP {status}")
    events = {e.get("eventAction"): e.get("eventDate") for e in j.get("events", [])}
    registrar, contacts = None, []
    for ent in j.get("entities", []):
        roles = ent.get("roles", [])
        name = _vcard_name(ent)
        if "registrar" in roles:
            registrar = name
        elif name:
            contacts.append({"roles": roles, "name": name})
    return {
        "registered": True,
        "registrar": registrar,
        "created": events.get("registration"),
        "updated": events.get("last changed"),
        "expires": events.get("expiration"),
        "status": j.get("status"),
        "nameservers": [n.get("ldhName", "").lower() for n in j.get("nameservers", [])],
        "contacts": contacts,
    }


def _vcard_name(ent):
    for item in (ent.get("vcardArray") or [None, []])[1]:
        if item and item[0] == "fn":
            return item[3]
    return None


def dns_records(d):
    out = {}
    for t in RECORD_TYPES:
        try:
            ans = dns(d, t)
        except Exception:
            continue
        if ans:
            out[t] = ans
    return out


def email_security(d):
    spf = [t for t in dns(d, "TXT") if t.lower().startswith("v=spf1")]
    dmarc = [t for t in dns(f"_dmarc.{d}", "TXT") if t.lower().startswith("v=dmarc1")]
    return {"spf": spf[0] if spf else None, "dmarc": dmarc[0] if dmarc else None,
            "mx": dns(d, "MX")}


def crtsh_subdomains(d):
    for _ in range(2):  # crt.sh frequently 502s under load; one retry usually succeeds
        status, j = get_json(f"https://crt.sh/?q=%25.{q(d)}&output=json", timeout=45)
        if status == 200:
            break
    if status != 200 or j is None:
        raise RuntimeError(f"crt.sh HTTP {status}")
    names = set()
    for row in j:
        for n in row.get("name_value", "").split("\n"):
            n = n.strip().lower().lstrip("*.")
            if n.endswith(d):
                names.add(n)
    return sorted(names)


def certspotter_subdomains(d):
    status, j = get_json(
        f"https://api.certspotter.com/v1/issuances?domain={q(d)}&include_subdomains=true&expand=dns_names",
        timeout=30)
    if status != 200 or j is None:
        raise RuntimeError(f"CertSpotter HTTP {status}")
    names = {n.lower().lstrip("*.") for row in j for n in row.get("dns_names", [])}
    return sorted(n for n in names if n.endswith(d))


def hackertarget_hosts(d):
    r = get(f"https://api.hackertarget.com/hostsearch/?q={q(d)}", timeout=20)
    if "API count exceeded" in r.text or r.status != 200:
        raise RuntimeError("HackerTarget rate limit / error")
    rows = [line.split(",") for line in r.text.strip().splitlines() if "," in line]
    return [{"host": h, "ip": ip} for h, ip in rows]


def wayback(d):
    _, avail = get_json(f"https://archive.org/wayback/available?url={q(d)}", timeout=20)
    _, first = get_json(
        f"https://web.archive.org/cdx/search/cdx?url={q(d)}&output=json&limit=1&fl=timestamp,original", timeout=25)
    closest = (avail or {}).get("archived_snapshots", {}).get("closest", {})
    return {
        "first_capture": first[1][0] if first and len(first) > 1 else None,
        "latest_capture": closest.get("timestamp"),
        "latest_url": closest.get("url"),
    }


def urlscan(d):
    status, j = get_json(f"https://urlscan.io/api/v1/search/?q=domain:{q(d)}&size=10", timeout=20)
    if status != 200 or not j:
        raise RuntimeError(f"urlscan HTTP {status}")
    return [{"time": r["task"].get("time"), "url": r["page"].get("url"), "ip": r["page"].get("ip"),
             "server": r["page"].get("server"), "country": r["page"].get("country"),
             "report": r.get("result", "").replace("/api/v1/result/", "/result/")}
            for r in j.get("results", [])]


def web_fingerprint(d):
    r = get(f"https://{d}", timeout=15)
    h = {k.lower(): v for k, v in r.headers.items()}
    title = re.search(r"<title[^>]*>(.*?)</title>", r.text, re.I | re.S)
    gen = re.search(r'<meta[^>]+name=["\']generator["\'][^>]+content=["\']([^"\']+)', r.text, re.I)
    tech = [name for name, pat in TECH_PATTERNS.items() if re.search(pat, r.text[:300000], re.I)]
    return {
        "final_url": r.url,
        "status": r.status,
        "title": title.group(1).strip()[:200] if title else None,
        "server": h.get("server"),
        "powered_by": h.get("x-powered-by"),
        "generator": gen.group(1) if gen else None,
        "technologies": tech,
        "security_headers": {k: (k in h) for k in SECURITY_HEADERS},
        "emails_on_page": sorted(set(re.findall(r"[A-Za-z0-9._%+-]+@" + re.escape(d), r.text)))[:20],
        "social_links": sorted(set(m.rstrip("/\\") for m in re.findall(SOCIAL_RE, r.text)))[:30],
        "phone_links": sorted(set(re.findall(r'href=["\']tel:([+\d\s().-]{7,20})', r.text)))[:10],
        "analytics_ids": sorted(set(re.findall(r"\b(UA-\d{4,10}-\d{1,4}|G-[A-Z0-9]{8,12}|GTM-[A-Z0-9]{5,8})\b", r.text)))[:10],
    }


SOCIAL_RE = (r"https?://(?:www\.)?(?:twitter\.com|x\.com|facebook\.com|instagram\.com|linkedin\.com/(?:company|in)|"
             r"youtube\.com/(?:@|c/|channel/|user/)|github\.com|tiktok\.com/@|t\.me|discord\.gg|mastodon\.social/@|"
             r"bsky\.app/profile|threads\.net/@|pinterest\.com|reddit\.com/r/)[A-Za-z0-9_./@-]{2,80}")


def tls_certificate(d):
    ctx = ssl.create_default_context()
    with socket.create_connection((d, 443), timeout=10) as sock:
        with ctx.wrap_socket(sock, server_hostname=d) as tls:
            cert = tls.getpeercert()
            version = tls.version()
    flat = lambda seq: {k: v for part in seq for k, v in part}  # noqa: E731
    sans = [v for k, v in cert.get("subjectAltName", []) if k == "DNS"]
    return {"subject": flat(cert.get("subject", [])).get("commonName"),
            "organization": flat(cert.get("subject", [])).get("organizationName"),
            "issuer": flat(cert.get("issuer", [])).get("organizationName"),
            "valid_from": cert.get("notBefore"), "valid_until": cert.get("notAfter"),
            "tls_version": version, "san_count": len(sans), "sans": sans[:50]}


def otx_passive_dns(d):
    key = os.environ.get("OTX_API_KEY")
    if not key:
        raise Skip("set OTX_API_KEY (free at otx.alienvault.com)")
    _, j = get_json(f"https://otx.alienvault.com/api/v1/indicators/domain/{q(d)}/passive_dns",
                    headers={"X-OTX-API-KEY": key}, timeout=25)
    rows = (j or {}).get("passive_dns", [])
    return [{"host": r.get("hostname"), "address": r.get("address"), "type": r.get("record_type"),
             "first": r.get("first"), "last": r.get("last")} for r in rows[:200]]


def hunter_domain(d):
    key = os.environ.get("HUNTER_API_KEY")
    if not key:
        raise Skip("set HUNTER_API_KEY (free tier at hunter.io)")
    _, j = get_json(f"https://api.hunter.io/v2/domain-search?domain={q(d)}&limit=25&api_key={key}")
    data = (j or {}).get("data", {})
    return {"organization": data.get("organization"), "pattern": data.get("pattern"),
            "emails": [{"email": e.get("value"), "name": " ".join(x for x in (e.get("first_name"), e.get("last_name")) if x),
                        "position": e.get("position"), "confidence": e.get("confidence")} for e in data.get("emails", [])]}


def virustotal_domain(d):
    key = os.environ.get("VT_API_KEY")
    if not key:
        raise Skip("set VT_API_KEY")
    _, j = get_json(f"https://www.virustotal.com/api/v3/domains/{q(d)}", headers={"x-apikey": key})
    a = (j or {}).get("data", {}).get("attributes", {})
    return {"last_analysis_stats": a.get("last_analysis_stats"), "reputation": a.get("reputation"),
            "categories": a.get("categories"), "popularity_ranks": a.get("popularity_ranks")}


def resolve_hosts(hosts, limit=300):
    """Resolve subdomains to find which are live; returns [{host, ips}]."""
    def one(h):
        try:
            return {"host": h, "ips": dns(h, "A")}
        except Exception:
            return {"host": h, "ips": []}
    with ThreadPoolExecutor(max_workers=32) as pool:
        rows = list(pool.map(one, sorted(hosts)[:limit]))
    return [r for r in rows if r["ips"]]


TECH_PATTERNS = {
    "WordPress": r"wp-content|wp-includes", "Shopify": r"cdn\.shopify\.com", "Wix": r"wixstatic\.com",
    "Squarespace": r"squarespace\.com", "React": r"react(-dom)?(\.production)?\.min\.js|__NEXT_DATA__|data-reactroot",
    "Next.js": r"__NEXT_DATA__|/_next/", "Vue": r"vue(\.min)?\.js|data-v-", "Angular": r"ng-version",
    "jQuery": r"jquery(\.min)?\.js", "Bootstrap": r"bootstrap(\.min)?\.(css|js)",
    "Google Analytics": r"googletagmanager\.com|google-analytics\.com", "Cloudflare": r"cdnjs\.cloudflare\.com|cf-ray",
    "HubSpot": r"js\.hs-scripts\.com", "Drupal": r"Drupal\.settings|/sites/default/files",
}


def well_known(d):
    out = {}
    for path in ("robots.txt", ".well-known/security.txt", "sitemap.xml"):
        try:
            r = get(f"https://{d}/{path}", timeout=10)
        except Exception:
            continue
        if r.status == 200 and "<html" not in r.text[:500].lower():
            out[path] = r.text[:2000]
    return out


def investigate(domain, progress=None):
    d = domain.strip().lower().rstrip(".")
    if d.startswith("www."):
        d = d[4:]
    checks = {
        "WHOIS (RDAP)": rdap_whois,
        "DNS records": dns_records,
        "Email security (SPF/DMARC/MX)": email_security,
        "Subdomains: crt.sh": crtsh_subdomains,
        "Subdomains: CertSpotter": certspotter_subdomains,
        "Hosts: HackerTarget": hackertarget_hosts,
        "Wayback Machine": wayback,
        "urlscan.io history": urlscan,
        "Web fingerprint": web_fingerprint,
        "robots / security.txt": well_known,
        "TLS certificate": tls_certificate,
        "Passive DNS (AlienVault OTX)": otx_passive_dns,
        "Staff emails (Hunter.io)": hunter_domain,
        "VirusTotal": virustotal_domain,
    }
    results = run_checks(checks, d, on_done=progress)

    subs = set()
    for k in ("Subdomains: crt.sh", "Subdomains: CertSpotter"):
        if results[k]["status"] == "ok":
            subs.update(results[k]["data"])
    if results["Hosts: HackerTarget"]["status"] == "ok":
        subs.update(h["host"] for h in results["Hosts: HackerTarget"]["data"])
    for row in results["Passive DNS (AlienVault OTX)"].get("data") or []:
        if (row.get("host") or "").endswith(d):
            subs.add(row["host"])
    subs.discard(d)

    # second phase: which subdomains actually resolve?
    live = run_checks({"Live subdomains (DNS)": lambda _t: resolve_hosts(subs)}, d, on_done=progress)
    results.update(live)

    whois = results["WHOIS (RDAP)"].get("data") or {}
    dnsd = results["DNS records"].get("data") or {}
    summary = {
        "registrar": whois.get("registrar"),
        "created": whois.get("created"),
        "expires": whois.get("expires"),
        "ips": dnsd.get("A", []) + dnsd.get("AAAA", []),
        "mail": dnsd.get("MX", []),
        "subdomain_count": len(subs),
        "live_subdomains": len(results["Live subdomains (DNS)"].get("data") or []),
        "tls_issuer": (results["TLS certificate"].get("data") or {}).get("issuer"),
        "tech": (results["Web fingerprint"].get("data") or {}).get("technologies"),
        "social_links": (results["Web fingerprint"].get("data") or {}).get("social_links"),
        "subdomains": sorted(subs),
    }
    return {"summary": summary, "sources": results}
