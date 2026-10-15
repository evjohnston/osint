"""IP address intelligence: geolocation, ownership, open ports, reputation."""

import ipaddress
import os

from ..net import get, get_json, q, reverse_dns
from ..runner import Skip, run_checks

_tor_cache = None


def ip_api(ip):
    _, j = get_json(f"http://ip-api.com/json/{q(ip)}?fields=status,message,country,regionName,city,zip,lat,lon,"
                    "timezone,isp,org,as,asname,reverse,mobile,proxy,hosting")
    if not j or j.get("status") != "success":
        raise RuntimeError((j or {}).get("message", "ip-api failed"))
    j.pop("status", None)
    return j


def ipinfo(ip):
    tok = os.environ.get("IPINFO_TOKEN")
    status, j = get_json(f"https://ipinfo.io/{q(ip)}/json" + (f"?token={tok}" if tok else ""))
    if status != 200 or not j:
        raise RuntimeError(f"ipinfo HTTP {status}")
    j.pop("readme", None)
    return j


def shodan_internetdb(ip):
    status, j = get_json(f"https://internetdb.shodan.io/{q(ip)}")
    if status == 404:
        return {"note": "No data (host not seen by Shodan)"}
    if status != 200:
        raise RuntimeError(f"InternetDB HTTP {status}")
    return j


def rdap_ip(ip):
    status, j = get_json(f"https://rdap.org/ip/{q(ip)}", timeout=20)
    if status != 200 or not j:
        raise RuntimeError(f"RDAP HTTP {status}")
    ents = []
    for e in j.get("entities", []):
        fn = next((v[3] for v in (e.get("vcardArray") or [None, []])[1] if v and v[0] == "fn"), None)
        ents.append({"roles": e.get("roles"), "name": fn, "handle": e.get("handle")})
    return {"name": j.get("name"), "handle": j.get("handle"), "range": f"{j.get('startAddress')} - {j.get('endAddress')}",
            "country": j.get("country"), "type": j.get("type"), "entities": ents}


def ptr(ip):
    return reverse_dns(ip)


def greynoise(ip):
    status, j = get_json(f"https://api.greynoise.io/v3/community/{q(ip)}")
    if status == 404:
        return {"noise": False, "riot": False, "message": (j or {}).get("message")}
    if status != 200 or not j:
        raise RuntimeError(f"GreyNoise HTTP {status}")
    return j


def tor_exit(ip):
    global _tor_cache
    if _tor_cache is None:
        r = get("https://check.torproject.org/torbulkexitlist", timeout=20)
        if r.status != 200:
            raise RuntimeError(f"Tor list HTTP {r.status}")
        _tor_cache = set(r.text.split())
    return {"is_tor_exit": ip in _tor_cache}


def ripestat(ip):
    """Routing + abuse contact from RIPEstat (works for all regions, not just RIPE)."""
    _, pre = get_json(f"https://stat.ripe.net/data/prefix-overview/data.json?resource={q(ip)}", timeout=20)
    _, abuse = get_json(f"https://stat.ripe.net/data/abuse-contact-finder/data.json?resource={q(ip)}", timeout=20)
    p = (pre or {}).get("data", {})
    return {"prefix": p.get("resource"), "announced": p.get("announced"),
            "asns": [{"asn": a.get("asn"), "holder": a.get("holder")} for a in p.get("asns", [])],
            "abuse_contacts": (abuse or {}).get("data", {}).get("abuse_contacts", [])}


def otx_ip(ip):
    kind = "IPv6" if ":" in ip else "IPv4"
    hdrs = {"X-OTX-API-KEY": os.environ["OTX_API_KEY"]} if os.environ.get("OTX_API_KEY") else {}
    status, j = get_json(f"https://otx.alienvault.com/api/v1/indicators/{kind}/{q(ip)}/general", headers=hdrs, timeout=20)
    if status != 200 or not j:
        raise RuntimeError(f"OTX HTTP {status}")
    pulses = j.get("pulse_info", {}).get("pulses", [])
    return {"reputation": j.get("reputation"), "pulse_count": j.get("pulse_info", {}).get("count"),
            "threat_reports": [{"name": p.get("name"), "created": p.get("created"), "tags": p.get("tags", [])[:8]}
                               for p in pulses[:10]],
            "malware_families": sorted({m.get("display_name") for p in pulses for m in p.get("malware_families", [])
                                        if isinstance(m, dict)})}


def reverse_ip(ip):
    r = get(f"https://api.hackertarget.com/reverseiplookup/?q={q(ip)}", timeout=20)
    if r.status != 200 or "API count exceeded" in r.text or "error" in r.text.lower()[:50]:
        raise RuntimeError("HackerTarget rate limit / error")
    hosts = [h.strip() for h in r.text.splitlines() if h.strip() and "No DNS A records" not in h]
    return {"domain_count": len(hosts), "domains": hosts[:200]}


def abuseipdb(ip):
    key = os.environ.get("ABUSEIPDB_API_KEY")
    if not key:
        raise Skip("set ABUSEIPDB_API_KEY")
    _, j = get_json(f"https://api.abuseipdb.com/api/v2/check?ipAddress={q(ip)}&maxAgeInDays=90",
                    headers={"Key": key})
    return (j or {}).get("data")


def virustotal(ip):
    key = os.environ.get("VT_API_KEY")
    if not key:
        raise Skip("set VT_API_KEY")
    _, j = get_json(f"https://www.virustotal.com/api/v3/ip_addresses/{q(ip)}", headers={"x-apikey": key})
    a = (j or {}).get("data", {}).get("attributes", {})
    return {"last_analysis_stats": a.get("last_analysis_stats"), "reputation": a.get("reputation"),
            "as_owner": a.get("as_owner"), "tags": a.get("tags")}


def shodan_full(ip):
    key = os.environ.get("SHODAN_API_KEY")
    if not key:
        raise Skip("set SHODAN_API_KEY")
    _, j = get_json(f"https://api.shodan.io/shodan/host/{q(ip)}?key={key}")
    if not j:
        return None
    return {"org": j.get("org"), "os": j.get("os"), "ports": j.get("ports"),
            "services": [{"port": s.get("port"), "product": s.get("product"), "version": s.get("version")}
                         for s in j.get("data", [])]}


def investigate(ip, progress=None):
    addr = ipaddress.ip_address(ip.strip())
    ip = str(addr)
    if addr.is_private or addr.is_loopback or addr.is_reserved:
        return {"summary": {"note": "Private/reserved address — no public intelligence available."}, "sources": {}}
    checks = {
        "Geolocation (ip-api)": ip_api,
        "ipinfo.io": ipinfo,
        "Reverse DNS": ptr,
        "Ownership (RDAP)": rdap_ip,
        "Open ports & CVEs (Shodan InternetDB)": shodan_internetdb,
        "GreyNoise community": greynoise,
        "Tor exit node": tor_exit,
        "Routing & abuse contact (RIPEstat)": ripestat,
        "Threat intel (AlienVault OTX)": otx_ip,
        "Domains on this IP (HackerTarget)": reverse_ip,
        "AbuseIPDB": abuseipdb,
        "VirusTotal": virustotal,
        "Shodan (full)": shodan_full,
    }
    results = run_checks(checks, ip, on_done=progress)
    geo = results["Geolocation (ip-api)"].get("data") or {}
    idb = results["Open ports & CVEs (Shodan InternetDB)"].get("data") or {}
    summary = {
        "location": ", ".join(x for x in (geo.get("city"), geo.get("regionName"), geo.get("country")) if x) or None,
        "isp": geo.get("isp"), "asn": geo.get("as"),
        "hosting": geo.get("hosting"), "proxy_or_vpn": geo.get("proxy"),
        "open_ports": idb.get("ports"), "vulns": idb.get("vulns"),
        "hostnames": sorted(set((idb.get("hostnames") or []) + (results["Reverse DNS"].get("data") or []))),
        "tor_exit": (results["Tor exit node"].get("data") or {}).get("is_tor_exit"),
        "threat_reports": (results["Threat intel (AlienVault OTX)"].get("data") or {}).get("pulse_count"),
        "abuse_contact": (results["Routing & abuse contact (RIPEstat)"].get("data") or {}).get("abuse_contacts"),
        "domains_hosted": (results["Domains on this IP (HackerTarget)"].get("data") or {}).get("domain_count"),
    }
    return {"summary": summary, "sources": results}
