"""Shared investigation pipeline used by both the CLI and the web UI."""

import os
import re
import urllib.parse
from datetime import datetime, timezone

from . import __version__, report
from .detect import detect
from .links import links_for
from .modules import domain, email, ip, phone, username


def load_env(path=None):
    """Read KEY=VALUE lines from .env so API keys don't need exporting."""
    path = path or os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), ".env")
    if not os.path.exists(path):
        return
    for line in open(path):
        line = line.strip()
        if line and not line.startswith("#") and "=" in line:
            k, v = line.split("=", 1)
            v = re.split(r"\s+#", v, maxsplit=1)[0]  # allow trailing comments
            os.environ.setdefault(k.strip(), v.strip().strip("'\""))


def investigate(target, kind=None, pivot=False, deep=True, on_section=None, on_source=None, on_section_done=None):
    """Run every relevant module for `target`.

    on_section(title)                  — a module is starting
    on_source(title, name, result)     — a source finished (result None = queued)
    on_section_done(title, section)    — a module finished; section has summary + sources
    deep=False skips the 600-site WhatsMyName username scan (much faster).
    """
    target = target.strip()
    kind = kind or detect(target)
    sections = {}

    def run(title, fn, value):
        if on_section:
            on_section(title)
        cb = (lambda name, res: on_source(title, name, res)) if on_source else None
        extra = {"deep": deep} if fn is username.investigate else {}
        sections[title] = fn(value, progress=cb, **extra)
        if on_section_done:
            on_section_done(title, sections[title])

    if kind == "url":
        host = urllib.parse.urlparse(target).hostname or ""
        kind, target = ("ip", host) if detect(host) == "ip" else ("domain", host)

    if kind == "username":
        run("Username footprint", username.investigate, target)
    elif kind == "email":
        run("Email", email.investigate, target)
        if pivot:
            local, dom = target.split("@", 1)
            run(f"Domain: {dom}", domain.investigate, dom)
            run(f"Username footprint: {local}", username.investigate, re.sub(r"\+.*$", "", local))
    elif kind == "domain":
        run("Domain", domain.investigate, target)
        ips = sections["Domain"]["summary"]["ips"]
        first_ip = next((x for x in ips if ":" not in x), ips[0] if ips else None)
        if pivot and first_ip:
            run(f"IP: {first_ip}", ip.investigate, first_ip)
    elif kind == "ip":
        run("IP address", ip.investigate, target)
    elif kind == "phone":
        run("Phone", phone.investigate, target)

    rep = {
        "target": target,
        "type": kind,
        "generated": datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC"),
        "tool": f"osintkit {__version__}",
        "sections": sections,
        "links": links_for(kind, target),
    }
    rep["leads"] = extract_leads(rep)
    return rep


# --- lead extraction ------------------------------------------------------------
# Walks every source's data and pulls out identifiers worth pivoting on, noting
# which sources reported each one (more sources = more confidence).

EMAIL_RE = re.compile(r"[A-Za-z0-9._%+-]+@[A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)*\.[A-Za-z]{2,}")
NAME_KEYS = {"name", "full_name", "display_name", "displayName", "fullname", "realname", "commit_names", "names_used"}
LOC_KEYS = {"location", "country", "city"}
USER_KEYS = {"twitter_username", "github_username", "login", "username"}
URL_KEYS = {"url", "blog", "website", "profile_url", "web_url", "html_url", "social_accounts", "social_links",
            "linked_accounts", "urls", "github_accounts"}
SKIP_SOURCES = {"urlscan.io history", "Wayback Machine", "Subdomains: crt.sh", "Subdomains: CertSpotter",
                "Hosts: HackerTarget", "Live subdomains (DNS)", "Passive DNS (AlienVault OTX)", "TLS certificate",
                "DNS records", "Domains on this IP (HackerTarget)", "Threat intel (AlienVault OTX)"}
PROFILE_HOSTS = re.compile(r"^https?://(?:www\.)?(twitter\.com|x\.com|github\.com|instagram\.com|tiktok\.com|"
                           r"facebook\.com|youtube\.com|threads\.net|t\.me|reddit\.com/user|medium\.com)/@?([A-Za-z0-9_.-]{2,40})/?$")
NOT_EMAIL_TLDS = (".png", ".jpg", ".jpeg", ".gif", ".svg", ".webp", ".css", ".js")


def extract_leads(rep):
    found = {"emails": {}, "usernames": {}, "names": {}, "locations": {}, "profiles": {}}
    me = rep["target"].lower()

    def add(kind, val, src):
        val = str(val).strip()
        if val and len(val) <= 200 and val.lower() != me:
            found[kind].setdefault(val, set()).add(src)

    def walk(v, key, src):
        if isinstance(v, dict):
            for k, x in v.items():
                walk(x, k, src)
        elif isinstance(v, list):
            for x in v:
                walk(x, key, src)
        elif isinstance(v, str):
            for e in EMAIL_RE.findall(v):
                if "noreply" not in e and not e.lower().endswith(NOT_EMAIL_TLDS):
                    add("emails", e.lower(), src)
            if key in NAME_KEYS and not EMAIL_RE.fullmatch(v) and not v.startswith("http"):
                if not src.startswith("Breaches"):  # breach records have "name" = breach name
                    add("names", v, src)
            elif key in LOC_KEYS:
                add("locations", v.rstrip("/").rsplit("/", 1)[-1] if v.startswith("http") else v, src)
            elif key in USER_KEYS:
                add("usernames", v.lstrip("@"), src)
            elif key in URL_KEYS and v.startswith("http") and "/api" not in v and "avatar" not in v:
                add("profiles", v, src)
                m = PROFILE_HOSTS.match(v)
                if m:
                    add("usernames", m.group(2), src)

    for title, sec in rep["sections"].items():
        for name, res in sec["sources"].items():
            if res["status"] != "ok" or name in SKIP_SOURCES:
                continue
            data = res["data"]
            if title.startswith("Username"):  # profile hits are already listed; mine their details
                data = data.get("details") if isinstance(data, dict) else None
            if data:
                walk(data, None, name)

    return {kind: [{"value": v, "sources": sorted(srcs)}
                   for v, srcs in sorted(vals.items(), key=lambda kv: (-len(kv[1]), kv[0].lower()))]
            for kind, vals in found.items() if vals}


def save_report(rep, out_dir="reports"):
    """Write <slug>_<timestamp>.json/.html and return the base path (no extension)."""
    os.makedirs(out_dir, exist_ok=True)
    slug = re.sub(r"[^A-Za-z0-9._-]+", "_", rep["target"])[:60]
    base = os.path.join(out_dir, f"{slug}_{datetime.now().strftime('%Y%m%d-%H%M%S')}")
    with open(base + ".json", "w") as f:
        f.write(report.to_json(rep))
    with open(base + ".html", "w") as f:
        f.write(report.to_html(rep))
    return base
