"""Email intelligence: deliverability, breaches, linked profiles."""

import hashlib
import os

from ..net import dns, get, get_json, q
from ..runner import Skip, run_checks

_disposable = None


def mail_server(email):
    domain = email.split("@", 1)[1]
    mx = dns(domain, "MX")
    spf = [t for t in dns(domain, "TXT") if t.lower().startswith("v=spf1")]
    dmarc = [t for t in dns(f"_dmarc.{domain}", "TXT") if t.lower().startswith("v=dmarc1")]
    provider = next((p for k, p in MX_PROVIDERS.items() if any(k in m.lower() for m in mx)), None)
    return {"accepts_mail": bool(mx), "mx": mx, "provider": provider,
            "spf": spf[0] if spf else None, "dmarc": dmarc[0] if dmarc else None}


MX_PROVIDERS = {
    "google.com": "Google Workspace / Gmail", "googlemail.com": "Google Workspace / Gmail",
    "outlook.com": "Microsoft 365 / Outlook", "protection.outlook": "Microsoft 365",
    "protonmail": "Proton Mail", "zoho": "Zoho Mail", "yahoodns": "Yahoo Mail", "icloud.com": "iCloud Mail",
    "mimecast": "Mimecast", "pphosted": "Proofpoint", "messagingengine": "Fastmail",
}


def disposable(email):
    global _disposable
    if _disposable is None:
        r = get("https://raw.githubusercontent.com/disposable-email-domains/disposable-email-domains/"
                "main/disposable_email_blocklist.conf", timeout=20)
        if r.status != 200:
            raise RuntimeError(f"blocklist HTTP {r.status}")
        _disposable = set(r.text.split())
    return {"disposable": email.split("@", 1)[1] in _disposable}


def gravatar(email):
    e = email.strip().lower().encode()
    sha = hashlib.sha256(e).hexdigest()
    md5 = hashlib.md5(e).hexdigest()  # noqa: S324 — Gravatar's legacy hash, not security use
    status, j = get_json(f"https://api.gravatar.com/v3/profiles/{sha}")
    avatar = get(f"https://gravatar.com/avatar/{md5}?d=404").status == 200
    if status == 200 and j:
        return {"has_profile": True, "has_avatar": avatar, "avatar_url": f"https://gravatar.com/avatar/{md5}?s=400",
                "display_name": j.get("display_name"), "location": j.get("location"),
                "profile_url": j.get("profile_url"), "job_title": j.get("job_title"),
                "company": j.get("company"), "description": j.get("description"),
                "verified_accounts": [{"service": a.get("service_label"), "url": a.get("url")}
                                      for a in j.get("verified_accounts", [])]}
    return {"has_profile": False, "has_avatar": avatar,
            "avatar_url": f"https://gravatar.com/avatar/{md5}?s=400" if avatar else None}


def xposedornot(email):
    status, j = get_json(f"https://api.xposedornot.com/v1/breach-analytics?email={q(email)}", timeout=25)
    if status == 404 or not j or j.get("Error") or not j.get("ExposedBreaches"):
        if status not in (200, 404) and not j:
            raise RuntimeError(f"XposedOrNot HTTP {status}")
        return {"breached": False, "breaches": []}
    details = j["ExposedBreaches"].get("breaches_details", [])
    pw = ((j.get("BreachMetrics") or {}).get("passwords_strength") or [{}])[0]
    return {
        "breached": bool(details),
        "breaches": [{"name": b.get("breach"), "year": b.get("xposed_date"), "domain": b.get("domain"),
                      "records": b.get("xposed_records"), "data_exposed": (b.get("xposed_data") or "").split(";"),
                      "password_risk": b.get("password_risk"), "industry": b.get("industry")} for b in details],
        "password_exposure": {"plaintext": pw.get("PlainText"), "easy_to_crack": pw.get("EasyToCrack"),
                              "strong_hash": pw.get("StrongHash"), "unknown": pw.get("Unknown")},
        "data_types_exposed": sorted({x for b in details for x in (b.get("xposed_data") or "").split(";") if x}),
        "pastes": (j.get("PastesSummary") or {}).get("cnt"),
    }


def hunter_verify(email):
    key = os.environ.get("HUNTER_API_KEY")
    if not key:
        raise Skip("set HUNTER_API_KEY (free tier at hunter.io)")
    _, j = get_json(f"https://api.hunter.io/v2/email-verifier?email={q(email)}&api_key={key}")
    d = (j or {}).get("data", {})
    return {k: d.get(k) for k in ("status", "result", "score", "smtp_check", "accept_all", "webmail", "sources")}


def hibp(email):
    key = os.environ.get("HIBP_API_KEY")
    if not key:
        raise Skip("set HIBP_API_KEY")
    status, j = get_json(f"https://haveibeenpwned.com/api/v3/breachedaccount/{q(email)}?truncateResponse=false",
                         headers={"hibp-api-key": key, "User-Agent": "osintkit"})
    if status == 404:
        return {"breached": False, "breaches": []}
    return {"breached": True, "breaches": [{"name": b["Name"], "date": b.get("BreachDate"),
                                             "data": b.get("DataClasses")} for b in (j or [])]}


def github_commits(email):
    hdrs = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        hdrs["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    status, j = get_json(f"https://api.github.com/search/commits?q=author-email:{q(email)}&per_page=10",
                         headers=hdrs)
    if status != 200 or j is None:
        raise RuntimeError(f"GitHub HTTP {status}")
    authors = {}
    for it in j.get("items", []):
        if it.get("author"):
            authors[it["author"]["login"]] = it["author"]["html_url"]
    return {"commit_count": j.get("total_count"), "github_accounts": authors,
            "names_used": sorted({it["commit"]["author"]["name"] for it in j.get("items", [])}),
            "repos": sorted({it["repository"]["full_name"] for it in j.get("items", [])})}


def investigate(email, progress=None):
    e = email.strip()
    checks = {
        "Mail server (MX/SPF/DMARC)": mail_server,
        "Disposable domain check": disposable,
        "Gravatar profile": gravatar,
        "Breaches: XposedOrNot": xposedornot,
        "Breaches: Have I Been Pwned": hibp,
        "Mailbox verification (Hunter.io)": hunter_verify,
        "GitHub commits by email": github_commits,
    }
    results = run_checks(checks, e, on_done=progress)
    breaches = set()
    for k in ("Breaches: XposedOrNot", "Breaches: Have I Been Pwned"):
        for b in (results[k].get("data") or {}).get("breaches", []):
            breaches.add(b["name"] if isinstance(b, dict) else b)
    grav = results["Gravatar profile"].get("data") or {}
    gh = results["GitHub commits by email"].get("data") or {}
    summary = {
        "deliverable_domain": (results["Mail server (MX/SPF/DMARC)"].get("data") or {}).get("accepts_mail"),
        "mail_provider": (results["Mail server (MX/SPF/DMARC)"].get("data") or {}).get("provider"),
        "disposable": (results["Disposable domain check"].get("data") or {}).get("disposable"),
        "breach_count": len(breaches),
        "breaches": sorted(breaches),
        "data_types_exposed": (results["Breaches: XposedOrNot"].get("data") or {}).get("data_types_exposed"),
        "gravatar_name": grav.get("display_name"),
        "linked_accounts": [a["url"] for a in grav.get("verified_accounts", [])] + list(gh.get("github_accounts", {}).values()),
        "username_guess": e.split("@")[0],
    }
    return {"summary": summary, "sources": results}
