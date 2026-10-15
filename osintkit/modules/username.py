"""Username enumeration across platforms (Sherlock / WhatsMyName style).

Each site uses the most reliable signal available — preferably a public JSON
API, otherwise HTTP status or a marker string in the page.
"""

import os
from collections import Counter

from ..net import get, get_json, q, request
from ..runner import run_checks
from . import wmn

# kind:
#   "status"  -> exists if HTTP 200, missing if 404/410
#   "json"    -> exists if fn(status, json) is truthy
#   "absent"  -> exists if HTTP 200 and `marker` NOT in body
#   "present" -> exists if HTTP 200 and `marker` IS in body
SITES = [
    # name, profile url, kind, check url (default=profile), extra
    ("GitHub", "https://github.com/{u}", "github", None, None),
    ("GitLab", "https://gitlab.com/{u}", "json", "https://gitlab.com/api/v4/users?username={u}",
     lambda s, j: s == 200 and j and {k: j[0].get(k) for k in ("name", "state", "web_url")}),
    ("Codeberg", "https://codeberg.org/{u}", "json", "https://codeberg.org/api/v1/users/{u}",
     lambda s, j: s == 200 and {k: j.get(k) for k in ("full_name", "location", "website", "created")}),
    ("Bitbucket", "https://bitbucket.org/{u}/", "status", "https://api.bitbucket.org/2.0/workspaces/{u}", None),
    ("Hacker News", "https://news.ycombinator.com/user?id={u}", "json",
     "https://hacker-news.firebaseio.com/v0/user/{u}.json",
     lambda s, j: s == 200 and j and {"karma": j.get("karma"), "created": j.get("created"), "about": j.get("about")}),
    ("Keybase", "https://keybase.io/{u}", "json", "https://keybase.io/_/api/1.0/user/lookup.json?usernames={u}",
     lambda s, j: s == 200 and j and (j.get("them") or [None])[0] and
     {"full_name": j["them"][0].get("profile", {}).get("full_name"),
      "proofs": [p.get("nametag") + "@" + p.get("proof_type") for p in
                 j["them"][0].get("proofs_summary", {}).get("all", [])]}),
    ("Dev.to", "https://dev.to/{u}", "json", "https://dev.to/api/users/by_username?url={u}",
     lambda s, j: s == 200 and j and {k: j.get(k) for k in ("name", "location", "summary", "joined_at", "github_username", "twitter_username")}),
    ("Docker Hub", "https://hub.docker.com/u/{u}", "json", "https://hub.docker.com/v2/users/{u}/",
     lambda s, j: s == 200 and j and {k: j.get(k) for k in ("full_name", "location", "company", "date_joined")}),
    ("Hugging Face", "https://huggingface.co/{u}", "status", "https://huggingface.co/api/users/{u}/overview", None),
    ("Chess.com", "https://www.chess.com/member/{u}", "json", "https://api.chess.com/pub/player/{u}",
     lambda s, j: s == 200 and j and {k: j.get(k) for k in ("name", "country", "joined", "last_online")}),
    ("Lichess", "https://lichess.org/@/{u}", "json", "https://lichess.org/api/user/{u}",
     lambda s, j: s == 200 and j and not j.get("disabled") and {"created": j.get("createdAt"), "profile": j.get("profile")}),
    ("Mastodon (mastodon.social)", "https://mastodon.social/@{u}", "json",
     "https://mastodon.social/api/v1/accounts/lookup?acct={u}",
     lambda s, j: s == 200 and j and {k: j.get(k) for k in ("display_name", "created_at", "followers_count", "url")}),
    ("Bluesky", "https://bsky.app/profile/{u}.bsky.social", "json",
     "https://public.api.bsky.app/xrpc/app.bsky.actor.getProfile?actor={u}.bsky.social",
     lambda s, j: s == 200 and j and {k: j.get(k) for k in ("displayName", "description", "followersCount", "createdAt")}),
    ("Telegram", "https://t.me/{u}", "present", None, 'class="tgme_page_title"'),
    ("Steam", "https://steamcommunity.com/id/{u}", "absent", None, "The specified profile could not be found"),
    ("Minecraft", "https://namemc.com/profile/{u}", "json", "https://api.mojang.com/users/profiles/minecraft/{u}",
     lambda s, j: s == 200 and j and {"uuid": j.get("id"), "name": j.get("name")}),
    ("Roblox", "https://www.roblox.com/search/users?keyword={u}", "roblox", None, None),
    ("Duolingo", "https://www.duolingo.com/profile/{u}", "json",
     "https://www.duolingo.com/2017-06-30/users?username={u}&fields=users%7Bname,creationDate,streak%7D",
     lambda s, j: s == 200 and j and j.get("users") and j["users"][0]),
    ("Wikipedia", "https://en.wikipedia.org/wiki/User:{u}", "json",
     "https://en.wikipedia.org/w/api.php?action=query&list=users&ususers={u}&usprop=editcount|registration&format=json",
     lambda s, j: s == 200 and j and "missing" not in j["query"]["users"][0] and "invalid" not in j["query"]["users"][0]
     and {k: j["query"]["users"][0].get(k) for k in ("editcount", "registration")}),
    ("Gravatar", "https://gravatar.com/{u}", "json", "https://en.gravatar.com/{u}.json",
     lambda s, j: s == 200 and j and j.get("entry") and
     {"name": j["entry"][0].get("displayName"), "urls": [x.get("value") for x in j["entry"][0].get("urls", [])]}),
    ("Replit", "https://replit.com/@{u}", "status", None, None),
    ("SoundCloud", "https://soundcloud.com/{u}", "status", None, None),
    ("Vimeo", "https://vimeo.com/{u}", "status", None, None),
    ("Dribbble", "https://dribbble.com/{u}", "status", None, None),
    ("Pastebin", "https://pastebin.com/u/{u}", "status", None, None),
    ("Linktree", "https://linktr.ee/{u}", "status", None, None),
    ("About.me", "https://about.me/{u}", "status", None, None),
    ("Flickr", "https://www.flickr.com/people/{u}", "status", None, None),
    ("Patreon", "https://www.patreon.com/{u}", "status", None, None),
    ("npm", "https://www.npmjs.com/~{u}", "json",
     "https://registry.npmjs.org/-/v1/search?text=maintainer:{u}&size=5",
     lambda s, j: s == 200 and j and j.get("total") and
     {"packages": j.get("total"), "examples": [o["package"]["name"] for o in j["objects"]]}),
]


# Some APIs reject browser-looking UAs but accept honest tool UAs.
SITE_HEADERS = {"Codeberg": {"User-Agent": "osintkit/1.0"}}

# Bot-protection interstitials — a 200 with one of these is not a real answer.
CHALLENGE_MARKERS = ("Client Challenge", "Just a moment...", "cf-chl", "challenge-platform", "recaptcha/challengepage")


def _challenged(r):
    return any(m in r.text[:20000] for m in CHALLENGE_MARKERS)


def _github(u):
    """Profile plus the identity leaks GitHub exposes: commit emails/names, keys, orgs."""
    hdrs = {"Accept": "application/vnd.github+json"}
    if os.environ.get("GITHUB_TOKEN"):
        hdrs["Authorization"] = f"Bearer {os.environ['GITHUB_TOKEN']}"
    status, j = get_json(f"https://api.github.com/users/{q(u)}", headers=hdrs)
    if status == 404:
        return {"found": False}
    if status != 200 or not j:
        return {"found": None, "http": status, "note": "rate-limited? set GITHUB_TOKEN" if status == 403 else None}
    details = {k: j.get(k) for k in ("name", "company", "blog", "location", "email", "bio", "twitter_username",
                                     "public_repos", "followers", "created_at")}
    _, repos = get_json(f"https://api.github.com/users/{q(u)}/repos?type=owner&sort=pushed&per_page=100", headers=hdrs)
    own = [r for r in (repos or []) if isinstance(r, dict) and not r.get("fork")]
    details["top_languages"] = [l for l, _ in Counter(r["language"] for r in own if r.get("language")).most_common(5)]
    details["top_repos"] = [r["name"] for r in sorted(own, key=lambda r: -r.get("stargazers_count", 0))[:5]]
    emails, names = Counter(), Counter()
    for r in own[:3]:  # authored commits in the most recently pushed repos
        _, commits = get_json(f"https://api.github.com/repos/{q(u)}/{q(r['name'])}/commits?author={q(u)}&per_page=30",
                              headers=hdrs)
        for c in commits if isinstance(commits, list) else []:
            a = c.get("commit", {}).get("author", {})
            if a.get("email") and "noreply" not in a["email"]:
                emails[a["email"]] += 1
            if a.get("name"):
                names[a["name"]] += 1
    details["commit_emails"] = [e for e, _ in emails.most_common()]
    details["commit_names"] = [n for n, _ in names.most_common()]
    _, orgs = get_json(f"https://api.github.com/users/{q(u)}/orgs", headers=hdrs)
    details["orgs"] = [o["login"] for o in orgs or [] if isinstance(o, dict)]
    _, keys = get_json(f"https://api.github.com/users/{q(u)}/keys", headers=hdrs)
    _, gpg = get_json(f"https://api.github.com/users/{q(u)}/gpg_keys", headers=hdrs)
    details["ssh_keys"] = len(keys) if isinstance(keys, list) else None
    details["gpg_key_emails"] = sorted({e["email"] for k in (gpg if isinstance(gpg, list) else [])
                                         for e in k.get("emails", []) if e.get("email")})
    _, social = get_json(f"https://api.github.com/users/{q(u)}/social_accounts", headers=hdrs)
    details["social_accounts"] = [s["url"] for s in social or [] if isinstance(s, dict)]
    return {"found": True, "url": f"https://github.com/{u}", "details": details}


def _check_site(site, u):
    name, profile, kind, check, extra = site
    if kind == "github":
        return _github(u)
    profile_url = profile.format(u=u)
    url = (check or profile).format(u=q(u))

    if kind == "roblox":
        r = request("https://users.roblox.com/v1/usernames/users", method="POST",
                    data={"usernames": [u], "excludeBannedUsers": False})
        data = r.json().get("data") if r.ok else None
        if data:
            return {"found": True, "url": f"https://www.roblox.com/users/{data[0]['id']}/profile",
                    "details": {"displayName": data[0].get("displayName"), "id": data[0].get("id")}}
        return {"found": False if r.ok else None, "http": r.status}

    headers = SITE_HEADERS.get(name, {})
    if kind == "json":
        status, j = get_json(url, headers=headers)
        try:
            info = extra(status, j)
        except Exception:
            info = None
        if info:
            return {"found": True, "url": profile_url, "details": info if isinstance(info, dict) else None}
        return {"found": False if status in (200, 404, 400, 410) or j is not None else None, "http": status}

    r = get(url, headers=headers)
    if r.status == 200 and _challenged(r):
        return {"found": None, "http": r.status, "note": "bot challenge page"}
    if kind == "status":
        if r.status == 200:
            return {"found": True, "url": profile_url}
        return {"found": False if r.status in (404, 410) else None, "http": r.status}
    if kind == "absent":
        return {"found": r.status == 200 and extra not in r.text, "url": profile_url} if r.status in (200, 404) \
            else {"found": None, "http": r.status}
    if kind == "present":
        return {"found": r.status == 200 and extra in r.text, "url": profile_url} if r.status in (200, 404) \
            else {"found": None, "http": r.status}
    raise ValueError(kind)


def _control_check(results, wmn_sites):
    """Re-test each WhatsMyName hit with a random username. A hit is kept only if
    the site clearly says the random name does NOT exist; sites that 'find' it,
    or that can't answer (rate limits, fuzzy search pages), are downgraded."""
    import secrets
    from concurrent.futures import ThreadPoolExecutor

    control = "zq" + secrets.token_hex(6)
    hits = [n for n, r in results.items()
            if n in wmn_sites and r["status"] == "ok" and r["data"].get("found")]

    def test(name):
        for _ in range(2):
            try:
                found = wmn.check(wmn_sites[name], control).get("found")
            except Exception:
                found = None
            if found is not None:
                return name, found
        return name, None

    with ThreadPoolExecutor(max_workers=64) as pool:
        for name, ctrl in pool.map(test, hits):
            if ctrl is not False:
                note = "site reports any username as existing" if ctrl else "could not verify against a control name"
                results[name]["data"].update(found=None, note=note)


def investigate(username, progress=None, deep=True):
    u = username.strip().lstrip("@")
    checks = {site[0]: (lambda _t, s=site: _check_site(s, u)) for site in SITES}
    wmn_sites = {}
    if deep:  # add WhatsMyName sites we don't already cover with a better check
        have = {n.lower().split(" (")[0] for n in checks}
        try:
            for site in wmn.load_sites():
                if site["name"].lower() not in have and site["name"] not in checks:
                    wmn_sites[site["name"]] = site
                    checks[site["name"]] = lambda _t, s=site: wmn.check(s, u)
        except Exception as e:  # noqa: BLE001
            checks["WhatsMyName dataset"] = lambda _t, e=e: (_ for _ in ()).throw(e)
    results = run_checks(checks, u, workers=128 if deep else 24, on_done=progress)
    if deep:
        _control_check(results, wmn_sites)
    found = {k: v["data"] for k, v in results.items() if v["status"] == "ok" and v["data"].get("found")}
    unknown = [k for k, v in results.items()
               if v["status"] == "error" or (v["status"] == "ok" and v["data"].get("found") is None)]
    summary = {
        "found_on": sorted(found),
        "checked": len(checks),
        "inconclusive": sorted(unknown),
    }
    return {"summary": summary, "sources": results}
