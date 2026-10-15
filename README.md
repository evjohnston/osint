# osintkit

An all-in-one OSINT lookup tool based on the categories at [osintframework.com](https://osintframework.com/).
Give it a username, email, domain, URL, IP, or phone number. It detects the type, queries every
relevant free source in parallel, and writes one combined report to the terminal, JSON, and HTML.

It runs on the Python standard library alone. `phonenumbers` is optional and enables phone lookups.

## Quick start

```bash
python3 osint.py torvalds                    # username across ~30 platforms
python3 osint.py someone@example.com -p      # email, then pivot to its domain and username
python3 osint.py example.com -p              # domain, then pivot to its main IP
python3 osint.py https://example.com/page    # URL → treated as its host
python3 osint.py 8.8.8.8                     # IP address
python3 osint.py "+1 650 253 0000"           # phone (needs: pip install phonenumbers)
```

Options: `-t TYPE` forces the target type, `-p/--pivot` follows leads, `--json` prints JSON to stdout,
`-o DIR` sets the report folder (default `reports/`), `--no-save` skips writing files, and `-q` hides progress.

To enable phone lookups:

```bash
python3 -m venv .venv && .venv/bin/pip install -r requirements.txt
.venv/bin/python osint.py "+44 20 7946 0000"
```

## Web UI

```bash
python3 web.py            # opens http://127.0.0.1:8000 in your browser
.venv/bin/python web.py   # same, with phone lookups enabled
```

Type a target, press **Investigate**, and watch each source report back live. Finished runs are
saved to `reports/` and listed under **Recent reports**. You can bookmark a search such as
`http://127.0.0.1:8000/?q=example.com&pivot=1`. The server only listens on localhost.
Use `--port` to change the port and `--no-browser` to stop it opening a tab.

## What it checks

| Target | Automated sources |
|---|---|
| **Username** | ~700 sites: the full [WhatsMyName](https://github.com/WebBreacher/WhatsMyName) dataset (cached for a week in `~/.cache/osintkit`), plus higher-precision API checks for GitHub (deep profile with commit emails and names, orgs, SSH/GPG keys, languages, social accounts), GitLab, Codeberg, Bitbucket, Hacker News, Keybase (with linked proofs), Dev.to, Docker Hub, npm, Hugging Face, Chess.com, Lichess, Mastodon, Bluesky, Telegram, Steam, Minecraft, Roblox, Duolingo, Wikipedia, Gravatar, Replit, SoundCloud, Vimeo, Dribbble, Pastebin, Linktree, About.me, Flickr, Patreon |
| **Email** | MX / SPF / DMARC and mail provider, disposable-domain list, Gravatar profile and verified accounts, XposedOrNot breaches with per-breach details (year, records, data exposed, password risk), Have I Been Pwned *(key)*, Hunter mailbox verification *(key)*, GitHub commits authored by the address |
| **Domain** | RDAP WHOIS, DNS (A, AAAA, MX, NS, TXT, CNAME, SOA, CAA), subdomains from crt.sh, CertSpotter, and HackerTarget, Wayback Machine first and last capture, urlscan.io history, web fingerprint (title, server, tech stack, security headers, emails on page), robots.txt and security.txt, TLS certificate (issuer, validity, SANs), social links, phone numbers and analytics IDs on the homepage, live-subdomain resolution, OTX passive DNS *(key)*, Hunter staff emails *(key)*, VirusTotal *(key)* |
| **IP** | ip-api geolocation (plus proxy and hosting flags), ipinfo, reverse DNS, RDAP ownership, Shodan InternetDB (open ports and CVEs), GreyNoise, Tor exit list, RIPEstat routing and abuse contact, AlienVault OTX threat reports, domains hosted on the IP (HackerTarget), AbuseIPDB *(key)*, VirusTotal *(key)*, full Shodan *(key)* |
| **Phone** | libphonenumber (validity, region, original carrier, line type, time zones), Numverify *(key)* |

Every report also has a **Leads** section. It collects every email, username, real name, location
and linked profile found by any source, and shows which sources agree on each one. In the web UI,
clicking an email or username lead starts a new investigation.

Use `--quick` (CLI) or untick **Deep username scan** (web) to skip the WhatsMyName sites when you
want results in a few seconds rather than about a minute.

Every report also includes **manual pivots**: pre-filled links to osintframework tools that need a
browser, a login, or a captcha, such as Instagram, X, TikTok, Epieos, IntelX, DeHashed, Censys,
SecurityTrails, and Google dorks.

## API keys (optional)

Copy `.env.example` to `.env` and fill in any keys you have. A source with no key shows as *skipped*.

## How detection works

Username checks favor each site's public JSON API, then fall back to HTTP status codes or a marker
string in the page. A site that serves a bot-challenge page or blocks the request is marked
**inconclusive**, not "not found", so missing accounts aren't reported with false confidence.
The checks were calibrated against a real account and a random string, and the random string
returned zero false positives.

## Adding a source

* **New username site:** add a tuple to `SITES` in `osintkit/modules/username.py`.
* **New check for another type:** write a function `fn(target) -> dict` in that module and add it to
  the `checks` dict in `investigate()`. Raise `Skip("reason")` when a key is missing. Exceptions are
  caught and shown as errors, so one broken source never stops the run.
* **New manual pivot:** add to `LINKS` in `osintkit/links.py`.

## Responsible use

Use this tool only on targets you're authorized to investigate: yourself, your own organization,
authorized pentest or red-team scopes, CTFs, or legitimate research and journalism. Follow each
source's terms of service and the privacy laws that apply to you (GDPR, CCPA, and others).
Results come from public data and can be stale or wrong, so verify them before you act.
