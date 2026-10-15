"""Pre-filled links to osintframework.com tools that need a browser, login, or captcha.

These can't be automated reliably (or their ToS forbid it), so the report
hands you one-click pivots with the target already filled in.
"""

from .net import q

LINKS = {
    "username": [
        ("WhatsMyName (600+ sites)", "https://whatsmyname.app/?q={t}"),
        ("Instagram", "https://www.instagram.com/{t}/"),
        ("X / Twitter", "https://x.com/{t}"),
        ("TikTok", "https://www.tiktok.com/@{t}"),
        ("Facebook", "https://www.facebook.com/{t}"),
        ("Reddit", "https://www.reddit.com/user/{t}"),
        ("YouTube", "https://www.youtube.com/@{t}"),
        ("Twitch", "https://www.twitch.tv/{t}"),
        ("Medium", "https://medium.com/@{t}"),
        ("PyPI", "https://pypi.org/user/{t}/"),
        ("Kaggle", "https://www.kaggle.com/{t}"),
        ("Threads", "https://www.threads.net/@{t}"),
        ("LinkedIn search", "https://www.linkedin.com/search/results/all/?keywords={t}"),
        ("Google exact match", "https://www.google.com/search?q=%22{t}%22"),
        ("IntelX", "https://intelx.io/?s={t}"),
    ],
    "email": [
        ("Epieos (Google/Holehe)", "https://epieos.com/?q={t}"),
        ("Have I Been Pwned", "https://haveibeenpwned.com/account/{t}"),
        ("Hunter.io verifier", "https://hunter.io/email-verifier/{t}"),
        ("IntelX", "https://intelx.io/?s={t}"),
        ("DeHashed", "https://dehashed.com/search?query={t}"),
        ("Google exact match", "https://www.google.com/search?q=%22{t}%22"),
        ("GitHub code search", "https://github.com/search?q=%22{t}%22&type=code"),
        ("Pastebin via Google", "https://www.google.com/search?q=site%3Apastebin.com+%22{t}%22"),
    ],
    "domain": [
        ("VirusTotal", "https://www.virustotal.com/gui/domain/{t}"),
        ("DNSDumpster", "https://dnsdumpster.com/"),
        ("SecurityTrails", "https://securitytrails.com/domain/{t}/dns"),
        ("ViewDNS reverse IP", "https://viewdns.info/reverseip/?host={t}&t=1"),
        ("BuiltWith", "https://builtwith.com/{t}"),
        ("Shodan", "https://www.shodan.io/search?query=hostname%3A{t}"),
        ("Censys", "https://search.censys.io/search?resource=hosts&q={t}"),
        ("urlscan.io", "https://urlscan.io/search/#domain%3A{t}"),
        ("crt.sh", "https://crt.sh/?q=%25.{t}"),
        ("Wayback Machine", "https://web.archive.org/web/*/{t}*"),
        ("Google dork: files", "https://www.google.com/search?q=site%3A{t}+filetype%3Apdf+OR+filetype%3Axlsx+OR+filetype%3Adocx"),
        ("Google dork: subdomains", "https://www.google.com/search?q=site%3A*.{t}+-www"),
        ("GitHub code search", "https://github.com/search?q=%22{t}%22&type=code"),
    ],
    "ip": [
        ("Shodan", "https://www.shodan.io/host/{t}"),
        ("Censys", "https://search.censys.io/hosts/{t}"),
        ("VirusTotal", "https://www.virustotal.com/gui/ip-address/{t}"),
        ("AbuseIPDB", "https://www.abuseipdb.com/check/{t}"),
        ("GreyNoise", "https://viz.greynoise.io/ip/{t}"),
        ("AlienVault OTX", "https://otx.alienvault.com/indicator/ip/{t}"),
        ("ViewDNS reverse IP", "https://viewdns.info/reverseip/?host={t}&t=1"),
        ("BGP.he.net", "https://bgp.he.net/ip/{t}"),
        ("Talos reputation", "https://talosintelligence.com/reputation_center/lookup?search={t}"),
    ],
    "phone": [
        ("Google exact match", "https://www.google.com/search?q=%22{t}%22"),
        ("Sync.me", "https://sync.me/search/?number={t}"),
        ("WhatsApp chat link", "https://wa.me/{digits}"),
        ("Telegram (if public)", "https://t.me/{t}"),
        ("NumLookup", "https://www.numlookup.com/"),
        ("SpyDialer", "https://www.spydialer.com/"),
    ],
}


def links_for(kind, target):
    digits = "".join(c for c in target if c.isdigit())
    return [{"name": n, "url": u.format(t=q(target), digits=digits)} for n, u in LINKS.get(kind, [])]
