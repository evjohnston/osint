"""Render an investigation as terminal text, JSON, and a self-contained HTML page."""

import html
import json
import sys

_TTY = sys.stdout.isatty()


def c(code, s):
    return f"\033[{code}m{s}\033[0m" if _TTY else str(s)


ICON = {"ok": c("32", "✔"), "empty": c("90", "·"), "skipped": c("33", "–"), "error": c("31", "✘")}


def _fmt(v):
    if isinstance(v, list):
        return ", ".join(map(str, v[:15])) + (f" … (+{len(v) - 15})" if len(v) > 15 else "") if v else "—"
    return "—" if v in (None, "") else str(v)


def print_section(title, section):
    print()
    print(c("1;36", f"━━ {title} " + "━" * max(0, 60 - len(title))))
    for k, v in section["summary"].items():
        if k == "subdomains":
            continue
        print(f"  {c('1', k.replace('_', ' ').title() + ':'):<32} {_fmt(v)}")
    for name, res in section["sources"].items():
        line = f"  {ICON[res['status']]} {name}"
        if res["status"] in ("error", "skipped"):
            line += c("90", f"  ({res['error']})")
        print(line)


def print_username(section):
    print()
    print(c("1;36", "━━ Username footprint " + "━" * 40))
    for name, res in section["sources"].items():
        d = res.get("data") or {}
        if res["status"] == "ok" and d.get("found"):
            print(f"  {c('32', '✔')} {name:<28} {d['url']}")
            for k, v in (d.get("details") or {}).items():
                if v not in (None, "", [], 0):
                    print(c("90", f"      {k}: {_fmt(v)}"))
    inconclusive = section["summary"]["inconclusive"]
    print(c("90", f"  checked {section['summary']['checked']} sites; "
                  f"found on {len(section['summary']['found_on'])}"
                  + (f"; inconclusive: {', '.join(inconclusive)}" if inconclusive else "")))


def print_report(report):
    print()
    print(c("1", f"Target: {report['target']}  ({report['type']})"))
    for title, section in report["sections"].items():
        if title.startswith("Username"):
            print_username(section)
        else:
            print_section(title, section)
    if report.get("leads"):
        print()
        print(c("1;36", "━━ Leads (pivot on these) " + "━" * 36))
        for kind, items in report["leads"].items():
            print(f"  {c('1', kind.title() + ':')}")
            for it in items[:15]:
                n = len(it["sources"])
                print(f"    {it['value']:<44} " + c("90", f"{n} source{'s' if n > 1 else ''}: {', '.join(it['sources'][:3])}"))
            if len(items) > 15:
                print(c("90", f"    … {len(items) - 15} more in the HTML/JSON report"))
    if report["links"]:
        print()
        print(c("1;36", "━━ Manual pivots (open in browser) " + "━" * 26))
        for l in report["links"]:
            print(f"  • {l['name']:<26} {c('90', l['url'])}")


def to_json(report):
    return json.dumps(report, indent=2, default=str)


# --- HTML ---------------------------------------------------------------------

def _h(s):
    return html.escape(str(s))


def _val_html(v):
    if isinstance(v, str) and v.startswith(("http://", "https://")):
        return f'<a href="{_h(v)}" target="_blank" rel="noopener">{_h(v)}</a>'
    if isinstance(v, list):
        if not v:
            return '<span class="muted">—</span>'
        return "<ul>" + "".join(f"<li>{_val_html(x)}</li>" for x in v) + "</ul>"
    if isinstance(v, dict):
        if not v:
            return '<span class="muted">—</span>'
        return "<table class='kv'>" + "".join(
            f"<tr><th>{_h(k)}</th><td>{_val_html(x)}</td></tr>" for k, x in v.items()) + "</table>"
    if v in (None, ""):
        return '<span class="muted">—</span>'
    if v is True:
        return '<span class="pill yes">yes</span>'
    if v is False:
        return '<span class="pill no">no</span>'
    return _h(v)


def to_html(report):
    parts = []
    for title, section in report["sections"].items():
        summ = {k: v for k, v in section["summary"].items()}
        src = []
        for name, res in section["sources"].items():
            body = _val_html(res.get("data")) if res["status"] == "ok" else \
                f'<span class="muted">{_h(res.get("error", "no results"))}</span>'
            src.append(
                f'<details{" open" if res["status"] == "ok" and not title.startswith("Username") else ""}>'
                f'<summary><span class="dot {res["status"]}"></span>{_h(name)}'
                f'<span class="ms">{res["ms"]} ms</span></summary><div class="body">{body}</div></details>')
        parts.append(f'<section><h2>{_h(title)}</h2>{_val_html(summ)}'
                     f'<h3>Sources</h3>{"".join(src)}</section>')
    links = "".join(f'<li><a href="{_h(l["url"])}" target="_blank" rel="noopener">{_h(l["name"])}</a></li>'
                    for l in report["links"])
    leads = ""
    for kind, items in (report.get("leads") or {}).items():
        rows = "".join(f"<tr><td>{_val_html(it['value'])}</td><td class='muted'>{_h(', '.join(it['sources']))}</td></tr>"
                       for it in items)
        leads += f"<h3>{_h(kind)}</h3><table class='kv'>{rows}</table>"
    if leads:
        parts.insert(0, f"<section><h2>Leads</h2>{leads}</section>")
    return HTML_TEMPLATE.format(
        title=_h(report["target"]), kind=_h(report["type"]), when=_h(report["generated"]),
        sections="".join(parts),
        links=f'<section><h2>Manual pivots</h2><ul class="links">{links}</ul></section>' if links else "")


HTML_TEMPLATE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>OSINT report: {title}</title>
<style>
:root {{ --bg:#f7f7f5; --card:#fff; --ink:#1d1d1f; --muted:#7a7a80; --line:#e4e4e0; --accent:#2457d6;
         --ok:#1f9d55; --err:#d64545; --skip:#c99a06; }}
@media (prefers-color-scheme: dark) {{
  :root {{ --bg:#141416; --card:#1d1d20; --ink:#ececee; --muted:#8e8e96; --line:#2e2e33; --accent:#7aa2ff; }} }}
* {{ box-sizing:border-box }}
body {{ margin:0; background:var(--bg); color:var(--ink); font:15px/1.5 -apple-system,BlinkMacSystemFont,"Segoe UI",sans-serif; }}
main {{ max-width:960px; margin:0 auto; padding:32px 16px 64px; }}
header h1 {{ margin:0; font-size:26px; word-break:break-all }}
header p {{ margin:4px 0 0; color:var(--muted) }}
section {{ background:var(--card); border:1px solid var(--line); border-radius:12px; padding:20px; margin-top:20px; overflow-x:auto }}
h2 {{ margin:0 0 12px; font-size:18px }} h3 {{ font-size:13px; text-transform:uppercase; letter-spacing:.06em; color:var(--muted); margin:20px 0 8px }}
table.kv {{ border-collapse:collapse; width:100% }}
table.kv th {{ text-align:left; vertical-align:top; color:var(--muted); font-weight:500; padding:4px 12px 4px 0; width:200px; white-space:nowrap }}
table.kv td {{ padding:4px 0; word-break:break-word }}
table.kv table.kv th {{ width:auto }}
ul {{ margin:0; padding-left:18px }}
details {{ border-top:1px solid var(--line) }}
summary {{ cursor:pointer; padding:8px 0; display:flex; align-items:center; gap:8px }}
.ms {{ margin-left:auto; color:var(--muted); font-size:12px }}
.body {{ padding:0 0 12px 18px }}
.dot {{ width:9px; height:9px; border-radius:50%; background:var(--muted); flex:none }}
.dot.ok {{ background:var(--ok) }} .dot.error {{ background:var(--err) }} .dot.skipped {{ background:var(--skip) }}
.muted {{ color:var(--muted) }} a {{ color:var(--accent) }}
.pill {{ padding:1px 8px; border-radius:99px; font-size:12px }} .yes {{ background:#1f9d5522; color:var(--ok) }} .no {{ background:#7a7a8022; color:var(--muted) }}
ul.links {{ columns:2; padding-left:18px }} @media (max-width:600px) {{ ul.links {{ columns:1 }} table.kv th {{ width:auto; white-space:normal }} }}
</style></head><body><main>
<header><h1>{title}</h1><p>Type: {kind} · Generated {when} · osintkit</p></header>
{sections}
{links}
<p class="muted" style="margin-top:24px;font-size:13px">Results come from public sources and may be stale or incorrect. Verify before you rely on them.</p>
</main></body></html>
"""
