#!/usr/bin/env python3
"""Local web UI for osintkit.

    python3 web.py            # opens http://127.0.0.1:8000
    python3 web.py --port 9000 --no-browser

Binds to 127.0.0.1 only: lookups run from this machine and the UI is not
meant to be exposed on a network.
"""

import argparse
import json
import os
import queue
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from osintkit.core import investigate, load_env, save_report
from osintkit.detect import TYPES, detect

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, "web")
REPORTS = os.path.join(ROOT, "reports")
TYPES_FILE = {".html": "text/html; charset=utf-8", ".json": "application/json", ".css": "text/css",
              ".js": "text/javascript", ".svg": "image/svg+xml"}


class Handler(BaseHTTPRequestHandler):
    server_version = "osintkit"

    def log_message(self, fmt, *args):  # quieter console
        if not self.path.startswith("/api/run"):
            return
        print(f"  {self.address_string()} {fmt % args}")

    # --- helpers ---
    def _send(self, code, body, ctype="application/json"):
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(data)

    def _file(self, base, name):
        path = os.path.realpath(os.path.join(base, name))
        if not path.startswith(os.path.realpath(base) + os.sep) or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        with open(path, "rb") as f:
            self._send(200, f.read(), TYPES_FILE.get(os.path.splitext(path)[1], "application/octet-stream"))

    # --- routes ---
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path in ("/", "/index.html"):
            return self._file(STATIC, "index.html")
        if url.path == "/api/run":
            return self._run(qs)
        if url.path == "/api/detect":
            return self._send(200, {"type": detect(qs.get("target", ""))})
        if url.path == "/api/history":
            return self._send(200, history())
        if url.path.startswith("/reports/"):
            return self._file(REPORTS, urllib.parse.unquote(url.path[len("/reports/"):]))
        return self._send(404, {"error": "not found"})

    def _run(self, qs):
        target = qs.get("target", "").strip()
        kind = qs.get("type") or None
        if not target or (kind and kind not in TYPES):
            return self._send(400, {"error": "missing target or bad type"})
        pivot = qs.get("pivot") in ("1", "true", "on")
        deep = qs.get("deep", "1") not in ("0", "false", "off")

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("Cache-Control", "no-store")
        self.send_header("Connection", "close")
        self.end_headers()

        events = queue.Queue()
        emit = lambda ev, **data: events.put((ev, data))  # noqa: E731

        def work():
            t0 = time.time()
            try:
                emit("start", target=target, type=kind or detect(target))
                rep = investigate(
                    target, kind, pivot=pivot, deep=deep,
                    on_section=lambda t: emit("section", title=t),
                    on_source=lambda t, n, r: emit("source", section=t, name=n, result=r),
                    on_section_done=lambda t, s: emit("section_done", title=t, section=s),
                )
                rep["elapsed_s"] = round(time.time() - t0, 1)
                base = os.path.basename(save_report(rep, REPORTS))
                emit("done", report=rep, files={"html": f"/reports/{base}.html", "json": f"/reports/{base}.json"})
            except Exception as e:  # noqa: BLE001
                emit("fail", error=f"{type(e).__name__}: {e}")
            events.put(None)

        threading.Thread(target=work, daemon=True).start()
        try:
            while True:
                try:
                    item = events.get(timeout=15)
                except queue.Empty:
                    self.wfile.write(b": keepalive\n\n")
                    self.wfile.flush()
                    continue
                if item is None:
                    break
                ev, data = item
                self.wfile.write(f"event: {ev}\ndata: {json.dumps(data, default=str)}\n\n".encode())
                self.wfile.flush()
        except (BrokenPipeError, ConnectionResetError):
            pass  # browser navigated away; the worker finishes and saves on its own


def history(limit=30):
    if not os.path.isdir(REPORTS):
        return []
    out = []
    for name in sorted((f for f in os.listdir(REPORTS) if f.endswith(".json")),
                       key=lambda f: os.path.getmtime(os.path.join(REPORTS, f)), reverse=True)[:limit]:
        try:
            with open(os.path.join(REPORTS, name)) as f:
                rep = json.load(f)
            out.append({"file": name, "target": rep.get("target"), "type": rep.get("type"),
                        "generated": rep.get("generated")})
        except (OSError, ValueError):
            continue
    return out


def main():
    load_env()
    ap = argparse.ArgumentParser(description="osintkit web UI")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    args = ap.parse_args()
    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{args.port}"
    print(f"osintkit UI running at {url}  (Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
