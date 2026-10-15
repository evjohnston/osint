#!/usr/bin/env python3
"""Web UI for osintkit, protected by a single-user login.

    python3 web.py --set-password   # first time: choose a username and password
    python3 web.py                  # opens http://127.0.0.1:8000
    python3 web.py --port 9000 --no-browser

Binds to 127.0.0.1 only. To reach it from elsewhere, publish it with
Cloudflare Tunnel (see scripts/setup-tunnel.sh) rather than opening a port.
"""

import argparse
import getpass
import json
import os
import queue
import secrets
import sys
import threading
import time
import urllib.parse
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

from osintkit import auth
from osintkit.core import investigate, load_env, save_report
from osintkit.detect import TYPES, detect

ROOT = os.path.dirname(os.path.abspath(__file__))
STATIC = os.path.join(ROOT, "web")
REPORTS = os.path.join(ROOT, "reports")
ENV_FILE = os.path.join(ROOT, ".env")
TYPES_FILE = {".html": "text/html; charset=utf-8", ".json": "application/json", ".css": "text/css",
              ".js": "text/javascript", ".svg": "image/svg+xml"}
SECURITY_HEADERS = {
    "X-Frame-Options": "DENY",
    "X-Content-Type-Options": "nosniff",
    "Referrer-Policy": "no-referrer",
    "Cache-Control": "no-store",
    "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; "
                               "img-src 'self' https: data:; frame-ancestors 'none'; form-action 'self'",
}
PUBLIC_PATHS = {"/login", "/favicon.ico"}
limiter = auth.LoginLimiter()


class Handler(BaseHTTPRequestHandler):
    server_version = "osintkit"

    def log_message(self, fmt, *args):  # quieter console: only log runs and logins
        if self.path.startswith(("/api/run", "/login")):
            print(f"  {self.client_ip()} {fmt % args}")

    # --- helpers ---
    def client_ip(self):
        # cloudflared connects from localhost and passes the visitor's IP in this header
        return self.headers.get("CF-Connecting-IP") or self.client_address[0]

    def is_https(self):
        return self.headers.get("X-Forwarded-Proto") == "https" or '"https"' in self.headers.get("CF-Visitor", "")

    def end_headers(self):
        for k, v in SECURITY_HEADERS.items():
            self.send_header(k, v)
        super().end_headers()

    def _send(self, code, body, ctype="application/json", headers=None):
        data = body if isinstance(body, bytes) else (json.dumps(body) if not isinstance(body, str) else body).encode()
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(data)))
        for k, v in (headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        self.wfile.write(data)

    def _redirect(self, location, cookie=None):
        self.send_response(303)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()

    def _file(self, base, name):
        path = os.path.realpath(os.path.join(base, name))
        if not path.startswith(os.path.realpath(base) + os.sep) or not os.path.isfile(path):
            return self._send(404, {"error": "not found"})
        with open(path, "rb") as f:
            self._send(200, f.read(), TYPES_FILE.get(os.path.splitext(path)[1], "application/octet-stream"))

    def _cookie(self, value, max_age):
        flags = f"; Path=/; HttpOnly; SameSite=Strict; Max-Age={max_age}" + ("; Secure" if self.is_https() else "")
        return f"{auth.COOKIE}={value}{flags}"

    def user(self):
        for part in self.headers.get("Cookie", "").split(";"):
            k, _, v = part.strip().partition("=")
            if k == auth.COOKIE:
                return auth.read_session(v)
        return None

    # --- routes ---
    def do_GET(self):
        url = urllib.parse.urlparse(self.path)
        qs = {k: v[0] for k, v in urllib.parse.parse_qs(url.query).items()}
        if url.path == "/login":
            return self._redirect("/") if self.user() else self._file(STATIC, "login.html")
        if url.path == "/favicon.ico":
            return self._send(204, b"")
        if not self.user():
            if url.path.startswith(("/api/", "/reports/")):
                return self._send(401, {"error": "login required"})
            nxt = urllib.parse.quote(self.path, safe="")
            return self._redirect(f"/login?next={nxt}" if self.path not in ("/", "") else "/login")

        if url.path in ("/", "/index.html"):
            return self._file(STATIC, "index.html")
        if url.path == "/api/run":
            return self._run(qs)
        if url.path == "/api/detect":
            return self._send(200, {"type": detect(qs.get("target", ""))})
        if url.path == "/api/history":
            return self._send(200, history())
        if url.path == "/api/me":
            return self._send(200, {"user": self.user()})
        if url.path.startswith("/reports/"):
            return self._file(REPORTS, urllib.parse.unquote(url.path[len("/reports/"):]))
        return self._send(404, {"error": "not found"})

    def do_POST(self):
        path = urllib.parse.urlparse(self.path).path
        length = int(self.headers.get("Content-Length") or 0)
        if length > 4096:
            return self._send(413, {"error": "too large"})
        form = {k: v[0] for k, v in urllib.parse.parse_qs(self.rfile.read(length).decode("utf-8", "replace")).items()}

        if path == "/logout":
            return self._redirect("/login?out=1", cookie=self._cookie("", 0))

        if path == "/login":
            ip = self.client_ip()
            nxt = form.get("next", "/")
            if not nxt.startswith("/") or nxt.startswith("//"):
                nxt = "/"  # no open redirects
            if limiter.blocked(ip):
                print(f"  login blocked (rate limit) from {ip}")
                return self._redirect("/login?error=locked")
            if auth.check_credentials(form.get("username", ""), form.get("password", "")):
                limiter.reset(ip)
                print(f"  login ok from {ip}")
                return self._redirect(nxt, cookie=self._cookie(auth.make_session(os.environ["OSINT_USER"]),
                                                               auth.SESSION_TTL))
            limiter.fail(ip)
            print(f"  login FAILED from {ip}")
            time.sleep(1)  # slow down guessing
            q = urllib.parse.urlencode({"error": "1", **({"next": nxt} if nxt != "/" else {})})
            return self._redirect(f"/login?{q}")

        return self._send(404, {"error": "not found"})

    def _run(self, qs):
        target = qs.get("target", "").strip()
        kind = qs.get("type") or None
        if not target or len(target) > 300 or (kind and kind not in TYPES):
            return self._send(400, {"error": "missing target or bad type"})
        pivot = qs.get("pivot") in ("1", "true", "on")
        deep = qs.get("deep", "1") not in ("0", "false", "off")

        self.send_response(200)
        self.send_header("Content-Type", "text/event-stream")
        self.send_header("X-Accel-Buffering", "no")
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


def set_password():
    print("Set the osintkit web login (stored as a salted hash in .env).")
    user = input("Username: ").strip()
    if not user:
        sys.exit("Username can't be empty.")
    while True:
        pw = getpass.getpass("Password (12+ characters): ")
        if len(pw) < 12:
            print("Too short. Use at least 12 characters; a passphrase works well.")
            continue
        if getpass.getpass("Repeat password: ") != pw:
            print("Passwords didn't match, try again.")
            continue
        break
    auth.write_env(ENV_FILE, {
        "OSINT_USER": user,
        "OSINT_PASSWORD_HASH": auth.hash_password(pw),
        "OSINT_SECRET": secrets.token_urlsafe(32),  # new secret signs out every existing session
    })
    print(f"Saved to {ENV_FILE}. Restart web.py if it's running.")


def main():
    ap = argparse.ArgumentParser(description="osintkit web UI")
    ap.add_argument("--port", type=int, default=8000)
    ap.add_argument("--no-browser", action="store_true")
    ap.add_argument("--set-password", action="store_true", help="create or change the login, then exit")
    args = ap.parse_args()
    if args.set_password:
        return set_password()

    load_env(ENV_FILE)
    if not auth.configured():
        sys.exit("No login is set up yet. Run:  python3 web.py --set-password")

    srv = ThreadingHTTPServer(("127.0.0.1", args.port), Handler)
    srv.daemon_threads = True
    url = f"http://127.0.0.1:{args.port}"
    print(f"osintkit UI running at {url}  (login: {os.environ['OSINT_USER']}; Ctrl+C to stop)")
    if not args.no_browser:
        threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        srv.serve_forever()
    except KeyboardInterrupt:
        print("\nstopped")


if __name__ == "__main__":
    main()
