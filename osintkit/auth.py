"""Single-user login for the web UI: password hashing, signed sessions, brute-force limits.

Credentials live in .env (never in the repo):
    OSINT_USER, OSINT_PASSWORD_HASH (PBKDF2-SHA256), OSINT_SECRET (session signing key)
Set them with:  python3 web.py --set-password
"""

import base64
import hashlib
import hmac
import os
import secrets
import threading
import time

ITERATIONS = 600_000
SESSION_TTL = 7 * 86400
COOKIE = "osint_session"


# --- passwords -----------------------------------------------------------------

def hash_password(password, salt=None):
    salt = salt or secrets.token_bytes(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, ITERATIONS)
    return f"pbkdf2_sha256${ITERATIONS}${base64.b64encode(salt).decode()}${base64.b64encode(dk).decode()}"


def verify_password(password, stored):
    try:
        algo, iters, salt, expected = stored.split("$")
        if algo != "pbkdf2_sha256":
            return False
        dk = hashlib.pbkdf2_hmac("sha256", password.encode(), base64.b64decode(salt), int(iters))
        return hmac.compare_digest(dk, base64.b64decode(expected))
    except (ValueError, TypeError):
        return False


def configured():
    return all(os.environ.get(k) for k in ("OSINT_USER", "OSINT_PASSWORD_HASH", "OSINT_SECRET"))


def check_credentials(user, password):
    # Always run the hash so timing doesn't reveal whether the username was right.
    ok_pw = verify_password(password, os.environ.get("OSINT_PASSWORD_HASH", ""))
    ok_user = hmac.compare_digest(user.encode(), os.environ.get("OSINT_USER", "").encode())
    return ok_pw and ok_user


# --- sessions ------------------------------------------------------------------

def _sign(payload):
    key = os.environ["OSINT_SECRET"].encode()
    return base64.urlsafe_b64encode(hmac.new(key, payload.encode(), hashlib.sha256).digest()).decode().rstrip("=")


def make_session(user):
    payload = f"{user}|{int(time.time()) + SESSION_TTL}|{secrets.token_hex(8)}"
    return base64.urlsafe_b64encode(payload.encode()).decode().rstrip("=") + "." + _sign(payload)


def read_session(token):
    """Return the username for a valid, unexpired token, else None."""
    try:
        body, sig = token.split(".", 1)
        payload = base64.urlsafe_b64decode(body + "=" * (-len(body) % 4)).decode()
        if not hmac.compare_digest(sig, _sign(payload)):
            return None
        user, expires, _ = payload.split("|")
        if int(expires) < time.time() or user != os.environ.get("OSINT_USER"):
            return None
        return user
    except (ValueError, KeyError, UnicodeDecodeError):
        return None


# --- brute-force protection ----------------------------------------------------

class LoginLimiter:
    """Max `per_ip` failures per IP and `total` failures overall per `window` seconds."""

    def __init__(self, per_ip=5, total=20, window=900):
        self.per_ip, self.total, self.window = per_ip, total, window
        self.fails = []  # (time, ip)
        self.lock = threading.Lock()

    def _prune(self):
        cutoff = time.time() - self.window
        self.fails = [f for f in self.fails if f[0] > cutoff]

    def blocked(self, ip):
        with self.lock:
            self._prune()
            return (sum(1 for _, i in self.fails if i == ip) >= self.per_ip
                    or len(self.fails) >= self.total)

    def fail(self, ip):
        with self.lock:
            self.fails.append((time.time(), ip))

    def reset(self, ip):
        with self.lock:
            self.fails = [f for f in self.fails if f[1] != ip]


# --- setup helper --------------------------------------------------------------

def write_env(path, values):
    """Set KEY=VALUE pairs in a .env file, replacing existing keys and keeping everything else."""
    lines = open(path).read().splitlines() if os.path.exists(path) else []
    out, done = [], set()
    for line in lines:
        key = line.split("=", 1)[0].strip()
        if key in values:
            out.append(f"{key}={values[key]}")
            done.add(key)
        else:
            out.append(line)
    out += [f"{k}={v}" for k, v in values.items() if k not in done]
    with open(path, "w") as f:
        f.write("\n".join(out) + "\n")
    os.chmod(path, 0o600)
