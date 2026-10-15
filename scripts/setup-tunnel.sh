#!/usr/bin/env bash
# Publish the local osintkit web UI at https://$HOST through a Cloudflare Tunnel.
# Prerequisite: the domain's DNS is managed by Cloudflare (nameservers moved there).
#
#   scripts/setup-tunnel.sh                         # osint.emersonjohnston.org
#   scripts/setup-tunnel.sh other.example.com
set -euo pipefail

HOST="${1:-osint.emersonjohnston.org}"
NAME="osint"
PORT="${PORT:-8000}"
CF="$HOME/.cloudflared"
REPO="evjohnston/osint"

command -v cloudflared >/dev/null || brew install cloudflared

if [ ! -f "$CF/cert.pem" ]; then
  echo "→ A browser window will open. Sign in to Cloudflare and pick the zone for $HOST."
  cloudflared tunnel login
fi

if ! cloudflared tunnel info "$NAME" >/dev/null 2>&1; then
  echo "→ Creating tunnel '$NAME'"
  cloudflared tunnel create "$NAME"
fi
UUID=$(cloudflared tunnel list --output json | python3 -c \
  "import sys,json; print(next(t['id'] for t in json.load(sys.stdin) if t['name']=='$NAME'))")

if [ -f "$CF/config.yml" ] && ! grep -q "$UUID" "$CF/config.yml"; then
  cp "$CF/config.yml" "$CF/config.yml.bak.$(date +%s)"
  echo "→ Backed up your existing $CF/config.yml"
fi
cat > "$CF/config.yml" <<EOF
tunnel: $UUID
credentials-file: $CF/$UUID.json
ingress:
  - hostname: $HOST
    service: http://127.0.0.1:$PORT
  - service: http_status:404
EOF
echo "→ Wrote $CF/config.yml"

echo "→ Pointing $HOST at the tunnel (replaces any existing record for it)"
cloudflared tunnel route dns --overwrite-dns "$NAME" "$HOST"

# The domain used to serve the GitHub Pages landing page. Now that DNS points at
# the tunnel, release it so the old Pages config doesn't linger.
if command -v gh >/dev/null && gh api "repos/$REPO/pages" >/dev/null 2>&1; then
  gh api -X DELETE "repos/$REPO/pages" && echo "→ Turned off GitHub Pages for $REPO"
fi

echo
echo "Done. Next: scripts/install-service.sh  (runs the app + tunnel in the background)"
echo "Or test in the foreground:  python3 web.py --no-browser   and   cloudflared tunnel run $NAME"
