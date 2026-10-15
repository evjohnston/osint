#!/usr/bin/env bash
# Run osintkit's web UI and its Cloudflare Tunnel as macOS LaunchAgents:
# they start when you log in and restart automatically if they crash.
#
#   scripts/install-service.sh              # install / reinstall and start
#   scripts/install-service.sh --uninstall  # stop and remove
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
AGENTS="$HOME/Library/LaunchAgents"
LOGS="$HOME/Library/Logs/osintkit"
DOMAIN="gui/$(id -u)"
WEB="org.emersonjohnston.osintkit.web"
TUN="org.emersonjohnston.osintkit.tunnel"

unload() { launchctl bootout "$DOMAIN/$1" 2>/dev/null || true; rm -f "$AGENTS/$1.plist"; }

if [ "${1:-}" = "--uninstall" ]; then
  unload "$WEB"; unload "$TUN"; echo "Removed both services."; exit 0
fi

PY="$ROOT/.venv/bin/python"; [ -x "$PY" ] || PY="$(command -v python3)"
CLOUDFLARED="$(command -v cloudflared || true)"
[ -n "$CLOUDFLARED" ] || { echo "cloudflared not found. Run scripts/setup-tunnel.sh first."; exit 1; }
[ -f "$HOME/.cloudflared/config.yml" ] || { echo "No tunnel config. Run scripts/setup-tunnel.sh first."; exit 1; }
grep -q '^OSINT_PASSWORD_HASH=' "$ROOT/.env" 2>/dev/null || { echo "No login set. Run: python3 web.py --set-password"; exit 1; }

mkdir -p "$AGENTS" "$LOGS"

plist() {  # label, log name, then program arguments
  local label="$1" log="$2"; shift 2
  local args=""; for a in "$@"; do args+="    <string>$a</string>"$'\n'; done
  cat > "$AGENTS/$label.plist" <<EOF
<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key><string>$label</string>
  <key>ProgramArguments</key>
  <array>
$args  </array>
  <key>WorkingDirectory</key><string>$ROOT</string>
  <key>RunAtLoad</key><true/>
  <key>KeepAlive</key><true/>
  <key>ThrottleInterval</key><integer>10</integer>
  <key>StandardOutPath</key><string>$LOGS/$log.log</string>
  <key>StandardErrorPath</key><string>$LOGS/$log.log</string>
  <key>EnvironmentVariables</key>
  <dict><key>PYTHONUNBUFFERED</key><string>1</string></dict>
</dict>
</plist>
EOF
}

unload "$WEB"; unload "$TUN"
plist "$WEB" web "$PY" "$ROOT/web.py" --no-browser
plist "$TUN" tunnel "$CLOUDFLARED" tunnel --no-autoupdate run osint
launchctl bootstrap "$DOMAIN" "$AGENTS/$WEB.plist"
launchctl bootstrap "$DOMAIN" "$AGENTS/$TUN.plist"

echo "Started. Logs: $LOGS/web.log and $LOGS/tunnel.log"
echo "Status:  launchctl print $DOMAIN/$WEB | grep state"
echo "Remove:  scripts/install-service.sh --uninstall"
echo
echo "Tip: to keep it reachable while the Mac is idle, turn on System Settings → Battery → Options →"
echo "     'Prevent automatic sleeping on power adapter when the display is off'."
