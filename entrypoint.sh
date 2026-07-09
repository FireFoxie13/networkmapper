#!/usr/bin/env bash
set -uo pipefail   # NOTE: not -e; a failed scan must not kill the web server.

cd /app/maps
PORT="${PORT:-8080}"

# `docker compose up` does not forward stdin to the az CLI, so the interactive
# tenant/subscription picker would hang forever. Turn it off before logging in.
az config set core.login_experience_v2=off >/dev/null 2>&1 || true
az config set extension.use_dynamic_install=yes_without_prompt >/dev/null 2>&1 || true

if ! az account show >/dev/null 2>&1; then
  echo ">> No Azure session found. Starting device-code login..."
  if ! az login --use-device-code --only-show-errors; then
    echo "!! Azure login failed. Fix credentials and restart the container." >&2
    exit 1
  fi
fi
echo ">> Logged in as: $(az account show --query user.name -o tsv 2>/dev/null || echo unknown)"
echo ">> Subscriptions visible: $(az account list --all --query 'length(@)' -o tsv 2>/dev/null || echo '?')"

run_scan() {
  echo ">> Scan started $(date -u +%Y-%m-%dT%H:%M:%SZ)"
  if TEMPLATE=/app/azure-net-map.html bash /app/generate-netmap.sh; then
    LATEST=$(ls -t azure-net-map-*.html 2>/dev/null | head -1 || true)
    if [ -n "${LATEST:-}" ]; then
      cp -f "$LATEST" index.html
      echo ">> Scan complete: $LATEST"
      return 0
    fi
    echo "!! Scan produced no output file." >&2
  else
    echo "!! Scan failed." >&2
  fi
  return 1
}

if ! run_scan; then
  if [ -f index.html ]; then
    echo ">> Serving the previous map from ./maps/index.html"
  else
    echo ">> No map available yet. The server will start; fix the error and restart, or wait for a rescan."
    printf '%s' '<h2 style="font-family:sans-serif">No scan data yet</h2><p style="font-family:sans-serif">The first scan failed. Check the container logs.</p>' > index.html
  fi
fi

# Scheduled rescans keep the map current, like a topology tool.
if [ -n "${RESCAN_HOURS:-}" ]; then
  echo ">> Rescanning every ${RESCAN_HOURS}h"
  ( while sleep $(( RESCAN_HOURS * 3600 )); do run_scan || echo ">> Rescan failed, keeping the last good map"; done ) &
fi

echo ""
echo "=============================================="
echo "  Network Mapper is live:  http://localhost:${PORT}"
echo "  Dated scans and index.html live in ./maps/"
echo "=============================================="
exec python3 -m http.server "$PORT" --bind 0.0.0.0
