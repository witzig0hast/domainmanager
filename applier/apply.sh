#!/bin/sh
# Applier: the ONLY component with Docker socket access. It has no network and accepts
# no commands – a request file just triggers one fixed `docker compose up -d <service>`.
set -u

DIR="${APPLIER_DIR:-/applier}"
PROJECT_DIR="${DDNS_PROJECT_DIR:?DDNS_PROJECT_DIR fehlt}"
SERVICE="${DDNS_SERVICE:-cloudflare-ddns}"
PROJECT_NAME="${DDNS_PROJECT_NAME:-}"
COMPOSE_FILE="${DDNS_COMPOSE_FILE:-}"

case "$SERVICE" in *[!a-zA-Z0-9_.-]*|"") echo "Ungültiger DDNS_SERVICE" >&2; exit 1 ;; esac

set -- docker compose --project-directory "$PROJECT_DIR"
[ -n "$COMPOSE_FILE" ] && set -- "$@" -f "$COMPOSE_FILE"
[ -n "$PROJECT_NAME" ] && set -- "$@" -p "$PROJECT_NAME"

echo "Applier bereit: $* up -d --no-deps $SERVICE"
last=0
while :; do
  touch "$DIR/heartbeat"
  if [ -f "$DIR/request.json" ]; then
    nonce=$(grep -o '"nonce": *"[a-f0-9]\{32\}"' "$DIR/request.json" | grep -o '[a-f0-9]\{32\}' | head -n1)
    rm -f "$DIR/request.json"
    now=$(date +%s)
    if [ -z "$nonce" ]; then
      echo "Ungültige Anfrage verworfen"
    elif [ $((now - last)) -lt 10 ]; then
      echo "Anfrage zu schnell nach der letzten – verworfen"
      printf '{"nonce":"%s","ok":false,"exit_code":-1,"finished":%s,"output":"Rate-Limit: bitte 10 s warten"}\n' "$nonce" "$now" > "$DIR/result.tmp"
      mv "$DIR/result.tmp" "$DIR/result.json"
    else
      last=$now
      echo "Wende an ($nonce) …"
      output=$("$@" up -d --no-deps "$SERVICE" 2>&1 | tail -n 20)
      # The pipe hides compose's exit code, so verify the outcome by asking for the service state.
      if "$@" ps --status running --services 2>/dev/null | grep -qx "$SERVICE"; then code=0; else code=1; fi
      ok=false; [ "$code" -eq 0 ] && ok=true
      esc=$(printf '%s' "$output" | sed 's/\\/\\\\/g; s/"/\\"/g' | awk '{printf "%s\\n", $0}' | tr -d '\r' | tr -d '\000-\037')
      printf '{"nonce":"%s","ok":%s,"exit_code":%s,"finished":%s,"output":"%s"}\n' "$nonce" "$ok" "$code" "$(date +%s)" "$esc" > "$DIR/result.tmp"
      mv "$DIR/result.tmp" "$DIR/result.json"
      echo "Fertig ($nonce): ok=$ok"
    fi
  fi
  sleep 2
done
