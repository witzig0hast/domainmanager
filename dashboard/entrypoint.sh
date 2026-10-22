#!/bin/sh
set -eu

TLS_MODE="${TLS_MODE:-selfsigned}"
CERT="${TLS_CERT_FILE:-/data/tls/cert.pem}"
KEY="${TLS_KEY_FILE:-/data/tls/key.pem}"

set -- uvicorn app.main:app --host 0.0.0.0 --port 8443 \
  --no-server-header --no-date-header --timeout-keep-alive 5 \
  --limit-concurrency 100 --log-level warning --no-access-log

if [ -n "${TRUSTED_PROXIES:-}" ]; then
  set -- "$@" --proxy-headers --forwarded-allow-ips "$TRUSTED_PROXIES"
fi

case "$TLS_MODE" in
  selfsigned)
    python -m app.tlsgen "$CERT" "$KEY"
    set -- "$@" --ssl-certfile "$CERT" --ssl-keyfile "$KEY" ;;
  custom)
    set -- "$@" --ssl-certfile "$CERT" --ssl-keyfile "$KEY" ;;
  off) ;;
  *) echo "Unbekannter TLS_MODE: $TLS_MODE" >&2; exit 1 ;;
esac

exec "$@"
