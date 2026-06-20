#!/bin/sh
set -eu

CONF="/etc/nginx/conf.d/default.conf"

if [ ! -f "$CONF" ]; then
  echo "SLS nginx hardening skipped: $CONF not found"
  exit 0
fi

if grep -q "sls_forbidden" "$CONF"; then
  exit 0
fi

tmp="$(mktemp)"
awk '
  BEGIN { patched = 0 }
  {
    print
    if (!patched && $0 ~ /^[[:space:]]*server[[:space:]]*\{/) {
      print "    server_tokens off;"
      print "    error_page 403 = @sls_forbidden;"
      print "    location @sls_forbidden {"
      print "        internal;"
      print "        default_type application/json;"
      print "        return 403 \"{\\\"detail\\\":\\\"Forbidden\\\"}\";"
      print "    }"
      patched = 1
    }
  }
' "$CONF" > "$tmp"
cat "$tmp" > "$CONF"
rm -f "$tmp"
