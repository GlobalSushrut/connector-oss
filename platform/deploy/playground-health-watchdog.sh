#!/bin/sh
# Restart connector-platform when /healthz stops answering (hung Tokio / mutex wedge).
# supervisord autorestart only helps when the process exits; a wedged HTTP server stays up.
set -eu
CONF="${SUPERVISOR_CONF:-/etc/supervisor/conf.d/connector.conf}"
URL="${PLAYGROUND_HEALTH_URL:-http://127.0.0.1:8080/healthz}"
INTERVAL="${PLAYGROUND_HEALTH_INTERVAL_SECS:-15}"
TIMEOUT="${PLAYGROUND_HEALTH_TIMEOUT_SECS:-5}"
THRESHOLD="${PLAYGROUND_HEALTH_FAIL_THRESHOLD:-3}"
GRACE="${PLAYGROUND_HEALTH_GRACE_SECS:-90}"

echo "playground-health-watchdog: start grace=${GRACE}s url=${URL}"
sleep "$GRACE"
fails=0
while true; do
  if curl -sf --max-time "$TIMEOUT" "$URL" >/dev/null 2>&1; then
    fails=0
  else
    fails=$((fails + 1))
    echo "playground-health-watchdog: healthz fail count=${fails}/${THRESHOLD}"
    if [ "$fails" -ge "$THRESHOLD" ]; then
      echo "playground-health-watchdog: restarting connector-platform"
      supervisorctl -c "$CONF" restart connector-platform || true
      fails=0
      sleep 45
    fi
  fi
  sleep "$INTERVAL"
done
