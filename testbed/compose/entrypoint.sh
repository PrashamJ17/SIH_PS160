#!/bin/sh
# Run charon as the container's main process.
#
# charon is started as a background job rather than exec'd so this shell can service
# SIGTERM: a foreground child would block signal handling until it exited, and the
# sweep tears containers down thousands of times. `wait` makes this equivalent to
# foreground execution — the container lives exactly as long as the daemon.
set -eu

CHARON=/usr/lib/ipsec/charon
[ -x "$CHARON" ] || CHARON=$(command -v charon)

mkdir -p /etc/swanctl/conf.d /var/run
: > /var/log/charon.log

# Write the pre-shared key supplied for this run. The key is generated per run by the
# caller and passed in the environment, so no secret is ever committed to the
# repository or baked into an image. Absent SENTINEL_PSK, no secrets stanza is
# written and PSK connections simply will not authenticate.
if [ -n "${SENTINEL_PSK:-}" ]; then
    cat > /etc/swanctl/conf.d/psk.conf <<PSKEOF
secrets {
    ike-net-net {
        id-left = left
        id-right = right
        secret = "${SENTINEL_PSK}"
    }
}
PSKEOF
    chmod 600 /etc/swanctl/conf.d/psk.conf
fi

"$CHARON" &
CHARON_PID=$!

shutdown() {
    kill -TERM "$CHARON_PID" 2>/dev/null || true
    wait "$CHARON_PID" 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

# Wait for the VICI socket before loading configuration, so `swanctl --load-all`
# cannot race the daemon's startup.
i=0
while [ ! -S /var/run/charon.vici ] && [ "$i" -lt 100 ]; do
    i=$((i + 1))
    sleep 0.1
done

if [ -f /etc/swanctl/swanctl.conf ]; then
    swanctl --load-all --noprompt || echo "entrypoint: swanctl --load-all failed" >&2
fi

wait "$CHARON_PID"
