#!/bin/sh
# Start Prosody for the testbed messaging sidecar.
#
# Account passwords are generated per run and supplied in the environment; none is
# committed to the repository or baked into the image.
set -eu

XMPP_DOMAIN="${XMPP_DOMAIN:-testbed.local}"
XMPP_PASSWORD="${XMPP_PASSWORD:?XMPP_PASSWORD must be supplied per run}"
FAR_SUBNET="${FAR_SUBNET:-10.1.0.0/24}"
VIA_GATEWAY="${VIA_GATEWAY:-10.2.0.2}"

ip route replace "$FAR_SUBNET" via "$VIA_GATEWAY" || true

cat > /etc/prosody/prosody.cfg.lua <<LUA
admins = { }
modules_enabled = { "roster"; "saslauth"; "tls"; "dialback"; "disco"; "carbons";
                    "pep"; "private"; "blocklist"; "vcard4"; "vcard_legacy";
                    "version"; "uptime"; "time"; "ping"; "posix"; }
-- The testbed link is already inside an IPsec tunnel; requiring TLS on top would
-- only obscure the traffic shape this corpus exists to capture.
c2s_require_encryption = false
s2s_require_encryption = false
allow_registration = false
authentication = "internal_plain"
pidfile = "/var/run/prosody/prosody.pid"
log = { info = "*console" }
data_path = "/var/lib/prosody"

VirtualHost "$XMPP_DOMAIN"
LUA

mkdir -p /var/run/prosody /var/lib/prosody
chown -R prosody:prosody /var/run/prosody /var/lib/prosody

prosodyctl register alice "$XMPP_DOMAIN" "$XMPP_PASSWORD" || true
prosodyctl register bob "$XMPP_DOMAIN" "$XMPP_PASSWORD" || true

exec prosody -F
