#!/bin/sh
# Start Postfix and Dovecot for the testbed mail sidecar.
#
# No credential is baked into the image. The mailbox password is generated per run by
# the caller and supplied in the environment, exactly as the tunnel PSK is.
set -eu

MAIL_USER="${MAIL_USER:-tester}"
MAIL_PASSWORD="${MAIL_PASSWORD:?MAIL_PASSWORD must be supplied per run}"
FAR_SUBNET="${FAR_SUBNET:-10.1.0.0/24}"
VIA_GATEWAY="${VIA_GATEWAY:-10.2.0.2}"

# Sidecars on a protected network need a route back through their own gateway, or
# replies leave via Docker's bridge instead of the tunnel.
ip route replace "$FAR_SUBNET" via "$VIA_GATEWAY" || true

id "$MAIL_USER" >/dev/null 2>&1 || useradd -m -s /usr/sbin/nologin "$MAIL_USER"
echo "$MAIL_USER:$MAIL_PASSWORD" | chpasswd
mkdir -p "/home/$MAIL_USER/Maildir"
chown -R "$MAIL_USER:$MAIL_USER" "/home/$MAIL_USER"

postconf -e "myhostname = mail.testbed.local"
postconf -e "mydestination = \$myhostname, testbed.local, localhost.localdomain, localhost"
postconf -e "mynetworks = 127.0.0.0/8 10.0.0.0/8"
postconf -e "home_mailbox = Maildir/"
postconf -e "inet_interfaces = all"
postconf -e "smtpd_client_restrictions = permit_mynetworks, reject"
# Attachments in the corpus reach a few megabytes; the default cap would reject them.
postconf -e "message_size_limit = 52428800"

cat > /etc/dovecot/local.conf <<'DOVECOT'
protocols = imap
listen = *
mail_location = maildir:~/Maildir
disable_plaintext_auth = no
auth_mechanisms = plain login
ssl = no
service imap-login {
  inet_listener imap {
    port = 143
  }
}
DOVECOT

postfix start
dovecot

shutdown() {
    dovecot stop 2>/dev/null || true
    postfix stop 2>/dev/null || true
    exit 0
}
trap shutdown TERM INT

# Keep the container alive for as long as the services are wanted.
while true; do sleep 3600 & wait $!; done
