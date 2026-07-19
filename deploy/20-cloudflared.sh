#!/bin/sh
# Recreate the cloudflared unit from persistent /data storage at UniFi boot.
set -eu

install -m 0644 \
  /data/fcr-gate/deploy/cloudflared.service \
  /etc/systemd/system/cloudflared.service
systemctl daemon-reload
systemctl enable cloudflared.service
systemctl restart cloudflared.service
