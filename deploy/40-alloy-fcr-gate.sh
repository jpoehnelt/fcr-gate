#!/bin/sh
set -eu

install_root=/data/fcr-gate
environment_file="$install_root/secrets/alloy.env"

[ -x "$install_root/bin/alloy" ] || exit 0
[ -s "$environment_file" ] || exit 0
grep -Eq '^FCR_GATE_LOKI_URL=https?://[^[:space:]]+/loki/api/v1/push$' \
  "$environment_file" || exit 0
for variable in FCR_GATE_HOST FCR_GATE_SITE; do
  grep -Eq "^${variable}=[^[:space:]]+$" "$environment_file" || exit 0
done

install -d -m 0700 "$install_root/alloy-data"
install -m 0644 "$install_root/deploy/alloy-fcr-gate.service" \
  /etc/systemd/system/alloy-fcr-gate.service
systemctl daemon-reload
systemctl enable alloy-fcr-gate.service
systemctl restart alloy-fcr-gate.service
