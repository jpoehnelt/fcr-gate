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

getent group alloy >/dev/null 2>&1 || groupadd --system alloy
if ! id -u alloy >/dev/null 2>&1; then
  useradd --system --gid alloy --home-dir /nonexistent --shell /bin/false alloy
fi
if getent group systemd-journal >/dev/null 2>&1; then
  journal_group=systemd-journal
elif getent group adm >/dev/null 2>&1; then
  journal_group=adm
else
  exit 0
fi
usermod -G "$journal_group" alloy

install -d -o alloy -g alloy -m 0750 "$install_root/alloy-data"
chown root:alloy "$install_root/deploy/alloy-fcr-gate.config.alloy"
chmod 0640 "$install_root/deploy/alloy-fcr-gate.config.alloy"
install -m 0644 "$install_root/deploy/alloy-fcr-gate.service" \
  /etc/systemd/system/alloy-fcr-gate.service
systemctl daemon-reload
systemctl enable alloy-fcr-gate.service
systemctl restart alloy-fcr-gate.service
