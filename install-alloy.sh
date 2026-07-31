#!/usr/bin/env bash
# Install or update the standalone Grafana Alloy binary used by FCR Gate.
set -Eeuo pipefail

readonly DEFAULT_VERSION="1.18.0"
readonly INSTALL_ROOT="/data/fcr-gate"
readonly ON_BOOT_DIR="/data/on_boot.d"

version="${FCR_GATE_ALLOY_VERSION:-$DEFAULT_VERSION}"
start_service=true

usage() {
  cat <<'EOF'
Usage: sudo bash install-alloy.sh [options]

Install the pinned Grafana Alloy standalone binary and enable the FCR Gate Loki
shipper. Run install-fcr-gate.sh first so its checked-in Alloy configuration is
available under /data/fcr-gate/deploy.

Options:
  --version VERSION  Install an explicit Alloy release, for example 1.18.0.
  --no-start         Install and enable the unit without starting it now.
  -h, --help         Show this help.
EOF
}

log() {
  printf 'fcr-gate Alloy installer: %s\n' "$*"
}

die() {
  printf 'fcr-gate Alloy installer: ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die "--version requires a value"
      version="$2"
      shift 2
      ;;
    --no-start)
      start_service=false
      shift
      ;;
    -h|--help)
      usage
      exit 0
      ;;
    *)
      die "unknown option: $1"
      ;;
  esac
done

[[ "$(id -u)" == "0" ]] || die "run this installer as root"
[[ "$version" =~ ^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] ||
  die "invalid Alloy version: $version"

for command in chmod chown curl getent grep groupadd id install mktemp mv sha256sum systemctl uname unzip useradd usermod; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

case "$(uname -m)" in
  aarch64|arm64)
    alloy_arch="arm64"
    ;;
  x86_64|amd64)
    alloy_arch="amd64"
    ;;
  *)
    die "unsupported gateway architecture: $(uname -m)"
    ;;
esac

for required in \
  alloy-fcr-gate.config.alloy \
  alloy-fcr-gate.service \
  alloy.env.example \
  40-alloy-fcr-gate.sh; do
  [[ -f "$INSTALL_ROOT/deploy/$required" ]] ||
    die "missing $INSTALL_ROOT/deploy/$required; update FCR Gate first"
done

install -d -m 0700 "$INSTALL_ROOT/secrets"
environment_file="$INSTALL_ROOT/secrets/alloy.env"
if [[ ! -e "$environment_file" ]]; then
  install -m 0600 "$INSTALL_ROOT/deploy/alloy.env.example" "$environment_file"
  log "created $environment_file; configure its Loki URL, then run this installer again"
  exit 0
fi
chmod 0600 "$environment_file"
grep -Eq '^FCR_GATE_LOKI_URL=https?://[^[:space:]]+/loki/api/v1/push$' \
  "$environment_file" || die "configure FCR_GATE_LOKI_URL in $environment_file"
for variable in FCR_GATE_HOST FCR_GATE_SITE; do
  grep -Eq "^${variable}=[^[:space:]]+$" "$environment_file" ||
    die "configure $variable in $environment_file"
done

asset="alloy-linux-${alloy_arch}.zip"
release_base="https://github.com/grafana/alloy/releases/download/v${version}"
case "${version}:${alloy_arch}" in
  1.18.0:amd64)
    expected_checksum="92f4c950aec4ec16a7fdbf6f805be4334d4d5fbbe458eecf514319c1c491bef4"
    ;;
  1.18.0:arm64)
    expected_checksum="e20f8570628818a15192d34372839017a4c446269b5d96036ad976ebf7a7728a"
    ;;
  *)
    die "Alloy v${version} for ${alloy_arch} has no checksum pinned in this installer"
    ;;
esac
tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT

curl_args=(
  --connect-timeout 15
  --fail
  --location
  --max-time 600
  --proto '=https'
  --proto-redir '=https'
  --show-error
  --silent
  --tlsv1.2
  --user-agent 'fcr-gate-alloy-installer/1'
)

log "downloading Grafana Alloy v${version} for ${alloy_arch}"
curl "${curl_args[@]}" --output "$tmpdir/$asset" "$release_base/$asset"
(
  cd "$tmpdir"
  printf '%s  %s\n' "$expected_checksum" "$asset" | sha256sum --check
)

unpack_dir="$tmpdir/unpacked"
install -d -m 0700 "$unpack_dir"
unzip -q "$tmpdir/$asset" -d "$unpack_dir"
alloy_binary="$unpack_dir/alloy-linux-${alloy_arch}"
[[ -f "$alloy_binary" && ! -L "$alloy_binary" ]] ||
  die "Alloy archive did not contain the expected binary"
chmod 0755 "$alloy_binary"
"$alloy_binary" --version | grep -Fq "v${version}" ||
  die "downloaded Alloy binary did not report v${version}"

install -d -m 0755 "$INSTALL_ROOT/bin" "$ON_BOOT_DIR"
getent group alloy >/dev/null 2>&1 || groupadd --system alloy
if ! id -u alloy >/dev/null 2>&1; then
  useradd --system --gid alloy --home-dir /nonexistent --shell /bin/false alloy
fi
if getent group systemd-journal >/dev/null 2>&1; then
  journal_group=systemd-journal
elif getent group adm >/dev/null 2>&1; then
  journal_group=adm
else
  die "neither adm nor systemd-journal exists; cannot grant Alloy journal access"
fi
usermod -G "$journal_group" alloy

install -d -o alloy -g alloy -m 0750 "$INSTALL_ROOT/alloy-data"
chown root:alloy "$INSTALL_ROOT/deploy/alloy-fcr-gate.config.alloy"
chmod 0640 "$INSTALL_ROOT/deploy/alloy-fcr-gate.config.alloy"
install -m 0755 "$alloy_binary" "$INSTALL_ROOT/bin/alloy.new"
mv -f "$INSTALL_ROOT/bin/alloy.new" "$INSTALL_ROOT/bin/alloy"
install -m 0755 "$INSTALL_ROOT/deploy/40-alloy-fcr-gate.sh" \
  "$ON_BOOT_DIR/40-alloy-fcr-gate.sh"

install -m 0644 "$INSTALL_ROOT/deploy/alloy-fcr-gate.service" \
  /etc/systemd/system/alloy-fcr-gate.service
systemctl daemon-reload
systemctl enable alloy-fcr-gate.service >/dev/null

if [[ "$start_service" == true ]]; then
  systemctl restart alloy-fcr-gate.service
  systemctl is-active --quiet alloy-fcr-gate.service ||
    die "Alloy did not stay active; inspect: journalctl -u alloy-fcr-gate -n 100"
  log "Alloy v${version} is active"
else
  log "Alloy v${version} installed and enabled but not started"
fi
