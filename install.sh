#!/usr/bin/env bash
# Install or update FCR Gate Rust binaries from a GitHub Release.
set -Eeuo pipefail

readonly DEFAULT_REPOSITORY="jpoehnelt/fcr-gate"
readonly INSTALL_ROOT="/data/fcr-gate"
readonly ON_BOOT_DIR="/data/on_boot.d"
readonly SYSTEMD_DIR="/etc/systemd/system"

repository="${FCR_GATE_REPOSITORY:-$DEFAULT_REPOSITORY}"
version="${FCR_GATE_VERSION:-latest}"
start_service=true

usage() {
  cat <<'EOF'
Usage: sudo bash install.sh [options]

Install or update fcr-rfid-encoder and fcr-gate-admin from GitHub Releases.

Options:
  --version TAG       Install a specific release tag, for example v0.1.0.
                      The default is the latest published release.
  --repository OWNER/REPO
                      Override the GitHub repository.
  --no-start          Install and enable the unit without starting it now.
  -h, --help          Show this help.

The first install securely prompts for the Impinj reader password. Existing
configuration and secrets under /data/fcr-gate/secrets are preserved on updates.
EOF
}

log() {
  printf 'fcr-gate installer: %s\n' "$*"
}

warn() {
  printf 'fcr-gate installer: WARNING: %s\n' "$*" >&2
}

die() {
  printf 'fcr-gate installer: ERROR: %s\n' "$*" >&2
  exit 1
}

while (($#)); do
  case "$1" in
    --version)
      (($# >= 2)) || die "--version requires a value"
      version="$2"
      shift 2
      ;;
    --repository)
      (($# >= 2)) || die "--repository requires OWNER/REPO"
      repository="$2"
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
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  die "invalid GitHub repository: $repository"
[[ "$version" == "latest" || "$version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] ||
  die "version must be 'latest' or a tag such as v0.1.0"

for command in chmod curl id install mktemp mv sha256sum sort systemctl tar uname; do
  command -v "$command" >/dev/null 2>&1 || die "required command not found: $command"
done

case "$(uname -m)" in
  aarch64|arm64)
    target="aarch64-unknown-linux-musl"
    ;;
  x86_64|amd64)
    target="x86_64-unknown-linux-musl"
    ;;
  *)
    die "unsupported gateway architecture: $(uname -m)"
    ;;
esac

asset="fcr-gate-${target}.tar.gz"
if [[ "$version" == "latest" ]]; then
  release_base="https://github.com/${repository}/releases/latest/download"
else
  release_base="https://github.com/${repository}/releases/download/${version}"
fi

tmpdir="$(mktemp -d)"
trap 'rm -rf -- "$tmpdir"' EXIT

curl_args=(
  --fail
  --location
  --proto '=https'
  --show-error
  --silent
  --tlsv1.2
  --user-agent 'fcr-gate-installer/1'
)

log "downloading ${asset} from ${repository} (${version})"
curl "${curl_args[@]}" --output "$tmpdir/$asset" "$release_base/$asset"
curl "${curl_args[@]}" --output "$tmpdir/$asset.sha256" "$release_base/$asset.sha256"

(
  cd "$tmpdir"
  sha256sum --check "$asset.sha256"
)

expected_members=(
  30-fcr-rfid-encoder.sh
  VERSION
  fcr-gate-admin
  fcr-rfid-encoder
  fcr-rfid-encoder.service
  gateway.env.example
)
mapfile -t archive_members < <(tar -tzf "$tmpdir/$asset" | LC_ALL=C sort)
mapfile -t sorted_expected < <(printf '%s\n' "${expected_members[@]}" | LC_ALL=C sort)
[[ "${archive_members[*]}" == "${sorted_expected[*]}" ]] ||
  die "release archive contains an unexpected file set"

unpack_dir="$tmpdir/unpacked"
install -d -m 0700 "$unpack_dir"
tar -xzf "$tmpdir/$asset" -C "$unpack_dir"
for member in "${expected_members[@]}"; do
  [[ -f "$unpack_dir/$member" && ! -L "$unpack_dir/$member" ]] ||
    die "release archive member is not a regular file: $member"
done

binary_version="$("$unpack_dir/fcr-rfid-encoder" --version)" ||
  die "downloaded binary did not execute on this gateway"
admin_version="$("$unpack_dir/fcr-gate-admin" --version)" ||
  die "downloaded admin binary did not execute on this gateway"
archive_version="$(<"$unpack_dir/VERSION")"
[[ "$archive_version" =~ ^v[0-9]+\.[0-9]+\.[0-9]+([.-][A-Za-z0-9.-]+)?$ ]] ||
  die "archive contains an invalid VERSION: $archive_version"
[[ "$binary_version" == "fcr-rfid-encoder ${archive_version#v}" ]] ||
  die "binary version '$binary_version' does not match archive '$archive_version'"
[[ "$admin_version" == "fcr-gate-admin ${archive_version#v}" ]] ||
  die "admin version '$admin_version' does not match archive '$archive_version'"
if [[ "$version" != "latest" ]]; then
  [[ "$archive_version" == "$version" ]] ||
    die "archive version '$archive_version' does not match requested release '$version'"
fi
log "verified $binary_version and $admin_version"

install -d -m 0755 "$INSTALL_ROOT" "$INSTALL_ROOT/bin" "$INSTALL_ROOT/deploy"
install -d -m 0700 "$INSTALL_ROOT/secrets"

if [[ ! -d "$ON_BOOT_DIR" ]]; then
  install -d -m 0755 "$ON_BOOT_DIR"
  warn "$ON_BOOT_DIR did not exist; verify that the UniFi on-boot utility is installed"
fi

# Install the executables atomically so a failed download cannot truncate a
# currently running binary.
install -m 0755 "$unpack_dir/fcr-rfid-encoder" "$INSTALL_ROOT/bin/fcr-rfid-encoder.new"
mv -f "$INSTALL_ROOT/bin/fcr-rfid-encoder.new" "$INSTALL_ROOT/bin/fcr-rfid-encoder"
install -m 0755 "$unpack_dir/fcr-gate-admin" "$INSTALL_ROOT/bin/fcr-gate-admin.new"
mv -f "$INSTALL_ROOT/bin/fcr-gate-admin.new" "$INSTALL_ROOT/bin/fcr-gate-admin"
install -m 0644 "$unpack_dir/fcr-rfid-encoder.service" \
  "$INSTALL_ROOT/deploy/fcr-rfid-encoder.service"
install -m 0755 "$unpack_dir/30-fcr-rfid-encoder.sh" \
  "$INSTALL_ROOT/deploy/30-fcr-rfid-encoder.sh"
install -m 0755 "$unpack_dir/30-fcr-rfid-encoder.sh" \
  "$ON_BOOT_DIR/30-fcr-rfid-encoder.sh"
install -m 0644 "$unpack_dir/VERSION" "$INSTALL_ROOT/VERSION"

environment_file="$INSTALL_ROOT/secrets/gateway.env"
if [[ ! -e "$environment_file" ]]; then
  install -m 0600 "$unpack_dir/gateway.env.example" "$environment_file"
  log "created safety-default configuration at $environment_file"
else
  chmod 0600 "$environment_file"
  log "preserved existing $environment_file"
fi

password_file="$INSTALL_ROOT/secrets/impinj-password"
if [[ ! -s "$password_file" ]]; then
  if [[ -r /dev/tty ]]; then
    reader_password=""
    read -r -s -p 'Impinj R700 password: ' reader_password </dev/tty
    printf '\n' >/dev/tty
    [[ -n "$reader_password" ]] || die "the Impinj password cannot be empty"
    umask 077
    printf '%s\n' "$reader_password" >"$password_file"
    unset reader_password
    chmod 0600 "$password_file"
  else
    die "no terminal is available to read the Impinj password securely"
  fi
else
  chmod 0600 "$password_file"
  log "preserved existing Impinj password file"
fi

install -m 0644 "$INSTALL_ROOT/deploy/fcr-rfid-encoder.service" \
  "$SYSTEMD_DIR/fcr-rfid-encoder.service"
systemctl daemon-reload
systemctl enable fcr-rfid-encoder.service >/dev/null

if [[ "$start_service" == true ]]; then
  systemctl restart fcr-rfid-encoder.service
  if systemctl is-active --quiet fcr-rfid-encoder.service; then
    log "service is active"
  else
    systemctl status --no-pager fcr-rfid-encoder.service || true
    die "service did not stay active; inspect: journalctl -u fcr-rfid-encoder -n 100"
  fi

  if curl --silent --show-error --max-time 3 \
    --output "$tmpdir/health.json" --write-out '%{http_code}' \
    http://127.0.0.1:8080/healthz >"$tmpdir/health.status"; then
    health_status="$(<"$tmpdir/health.status")"
    log "local health endpoint returned HTTP $health_status"
  else
    warn "the local health endpoint is not responding yet"
  fi
else
  log "service installed and enabled but not started (--no-start)"
fi

cat <<EOF

Installed $binary_version and $admin_version under $INSTALL_ROOT.

Safety defaults on a first install:
  RFID_WRITES_ENABLED=false
  RFID_LPR_CORRELATION_MODE=disabled
  RFID_DISCOVERY_MODE=disabled
  RFID_GATE_MODE=disabled
  FCR_GATE_WEB_ENABLED=false
  FCR_GATE_METRICS_ENABLED=false

Useful checks:
  systemctl status fcr-rfid-encoder --no-pager
  journalctl -u fcr-rfid-encoder -f
  curl --fail-with-body http://127.0.0.1:8080/healthz
  # After enabling metrics, load the configured listener values:
  . $environment_file
  curl --fail-with-body "http://\${FCR_GATE_METRICS_BIND}:\${FCR_GATE_METRICS_PORT}/metrics"
  /data/fcr-gate/bin/fcr-gate-admin --help

Configuration: $environment_file
EOF
