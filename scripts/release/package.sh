#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'package release: ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || die "usage: $0 TARGET TAG OUTPUT_DIR"

target="$1"
tag="$2"
output_dir="$3"

case "$target" in
  aarch64-unknown-linux-musl|x86_64-unknown-linux-musl) ;;
  *) die "unsupported target: $target" ;;
esac

[[ "$tag" =~ ^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z.-]+)?$ ]] ||
  die "invalid release tag: $tag"

repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"
cd "$repo_root"

package_version="$(awk -F '"' '/^version = / { print $2; exit }' Cargo.toml)"
[[ "v$package_version" == "$tag" ]] ||
  die "Cargo version $package_version does not match tag $tag"

cargo_target_dir="${CARGO_TARGET_DIR:-target}"
binary_dir="$cargo_target_dir/$target/release"
for binary in fcr-gate-admin fcr-rfid-encoder; do
  [[ -x "$binary_dir/$binary" ]] || die "missing binary: $binary_dir/$binary"
done

mkdir -p "$output_dir"
output_dir="$(cd -- "$output_dir" && pwd)"
asset="fcr-gate-${target}.tar.gz"
stage="$(mktemp -d)"
trap 'rm -rf -- "$stage"' EXIT

install -m 0755 "$binary_dir/fcr-rfid-encoder" "$stage/fcr-rfid-encoder"
install -m 0755 "$binary_dir/fcr-gate-admin" "$stage/fcr-gate-admin"
install -m 0644 deploy/fcr-rfid-encoder.service "$stage/fcr-rfid-encoder.service"
install -m 0755 deploy/30-fcr-rfid-encoder.sh "$stage/30-fcr-rfid-encoder.sh"
install -m 0644 deploy/gateway.env.example "$stage/gateway.env.example"
printf '%s\n' "$tag" >"$stage/VERSION"
chmod 0644 "$stage/VERSION"

source_date_epoch="${SOURCE_DATE_EPOCH:-$(git show -s --format=%ct HEAD)}"
[[ "$source_date_epoch" =~ ^[0-9]+$ ]] || die "invalid SOURCE_DATE_EPOCH"

members=(
  30-fcr-rfid-encoder.sh
  VERSION
  fcr-gate-admin
  fcr-rfid-encoder
  fcr-rfid-encoder.service
  gateway.env.example
)

rm -f -- "$output_dir/$asset" "$output_dir/$asset.sha256"
LC_ALL=C TZ=UTC tar \
  --sort=name \
  --format=gnu \
  --mtime="@$source_date_epoch" \
  --owner=0 \
  --group=0 \
  --numeric-owner \
  -C "$stage" \
  -cf - \
  "${members[@]}" | gzip -n -9 >"$output_dir/$asset"

(
  cd "$output_dir"
  sha256sum "$asset" >"$asset.sha256"
)

printf 'packaged %s\n' "$output_dir/$asset"
