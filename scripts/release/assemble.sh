#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'assemble release: ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 2 ]] || die "usage: $0 TAG DIST_DIR"

tag="$1"
dist_dir="$2"
repo_root="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)"

[[ -d "$dist_dir" ]] || die "distribution directory not found: $dist_dir"
dist_dir="$(cd -- "$dist_dir" && pwd)"

targets=(
  aarch64-unknown-linux-musl
  x86_64-unknown-linux-musl
)
for target in "${targets[@]}"; do
  "$repo_root/scripts/release/verify-archive.sh" \
    "$dist_dir/fcr-gate-${target}.tar.gz" "$target" "$tag"
done

install -m 0755 "$repo_root/install.sh" "$dist_dir/install-fcr-gate.sh"
(
  cd "$dist_dir"
  sha256sum install-fcr-gate.sh >install-fcr-gate.sh.sha256
  sha256sum \
    fcr-gate-aarch64-unknown-linux-musl.tar.gz \
    fcr-gate-x86_64-unknown-linux-musl.tar.gz \
    install-fcr-gate.sh | LC_ALL=C sort -k2 >SHA256SUMS
  sha256sum --check SHA256SUMS
  sha256sum --check -- ./*.sha256
)

expected_files=(
  SHA256SUMS
  fcr-gate-aarch64-unknown-linux-musl.tar.gz
  fcr-gate-aarch64-unknown-linux-musl.tar.gz.sha256
  fcr-gate-x86_64-unknown-linux-musl.tar.gz
  fcr-gate-x86_64-unknown-linux-musl.tar.gz.sha256
  install-fcr-gate.sh
  install-fcr-gate.sh.sha256
)
actual_files=()
for path in "$dist_dir"/*; do
  [[ -f "$path" ]] || die "unexpected non-file release asset: $path"
  actual_files+=("$(basename -- "$path")")
done
mapfile -t sorted_actual < <(printf '%s\n' "${actual_files[@]}" | LC_ALL=C sort)
mapfile -t sorted_expected < <(printf '%s\n' "${expected_files[@]}" | LC_ALL=C sort)
[[ "${sorted_actual[*]}" == "${sorted_expected[*]}" ]] ||
  die "distribution directory contains an unexpected file set"

printf 'assembled and verified %s\n' "$dist_dir"
