#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'set release version: ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -ge 1 && $# -le 2 ]] || die "usage: $0 TAG [REPOSITORY_ROOT]"

tag="$1"
repo_root="${2:-$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/../.." && pwd)}"
manifest="$repo_root/Cargo.toml"
lockfile="$repo_root/Cargo.lock"

[[ -f "$manifest" && -f "$lockfile" ]] ||
  die "Cargo.toml and Cargo.lock are required below $repo_root"
[[ "$tag" =~ ^v([1-9][0-9]{3})\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$ ]] ||
  die "calendar tag must use vYYYY.M.D without zero padding"

year="${BASH_REMATCH[1]}"
month="${BASH_REMATCH[2]}"
day="${BASH_REMATCH[3]}"
release_date="$(printf '%04d-%02d-%02d' "$year" "$month" "$day")"
expected_tag="$("$(dirname -- "${BASH_SOURCE[0]}")/calver.sh" "$release_date")"
[[ "$expected_tag" == "$tag" ]] || die "invalid calendar date in tag: $tag"

package_name="$(awk -F '"' '
  $0 == "[package]" { in_package = 1; next }
  in_package && /^\[/ { in_package = 0 }
  in_package && /^name = "/ { print $2; exit }
' "$manifest")"
current_version="$(awk -F '"' '
  $0 == "[package]" { in_package = 1; next }
  in_package && /^\[/ { in_package = 0 }
  in_package && /^version = "/ { print $2; exit }
' "$manifest")"
[[ -n "$package_name" && -n "$current_version" ]] ||
  die "could not read package name and version from Cargo.toml"
[[ "$current_version" != "${tag#v}" ]] || die "Cargo version already matches $tag"

manifest_tmp="$(mktemp "$manifest.XXXXXX")"
lockfile_tmp="$(mktemp "$lockfile.XXXXXX")"
cleanup() {
  rm -f -- "$manifest_tmp" "$lockfile_tmp"
}
trap cleanup EXIT

awk -v version="${tag#v}" '
  BEGIN { in_package = 0; replaced = 0 }
  $0 == "[package]" { in_package = 1; print; next }
  in_package && /^\[/ { in_package = 0 }
  in_package && !replaced && /^version = "/ {
    print "version = \"" version "\""
    replaced = 1
    next
  }
  { print }
  END { if (!replaced) exit 42 }
' "$manifest" >"$manifest_tmp" || die "could not update Cargo.toml"

awk -v package_name="$package_name" -v old_version="$current_version" -v version="${tag#v}" '
  BEGIN { in_package = 0; target_package = 0; replaced = 0 }
  $0 == "[[package]]" { in_package = 1; target_package = 0; print; next }
  in_package && $0 == "name = \"" package_name "\"" {
    target_package = 1
    print
    next
  }
  target_package && $0 == "version = \"" old_version "\"" {
    print "version = \"" version "\""
    replaced = 1
    target_package = 0
    next
  }
  { print }
  END { if (!replaced) exit 42 }
' "$lockfile" >"$lockfile_tmp" || die "could not update Cargo.lock"

chmod 0644 "$manifest_tmp" "$lockfile_tmp"
mv -f -- "$manifest_tmp" "$manifest"
mv -f -- "$lockfile_tmp" "$lockfile"
trap - EXIT

(
  cd "$repo_root"
  cargo metadata --locked --no-deps --format-version 1 >/dev/null
)

printf 'set %s to %s\n' "$package_name" "${tag#v}"
