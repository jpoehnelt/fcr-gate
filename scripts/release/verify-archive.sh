#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'verify release archive: ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || die "usage: $0 ARCHIVE TARGET TAG"

archive="$1"
target="$2"
tag="$3"

[[ -f "$archive" ]] || die "archive not found: $archive"
archive_dir="$(cd -- "$(dirname -- "$archive")" && pwd)"
archive_name="$(basename -- "$archive")"
archive="$archive_dir/$archive_name"
checksum="$archive.sha256"

[[ "$archive_name" == "fcr-gate-${target}.tar.gz" ]] ||
  die "archive name does not match target $target"
[[ -f "$checksum" ]] || die "checksum not found: $checksum"

case "$target" in
  aarch64-unknown-linux-musl)
    expected_machine='Machine:                           AArch64'
    ;;
  x86_64-unknown-linux-musl)
    expected_machine='Machine:                           Advanced Micro Devices X86-64'
    ;;
  *) die "unsupported target: $target" ;;
esac

(
  cd "$archive_dir"
  sha256sum --check "$archive_name.sha256"
)

expected_members=(
  30-fcr-rfid-encoder.sh
  VERSION
  fcr-rfid-encoder
  fcr-rfid-encoder.service
  gateway.env.example
)
mapfile -t archive_members < <(tar -tzf "$archive" | LC_ALL=C sort)
mapfile -t sorted_expected < <(printf '%s\n' "${expected_members[@]}" | LC_ALL=C sort)
[[ "${archive_members[*]}" == "${sorted_expected[*]}" ]] ||
  die "archive contains an unexpected file set"

unpack_dir="$(mktemp -d)"
trap 'rm -rf -- "$unpack_dir"' EXIT
tar -xzf "$archive" -C "$unpack_dir"

for member in "${expected_members[@]}"; do
  [[ -f "$unpack_dir/$member" && ! -L "$unpack_dir/$member" ]] ||
    die "archive member is not a regular file: $member"
done
[[ "$(<"$unpack_dir/VERSION")" == "$tag" ]] || die "VERSION does not match $tag"

binary_path="$unpack_dir/fcr-rfid-encoder"
[[ -x "$binary_path" ]] || die "fcr-rfid-encoder is not executable"
header="$(readelf -h "$binary_path")" ||
  die "cannot read ELF header of fcr-rfid-encoder"
grep -Fq "$expected_machine" <<<"$header" ||
  die "fcr-rfid-encoder has the wrong architecture"
segments="$(readelf -l "$binary_path")" ||
  die "cannot read ELF program headers of fcr-rfid-encoder"
if grep -Fq 'INTERP' <<<"$segments"; then
  die "fcr-rfid-encoder has a dynamic program interpreter"
fi
dynamic="$(readelf -d "$binary_path" 2>/dev/null || true)"
if grep -Fq '(NEEDED)' <<<"$dynamic"; then
  die "fcr-rfid-encoder has a dynamic library dependency"
fi

if [[ "$(uname -m)" == x86_64 && "$target" == x86_64-unknown-linux-musl ]]; then
  [[ "$("$unpack_dir/fcr-rfid-encoder" --version)" == "fcr-rfid-encoder ${tag#v}" ]] ||
    die "encoder binary version does not match $tag"
fi

printf 'verified %s\n' "$archive"
