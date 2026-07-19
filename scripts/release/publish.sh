#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'publish release: ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -eq 3 ]] || die "usage: $0 TAG OWNER/REPO DIST_DIR"

tag="$1"
repository="$2"
dist_dir="$3"

[[ "${GITHUB_ACTIONS:-}" == true ]] || die "publishing is only allowed in GitHub Actions"
[[ "${GITHUB_REF_TYPE:-}" == tag && "${GITHUB_REF_NAME:-}" == "$tag" ]] ||
  die "workflow ref does not match release tag $tag"
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] ||
  die "invalid GitHub repository: $repository"
[[ -d "$dist_dir" ]] || die "distribution directory not found: $dist_dir"
dist_dir="$(cd -- "$dist_dir" && pwd)"

compare_release_assets() {
  local remote_dir="$1"
  local local_names=()
  local remote_names=()
  local path name

  for path in "$dist_dir"/*; do
    [[ -f "$path" ]] || die "unexpected local release entry: $path"
    local_names+=("$(basename -- "$path")")
  done
  for path in "$remote_dir"/*; do
    [[ -f "$path" ]] || die "unexpected remote release entry: $path"
    remote_names+=("$(basename -- "$path")")
  done
  mapfile -t local_names < <(printf '%s\n' "${local_names[@]}" | LC_ALL=C sort)
  mapfile -t remote_names < <(printf '%s\n' "${remote_names[@]}" | LC_ALL=C sort)
  [[ "${local_names[*]}" == "${remote_names[*]}" ]] ||
    die "GitHub release has a different asset set"

  for name in "${local_names[@]}"; do
    cmp --silent "$dist_dir/$name" "$remote_dir/$name" ||
      die "GitHub release asset differs: $name"
  done
}

release_state=""
if release_state="$(gh release view "$tag" --repo "$repository" --json isDraft --jq '.isDraft')"; then
  if [[ "$release_state" == false ]]; then
    existing_dir="$(mktemp -d)"
    trap 'rm -rf -- "$existing_dir"' EXIT
    gh release download "$tag" --repo "$repository" --dir "$existing_dir"
    compare_release_assets "$existing_dir"
    printf 'published release %s already has the expected immutable assets\n' "$tag"
    exit 0
  fi
  [[ "$release_state" == true ]] || die "could not determine release state"
  while IFS= read -r asset_name; do
    [[ -n "$asset_name" ]] || continue
    gh release delete-asset "$tag" "$asset_name" --repo "$repository" --yes
  done < <(gh release view "$tag" --repo "$repository" --json assets --jq '.assets[].name')
else
  create_args=(
    release create "$tag"
    --repo "$repository"
    --draft
    --verify-tag
    --generate-notes
    --title "$tag"
  )
  if [[ "$tag" == *-* ]]; then
    create_args+=(--prerelease --latest=false)
  fi
  gh "${create_args[@]}"
fi

gh release upload "$tag" --repo "$repository" "$dist_dir"/*

uploaded_dir="$(mktemp -d)"
trap 'rm -rf -- "$uploaded_dir"' EXIT
gh release download "$tag" --repo "$repository" --dir "$uploaded_dir"
compare_release_assets "$uploaded_dir"

if [[ "$tag" == *-* ]]; then
  gh release edit "$tag" --repo "$repository" --draft=false --latest=false --prerelease
else
  gh release edit "$tag" --repo "$repository" --draft=false --latest
fi

printf 'published verified release %s\n' "$tag"
