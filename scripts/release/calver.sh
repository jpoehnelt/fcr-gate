#!/usr/bin/env bash
set -Eeuo pipefail

die() {
  printf 'calendar version: ERROR: %s\n' "$*" >&2
  exit 1
}

[[ $# -le 1 ]] || die "usage: $0 [YYYY-MM-DD]"

release_date="${1:-}"
if [[ -z "$release_date" ]]; then
  release_date="$(TZ="${CALVER_TIMEZONE:-America/Denver}" date +%F)"
fi

[[ "$release_date" =~ ^([1-9][0-9]{3})-([0-9]{2})-([0-9]{2})$ ]] ||
  die "date must use YYYY-MM-DD"

year="$((10#${BASH_REMATCH[1]}))"
month="$((10#${BASH_REMATCH[2]}))"
day="$((10#${BASH_REMATCH[3]}))"

case "$month" in
  1|3|5|7|8|10|12) days_in_month=31 ;;
  4|6|9|11) days_in_month=30 ;;
  2)
    days_in_month=28
    if ((year % 400 == 0 || (year % 4 == 0 && year % 100 != 0))); then
      days_in_month=29
    fi
    ;;
  *) die "month is out of range: ${BASH_REMATCH[2]}" ;;
esac

((day >= 1 && day <= days_in_month)) ||
  die "day is out of range for $release_date"

printf 'v%d.%d.%d\n' "$year" "$month" "$day"
