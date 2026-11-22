#!/usr/bin/env bash
# Lists Go files that are not gofmt-clean and exits 1 if there are any.
# Scans the Go source directories that exist: cmd, internal and e2e.
set -euo pipefail

cd "$(dirname "$0")/.."

dirs=()
for d in cmd internal e2e; do
  if [ -d "$d" ]; then
    dirs+=("$d")
  fi
done

if [ "${#dirs[@]}" -eq 0 ]; then
  exit 0
fi

offending="$(gofmt -l "${dirs[@]}")"
if [ -n "$offending" ]; then
  echo "$offending"
  echo "gofmt: the files above need formatting (run: gofmt -w <file>)" >&2
  exit 1
fi
