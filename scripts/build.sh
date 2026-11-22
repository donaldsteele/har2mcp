#!/usr/bin/env bash
# Cross-compiles har2mcp for Windows, macOS and Linux (amd64 and arm64), zips
# each binary with README.md, HOW-TO-OPEN.txt, LICENSE and NOTICE into
# dist/har2mcp_<version>_<os>_<arch>.zip, and writes dist/SHA256SUMS.
#
# Usage: bash scripts/build.sh                     (VERSION from git describe)
#        VERSION=0.1.0 bash scripts/build.sh       (a leading "v" is dropped)
#        RELEASE=1 VERSION=v0.1.0 bash scripts/build.sh
#
# LICENSE and NOTICE are always required. A missing README.md or
# HOW-TO-OPEN.txt is a warning, or an error with RELEASE=1 (the release
# workflow sets it), so a release zip always carries all four.
#
# Zips are made with zip, or 7z when zip is not installed (Git Bash on
# Windows).
set -euo pipefail
cd "$(dirname "$0")/.."

VERSION="${VERSION:-$(git describe --tags --always --dirty 2>/dev/null || echo dev)}"
VERSION="${VERSION#v}" # 'har2mcp version' prints "har2mcp 0.1.0", not "v0.1.0"
case "$VERSION" in
  "" | *[!A-Za-z0-9._+-]*)
    echo "build.sh: VERSION '$VERSION' may only contain letters, digits and . _ + -" >&2
    exit 2
    ;;
esac

MODULE=github.com/donaldsteele/har2mcp
LDFLAGS="-s -w -X $MODULE/internal/version.Version=$VERSION"
TARGETS="windows/amd64 windows/arm64 darwin/amd64 darwin/arm64 linux/amd64 linux/arm64"
DIST=dist

docs=()
for f in README.md HOW-TO-OPEN.txt LICENSE NOTICE; do
  if [ -f "$f" ]; then
    docs+=("$f")
  elif [ "$f" = LICENSE ] || [ "$f" = NOTICE ] || [ "${RELEASE:-}" = 1 ]; then
    echo "build.sh: missing $f" >&2
    exit 1
  else
    echo "build.sh: warning: $f is missing; the zips will not include it" >&2
  fi
done

if command -v zip >/dev/null 2>&1; then
  zipper=zip
elif command -v 7z >/dev/null 2>&1; then
  zipper=7z
else
  echo "build.sh: neither zip nor 7z is installed" >&2
  exit 1
fi

# make_zip <dest.zip> <dir>: zip the files in dir at the root of dest.zip.
make_zip() {
  local dest="$1" src="$2"
  rm -f "$dest"
  if [ "$zipper" = zip ]; then
    (cd "$src" && zip -q -X -9 "$dest" ./*)
  else
    (cd "$src" && 7z a -tzip -mx=9 "$dest" ./* >/dev/null)
  fi
}

# sha256 <file>...: "<hash>  <file>" lines with GNU coreutils or macOS. The
# sed drops the "*" binary marker sha256sum prints on Windows.
sha256() {
  if command -v sha256sum >/dev/null 2>&1; then
    sha256sum "$@"
  else
    shasum -a 256 "$@"
  fi | sed 's/ [*]/  /'
}

mkdir -p "$DIST"
rm -f "$DIST"/har2mcp_*.zip "$DIST"/SHA256SUMS
dist_abs="$(cd "$DIST" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT

echo "har2mcp version: $VERSION"
for target in $TARGETS; do
  goos="${target%/*}"
  goarch="${target#*/}"
  exe=""
  [ "$goos" = windows ] && exe=".exe"

  pkg="$stage/$goos-$goarch"
  mkdir -p "$pkg"
  echo "building $goos/$goarch"
  CGO_ENABLED=0 GOOS="$goos" GOARCH="$goarch" \
    go build -trimpath -ldflags "$LDFLAGS" -o "$pkg/har2mcp$exe" ./cmd/har2mcp
  cp "${docs[@]}" "$pkg/"

  zipname="har2mcp_${VERSION}_${goos}_${goarch}.zip"
  make_zip "$dist_abs/$zipname" "$pkg"
  echo "wrote $DIST/$zipname"
  rm -rf "$pkg"
done

(cd "$DIST" && sha256 har2mcp_*.zip > SHA256SUMS)
echo "wrote $DIST/SHA256SUMS"
