#!/bin/bash
# Apple pkgbuild(1)/productbuild(1), shipped man pages (also mirrored at):
# https://keith.github.io/xcode-man-pages/pkgbuild.1.html
# https://keith.github.io/xcode-man-pages/productbuild.1.html
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
test_arm64=false
if [ "${1:-}" = --test-arm64 ]; then test_arm64=true; shift; fi
[ "$#" -eq 3 ] || { echo 'usage: build-pkg.sh [--test-arm64] BINARY VERSION OUTPUT.pkg' >&2; exit 2; }
binary=$1
version=$2
output=$3
[ -f "$binary" ] && [ ! -L "$binary" ] || { echo 'binary must be a regular file' >&2; exit 2; }
case "$version" in ''|*[!0-9.]*) echo 'version must be numeric dot-separated components' >&2; exit 2;; esac
case "$output" in /*.pkg) ;; *) echo 'output must be an absolute .pkg path' >&2; exit 2;; esac
[ ! -e "$output" ] && [ ! -L "$output" ] || { echo 'output already exists' >&2; exit 2; }
# D7: shipping payloads are universal. The explicit thin fixture is not releasable.
if "$test_arm64"; then
    /usr/bin/lipo "$binary" -verify_arch arm64
    echo 'TEST ONLY: unsigned arm64 inspection fixture; not a release artifact' >&2
else
    /usr/bin/lipo "$binary" -verify_arch arm64 x86_64
fi
mkdir -p -- "$(dirname -- "$output")"
work=$(mktemp -d "$(dirname -- "$output")/.pkg-build.XXXXXX")
trap 'rm -rf -- "$work"' EXIT
payload="$work/root"
app="$payload/Library/Application Support/TG-Sentry"
mkdir -p "$app" "$payload/Library/LaunchDaemons" "$work/scripts"
# Stage only package-owned public files; never package private/ or run/.
input_hash=$(shasum -a 256 "$binary" | awk '{print $1}')
install -m 755 "$binary" "$app/aegishook"
[ "$(shasum -a 256 "$app/aegishook" | awk '{print $1}')" = "$input_hash" ] || { echo 'STOP: binary changed during staging' >&2; exit 1; }
install -m 644 "$here/launchd/com.tg-sentry.endpoint.plist" "$payload/Library/LaunchDaemons/"
binary_hash=$(shasum -a 256 "$app/aegishook" | awk '{print $1}')
plist_hash=$(shasum -a 256 "$here/launchd/com.tg-sentry.endpoint.plist" | awk '{print $1}')
sed -e "s/@BINARY_SHA256@/$binary_hash/g" -e "s/@PLIST_SHA256@/$plist_hash/g" \
    "$here/payload/uninstall.sh" > "$app/uninstall.sh"
chmod 755 "$app/uninstall.sh"
install -m 755 "$here/scripts/preinstall" "$here/scripts/postinstall" "$work/scripts/"
find "$payload" -type d -exec chmod 755 {} +
# --root archives this staging tree; --scripts recognizes preinstall/postinstall.
# Stable identifier enables upgrade recognition; explicit version avoids version 0.
# recommended records root:wheel without root/chown on the build host.
/usr/bin/pkgbuild --root "$payload" --scripts "$work/scripts" \
    --identifier com.tg-sentry.endpoint --version "$version" \
    --install-location / --ownership recommended "$work/endpoint.pkg"
# S6 HOOK: sign the universal binary BEFORE staging, and add productbuild --sign
# with a purchased Developer ID Installer identity here; notarize/staple in S6.
# Deliberately no signing/keychain lookup or notarization in this unsigned S5 path.
/usr/bin/productbuild --package "$work/endpoint.pkg" "$output"
printf '%s\n' "UNSIGNED package: $output"
