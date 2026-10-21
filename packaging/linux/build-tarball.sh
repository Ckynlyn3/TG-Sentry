#!/bin/sh
# Reuse packaging/macos/build-pkg.sh: stage only public payload, bind actual bytes.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
[ "$#" -eq 3 ] || { echo 'usage: build-tarball.sh BINARY VERSION OUTPUT.tar.gz' >&2; exit 2; }
binary=$1
version=$2
output=$3
if [ ! -f "$binary" ] || [ -L "$binary" ]; then echo 'binary must be a regular file' >&2; exit 2; fi
case "$version" in ''|*[!0-9.]*) echo 'version must be numeric dot-separated components' >&2; exit 2;; esac
case "$output" in /*.tar.gz) ;; *) echo 'output must be an absolute .tar.gz path' >&2; exit 2;; esac
if [ -e "$output" ] || [ -L "$output" ]; then echo 'output already exists' >&2; exit 2; fi
# Standard ELF magic (System V ABI), then EI_CLASS/EI_DATA and e_machine.
# https://gabi.xinuos.com/elf/02-eheader.html
magic=$(od -An -tx1 -N4 "$binary" | tr -d ' \n')
[ "$magic" = 7f454c46 ] || { echo 'binary must be ELF' >&2; exit 2; }
format=$(od -An -tu1 -j4 -N2 "$binary" | awk '{$1=$1; print}')
[ "$format" = '2 1' ] || { echo 'binary must be 64-bit little-endian ELF' >&2; exit 2; }
machine=$(od -An -tu1 -j18 -N2 "$binary" | awk '{$1=$1; print}')
case "$machine" in
    '62 0') arch=amd64 ;;
    '183 0') arch=arm64 ;;
    *) echo 'binary must target Linux amd64 or arm64' >&2; exit 2;;
esac
mkdir -p -- "$(dirname -- "$output")"
work=$(mktemp -d "$(dirname -- "$output")/.tarball-build.XXXXXX")
trap 'rm -rf -- "$work"' 0
trap 'exit 1' HUP INT TERM
payload="$work/tg-sentry-$version-linux-$arch"
mkdir -p "$payload/opt/tg-sentry" "$payload/etc/systemd/system"
input_hash=$(shasum -a 256 "$binary" | awk '{print $1}')
install -m 755 "$binary" "$payload/opt/tg-sentry/aegishook"
[ "$(shasum -a 256 "$payload/opt/tg-sentry/aegishook" | awk '{print $1}')" = "$input_hash" ] || { echo 'STOP: binary changed during staging' >&2; exit 1; }
install -m 644 "$here/tg-sentry.service" "$payload/etc/systemd/system/tg-sentry.service"
binary_hash=$(shasum -a 256 "$payload/opt/tg-sentry/aegishook" | awk '{print $1}')
unit_hash=$(shasum -a 256 "$payload/etc/systemd/system/tg-sentry.service" | awk '{print $1}')
# Reproduce macOS build-pkg.sh substitutions from actual staged public bytes.
for script in install.sh uninstall.sh; do
    destination="$payload/install.sh"
    if [ "$script" = uninstall.sh ]; then destination="$payload/opt/tg-sentry/uninstall.sh"; fi
    sed -e "s/@BINARY_SHA256@/$binary_hash/g" -e "s/@UNIT_SHA256@/$unit_hash/g" \
        "$here/$script" > "$destination"
    chmod 755 "$destination"
done
# bsdtar native copyfile switch: do not ship macOS AppleDouble metadata.
# https://github.com/libarchive/libarchive/blob/v3.8.1/tar/bsdtar.c
COPYFILE_DISABLE=1 tar -czf "$work/package.tar.gz" -C "$work" "tg-sentry-$version-linux-$arch"
mv -- "$work/package.tar.gz" "$output"
printf '%s\n' "$output"
shasum -a 256 "$output"
