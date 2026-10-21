#!/bin/bash
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
root='/Library/Application Support/TG-Sentry'
plist=/Library/LaunchDaemons/com.tg-sentry.endpoint.plist
label=system/com.tg-sentry.endpoint
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'uninstall requires root'
case ${1:-} in
    '') [ "$#" -eq 0 ] ;;
    --acknowledge-managed) [ "$#" -eq 1 ] ;;
    *) fail 'usage: uninstall.sh [--acknowledge-managed]' ;;
esac
# Do not execute a substituted/symlinked package binary. Hashes are inserted by
# build-pkg.sh from the ACTUAL staged bytes, never an earlier build receipt.
for dir in / /Library '/Library/Application Support' "$root" /Library/LaunchDaemons; do
    [ ! -L "$dir" ] || fail 'symlink installation directory refused'
    [ -e "$dir" ] || continue
    [ -d "$dir" ] && [ "$(stat -f %u "$dir")" -eq 0 ] || fail 'untrusted installation directory'
    mode=$(stat -f %Lp "$dir")
    [ "$((8#$mode & 0022))" -eq 0 ] || fail 'writable installation directory refused'
done
if [ ! -e "$root/aegishook" ] && [ ! -L "$root/aegishook" ] && [ ! -e "$plist" ] && [ ! -L "$plist" ]; then
    exit 0
fi
for file in "$root/aegishook" "$plist"; do
    [ -f "$file" ] && [ ! -L "$file" ] && [ "$(stat -f %u "$file")" -eq 0 ] || fail 'untrusted payload retained'
    mode=$(stat -f %Lp "$file")
    [ "$((8#$mode & 0022))" -eq 0 ] || fail 'writable payload retained'
done
if [ -e "$root/private/rollback" ] || [ -L "$root/private/rollback" ]; then
    fail 'transaction snapshot retained; resolve explicitly before uninstall'
fi
[ -f "$root/aegishook" ] && [ ! -L "$root/aegishook" ] || fail 'package binary missing or foreign; retained'
[ "$(shasum -a 256 "$root/aegishook" | awk '{print $1}')" = '@BINARY_SHA256@' ] || fail 'modified package binary retained'
[ -f "$plist" ] && [ ! -L "$plist" ] || fail 'LaunchDaemon missing or foreign; retained'
[ "$(shasum -a 256 "$plist" | awk '{print $1}')" = '@PLIST_SHA256@' ] || fail 'modified LaunchDaemon retained'
# This observation is outside core's maintenance lock. Never issue a destructive
# verb on the assumption it will only clean up: concurrent repair can remove the
# sibling first. Refuse before stopping anything; let explicit repair recover it.
if [ -e "$root/private/rollback.cleanup" ] || [ -L "$root/private/rollback.cleanup" ]; then
    fail 'terminal cleanup pending; run aegishook ctl repair and retry uninstall'
fi
# Apple launchctl(1), bootout removes the service definition before terminating
# the foreground daemon; SIGTERM handling lives in S3, not shell kill logic.
# https://keith.github.io/xcode-man-pages/launchctl.1.html
loaded=false
if /bin/launchctl print "$label" >/dev/null 2>&1; then
    /bin/launchctl bootout "$label"
    loaded=true
fi
# Core owns exact-resource removal and managed-reference refusal. Never rm -rf
# private/, run/, rollback/, user hooks, or administrator-managed configuration.
if ! "$root/aegishook" ctl system-uninstall "$@" >/dev/null 2>&1; then
    if "$loaded"; then
        /bin/launchctl bootstrap system "$plist" || fail 'uninstall refused; daemon registration restoration also failed'
    fi
    fail 'uninstall refused; managed references or foreign/modified machine state retained'
fi
rm -- "$plist" "$root/aegishook" "$root/uninstall.sh"
# Only empty runtime directories and core-owned empty lock remain after success.
[ ! -S "$root/run/ctl.sock" ] || fail 'control socket still present; runtime retained'
if [ -f "$root/private/client.lock" ] && [ ! -s "$root/private/client.lock" ]; then
    rm -- "$root/private/client.lock"
fi
# rmdir never recursively deletes foreign files. Parent directories are OS-owned.
for dir in "$root/private" "$root/run" "$root"; do
    if [ -d "$dir" ]; then rmdir -- "$dir" || fail 'nonempty runtime directory retained'; fi
done
