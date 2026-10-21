#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'uninstall requires root'
case ${1:-} in
    '') [ "$#" -eq 0 ] || fail 'usage: uninstall.sh [--acknowledge-managed]' ;;
    --acknowledge-managed) [ "$#" -eq 1 ] || fail 'usage: uninstall.sh [--acknowledge-managed]' ;;
    *) fail 'usage: uninstall.sh [--acknowledge-managed]' ;;
esac
app=/opt/tg-sentry
root=/var/opt/tg-sentry
unit=/etc/systemd/system/tg-sentry.service
if [ ! -e "$app/aegishook" ] && [ ! -L "$app/aegishook" ] && [ ! -e "$unit" ] && [ ! -L "$unit" ] && [ ! -e "$root/private/client.json" ] && [ ! -L "$root/private/client.json" ]; then
    exit 0
fi
# Build-bound public bytes, following packaging/macos/payload/uninstall.sh:35-38.
# Never stop the daemon or clean private state for a substituted public payload.
for file in "$app/aegishook" "$unit"; do
    case "$file" in
        "$app/aegishook") expected='@BINARY_SHA256@' ;;
        "$unit") expected='@UNIT_SHA256@' ;;
    esac
    if [ ! -f "$file" ] || [ -L "$file" ]; then
        fail "package file $file missing or foreign; retained"
    fi
    [ "$(sha256sum "$file" | awk '{print $1}')" = "$expected" ] || fail "modified package file $file retained"
done
# Never dispatch destructive uninstall into core's cleanup-only early return.
if [ -e "$root/private/rollback" ] || [ -L "$root/private/rollback" ] || [ -e "$root/private/rollback.cleanup" ] || [ -L "$root/private/rollback.cleanup" ]; then
    fail 'transaction state retained; resolve explicitly before uninstall'
fi
active=false
if [ -e "$unit" ] || [ -L "$unit" ]; then
    if systemctl is-active --quiet tg-sentry.service; then active=true; fi
    systemctl stop tg-sentry.service
fi
# Core owns exact-resource removal and managed-reference refusal, not shell.
if ! "$app/aegishook" ctl system-uninstall "$@" >/dev/null 2>&1; then
    if "$active"; then
        systemctl start tg-sentry.service || fail 'uninstall refused; service restoration also failed'
    fi
    fail 'uninstall refused; managed references or foreign/modified machine state retained'
fi
if [ -e "$unit" ] || [ -L "$unit" ]; then
    systemctl disable tg-sentry.service
    rm -- "$unit"
fi
systemctl daemon-reload
rm -f -- "$app/aegishook" "$app/uninstall.sh"
# Leave empty locks/directories; never recursively remove private state or hooks.
# A retained directory also remains a safe destination for a subsequent install.
printf '%s\n' 'Uninstalled; machine directories and unrelated files retained.'
