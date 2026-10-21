#!/bin/sh
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
fail() { printf '%s\n' "$1" >&2; exit 1; }
[ "$(id -u)" -eq 0 ] || fail 'installation requires root'
[ "$#" -eq 0 ] || fail 'usage: install.sh'
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
app=/opt/tg-sentry
root=/var/opt/tg-sentry
unit=/etc/systemd/system/tg-sentry.service
for file in opt/tg-sentry/aegishook opt/tg-sentry/uninstall.sh etc/systemd/system/tg-sentry.service; do
    if [ ! -f "$here/$file" ] || [ -L "$here/$file" ]; then
        fail 'package payload missing or not a regular file'
    fi
done
# Build-bound public bytes, following packaging/macos/payload/uninstall.sh.
# Validate both the incoming payload and any existing targets before side effects.
for file in "$app/aegishook" "$unit"; do
    case "$file" in
        "$app/aegishook") expected='@BINARY_SHA256@'; source=opt/tg-sentry/aegishook ;;
        "$unit") expected='@UNIT_SHA256@'; source=etc/systemd/system/tg-sentry.service ;;
    esac
    [ "$(sha256sum "$here/$source" | awk '{print $1}')" = "$expected" ] || fail "package payload $file does not match its build fingerprint"
    if [ -e "$file" ] || [ -L "$file" ]; then
        if [ ! -f "$file" ] || [ -L "$file" ]; then
            fail "existing $file is not from this package; run its uninstaller or remove it explicitly"
        fi
        [ "$(sha256sum "$file" | awk '{print $1}')" = "$expected" ] || fail "existing $file is not from this package; run its uninstaller or remove it explicitly"
    fi
done
# Match the macOS preinstall boundary: do not replace a pending transaction.
# Ownership/private-tree checks remain in ctl, never repaired by this script.
if [ -e "$root/private/rollback" ] || [ -L "$root/private/rollback" ]; then
    if [ ! -f "$root/private/rollback/.committed" ] && [ ! -f "$root/private/rollback/.rolled-back" ]; then
        fail 'pending transaction: explicit ctl commit or rollback required'
    fi
fi
terminal=false
if [ -d "$root/private/rollback.cleanup" ] || [ -f "$root/private/rollback/.committed" ] || [ -f "$root/private/rollback/.rolled-back" ]; then
    terminal=true
fi
# systemctl(1): explicit stop suppresses Restart=always during replacement.
if [ -e "$unit" ] || [ -L "$unit" ]; then
    systemctl stop tg-sentry.service
fi
# GNU install(1); trusted OS-owned /opt and /etc/systemd are preconditions.
# Stage beside each destination so mv publishes complete root-owned bytes.
install -d -o root -g root -m 755 "$app"
staged=''
trap '[ -z "$staged" ] || rm -f -- "$staged"' 0
trap 'exit 1' HUP INT TERM
for file in aegishook uninstall.sh; do
    staged=$(mktemp "$app/.install.XXXXXX")
    install -o root -g root -m 755 "$here/opt/tg-sentry/$file" "$staged"
    mv -fT -- "$staged" "$app/$file"
    staged=''
done
staged=$(mktemp /etc/systemd/system/.tg-sentry.XXXXXX)
install -o root -g root -m 644 "$here/etc/systemd/system/tg-sentry.service" "$staged"
mv -fT -- "$staged" "$unit"
staged=''
# Core validates before reading config/setup-code; keep enrollment out of logs.
if ! "$app/aegishook" ctl system-install >/dev/null 2>&1; then
    fail 'machine installation failed; private retry state retained'
fi
# Core returns after disposing terminal snapshots; re-enter to refresh manifest.
if "$terminal"; then
    if ! "$app/aegishook" ctl system-install >/dev/null 2>&1; then
        fail 'machine installation after terminal cleanup failed; retry state retained'
    fi
fi
systemctl daemon-reload
systemctl enable tg-sentry.service
systemctl start tg-sentry.service
# Type=simple start is not readiness/enrollment evidence. Never commit implicitly.
printf '%s\n' 'Installed; verify ctl status --require enrolled before explicit ctl commit.'
