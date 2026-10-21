#!/bin/bash
# Inspection is unprivileged. Lifecycle mode is ONLY for a disposable native runner.
set -eu
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
here=$(CDPATH='' cd -- "$(dirname -- "$0")" && pwd)
root='/Library/Application Support/TG-Sentry'
plist=/Library/LaunchDaemons/com.tg-sentry.endpoint.plist
label=system/com.tg-sentry.endpoint

fail() { printf '%s\n' "$1" >&2; exit 1; }
check_scripts() {
    for script in build-pkg.sh scripts/preinstall scripts/postinstall payload/uninstall.sh test-pkg.sh; do
        [ -f "$here/$script" ] || fail "missing script: $script"
        /bin/bash -n "$here/$script"
        /bin/sh -n "$here/$script"
    done
}
inspect() {
    package=$1
    work=$(mktemp -d "${TMPDIR:-/tmp}/tg-sentry-pkg-test.XXXXXX")
    trap 'rm -rf -- "$work"' EXIT
    # Apple pkgutil(1), FILE COMMANDS. Never installs or opens a receipt database.
    /usr/sbin/pkgutil --expand "$package" "$work/expanded"
    /usr/sbin/pkgutil --payload-files "$package" > "$work/files"
    for path in 'Library/Application Support/TG-Sentry/aegishook' \
        'Library/Application Support/TG-Sentry/uninstall.sh' \
        'Library/LaunchDaemons/com.tg-sentry.endpoint.plist'; do
        grep -Fx "./$path" "$work/files" >/dev/null || fail "missing payload: $path"
    done
    ! grep -E '(^|/)(private|run)(/|$)' "$work/files" || fail 'runtime state in payload'
    # pkgutil also lists AppleDouble metadata entries (._*) on current macOS;
    # expand-full decodes them. They are not additional runnable payload files.
    component="$work/expanded/endpoint.pkg"
    [ -f "$component/PackageInfo" ] || fail 'missing component package'
    grep 'identifier="com.tg-sentry.endpoint"' "$component/PackageInfo" >/dev/null
    grep 'install-location="/"' "$component/PackageInfo" >/dev/null
    /usr/bin/lsbom -p fmug "$component/Bom" > "$work/bom"
    awk -F '\t' '
        $3 != 0 || $4 != 0 { exit 1 }
        $2 ~ /^40/ && $2 != "40755" { exit 1 }
        $1 ~ /\/aegishook$/ || $1 ~ /\/uninstall.sh$/ { n++; if ($2 != "100755" || $3 != 0 || $4 != 0) exit 1 }
        $1 ~ /\/com.tg-sentry.endpoint.plist$/ { n++; if ($2 != "100644" || $3 != 0 || $4 != 0) exit 1 }
        END { if (n != 3) exit 1 }
    ' "$work/bom" || fail 'incorrect payload ownership or modes'
    # expand-full also decodes Payload and Scripts, without running either.
    /usr/sbin/pkgutil --expand-full "$package" "$work/full"
    for script in preinstall postinstall; do
        path="$work/full/endpoint.pkg/Scripts/$script"
        [ -x "$path" ] || fail "missing executable installer script: $script"
        /bin/bash -n "$path"
        /bin/sh -n "$path"
        cmp "$here/scripts/$script" "$path"
    done
    app="$work/full/endpoint.pkg/Payload$root"
    binary_hash=$(shasum -a 256 "$app/aegishook" | awk '{print $1}')
    plist_hash=$(shasum -a 256 "$work/full/endpoint.pkg/Payload$plist" | awk '{print $1}')
    sed -e "s/@BINARY_SHA256@/$binary_hash/g" -e "s/@PLIST_SHA256@/$plist_hash/g" \
        "$here/payload/uninstall.sh" > "$work/expected-uninstall"
    cmp "$work/expected-uninstall" "$app/uninstall.sh"
    cmp "$here/launchd/com.tg-sentry.endpoint.plist" \
        "$work/full/endpoint.pkg/Payload$plist"
    /usr/bin/plutil -lint "$work/full/endpoint.pkg/Payload$plist"
    printf '%s\n' 'PASS: package layout, root:wheel, modes, scripts and LaunchDaemon bytes'
    rm -rf -- "$work"
    trap - EXIT
}
script_behavior() {
    # Stdlib-only harness. Rewrites COPIES into a temporary fixture; never runs
    # installer/launchctl or touches /Library. Production has no test override.
    /usr/bin/python3 - "$here" <<'PY'
import hashlib
import os
from pathlib import Path
import subprocess
import sys
import tempfile

source = Path(sys.argv[1])
with tempfile.TemporaryDirectory(prefix="tg-sentry-script-", dir=os.environ.get("TMPDIR")) as temp:
    base = Path(temp)
    root = base / "app"
    plist = base / "endpoint.plist"
    log = base / "calls"
    launch = base / "launchctl"
    launch.write_text('''#!/bin/bash
set -eu
printf '%s\\n' "launchctl $*" >> "$FIXTURE/calls"
case $1 in
 print) test -f "$FIXTURE/loaded";;
 bootout) test "${BOOTOUT_FAIL:-0}" = 0; rm "$FIXTURE/loaded";;
 bootstrap) touch "$FIXTURE/loaded";;
esac
''')
    launch.chmod(0o755)
    binary_text = '''#!/bin/bash
set -eu
printf '%s\\n' "$*" >> "$FIXTURE/calls"
case $2 in
 system-install)
  test "${INSTALL_FAIL:-0}" = 0
  test ! -d "$FIXTURE/app/private/rollback" || test -f "$FIXTURE/app/private/rollback/.committed" || exit 2
  rm -rf "$FIXTURE/app/private/rollback.cleanup" "$FIXTURE/app/private/rollback"
  ;;
 status) exit "${STATUS:-0}";;
 commit) test "${COMMIT_FAIL:-0}" = 0; rm -f "$FIXTURE/app/private/enrolled.json";;
 system-uninstall)
  if test -d "$FIXTURE/app/private/rollback.cleanup"; then
   rm -rf "$FIXTURE/app/private/rollback.cleanup"
   exit 0
  fi
  test "${UNINSTALL_FAIL:-0}" = 0
  test ! -f "$FIXTURE/managed-reference"
  rm -f "$FIXTURE/app/private/enrolled.json" "$FIXTURE/app/run/ctl.sock"
  ;;
esac
'''
    def fixture():
        import shutil
        shutil.rmtree(root, ignore_errors=True)
        root.mkdir()
        (root / "private").mkdir(mode=0o700)
        (root / "run").mkdir()
        (root / "aegishook").write_text(binary_text)
        (root / "aegishook").chmod(0o755)
        (root / "uninstall.sh").write_text("fixture")
        (root / "private/enrolled.json").write_text("retry sentinel")
        plist.write_text("fixture plist")
        log.write_text("")
        (base / "loaded").unlink(missing_ok=True)
        (root / "run/ctl.sock").touch()
    def run(name, race_cleanup=False, **overrides):
        text = (source / name).read_text()
        if race_cleanup:
            # Deterministic repair race: the shell has observed the sibling, but
            # it disappears before executing the chosen branch or any ctl verb.
            check = 'if [ -e "$root/private/rollback.cleanup" ] || [ -L "$root/private/rollback.cleanup" ]; then'
            assert check in text
            text = text.replace(check, check + '\n    rm -rf -- "$root/private/rollback.cleanup"\n    : > "$FIXTURE/cleanup-race-fired"', 1)
        text = text.replace("/Library/Application Support/TG-Sentry", str(root))
        text = text.replace("/Library/LaunchDaemons/com.tg-sentry.endpoint.plist", str(plist))
        text = text.replace("/bin/launchctl", str(launch))
        text = text.replace('[ ! -S "$root/run/ctl.sock" ]', '[ ! -e "$root/run/ctl.sock" ]')
        text = text.replace('exit 0 if -S $path;', 'exit 0 if -e $path;')
        text = text.replace('$(id -u)', '0').replace('$(stat -f %u "$dir")', '0').replace('$(stat -f %u "$file")', '0')
        text = text.replace("@BINARY_SHA256@", hashlib.sha256(binary_text.encode()).hexdigest())
        text = text.replace("@PLIST_SHA256@", hashlib.sha256(plist.read_bytes()).hexdigest())
        copy = base / "script"
        copy.write_text(text)
        result = subprocess.run(["/bin/bash", str(copy), "pkg", "/", "/"] if name.startswith("scripts/") else ["/bin/bash", str(copy)], env={**os.environ, "FIXTURE": str(base), **overrides}, capture_output=True)
        (base / "stderr").write_bytes(result.stderr)
        return result.returncode, log.read_text().splitlines()
    for status in (0, 30, 20, 2):
        fixture()
        code, calls = run("scripts/postinstall", STATUS=str(status))
        assert (code == 0) == (status in (0, 30)), (status, code)
        assert ("ctl commit" in calls) == (status == 0), calls
        if status == 0:
            assert calls.index("ctl status --require enrolled") < calls.index("ctl commit")
        assert (root / "private/enrolled.json").exists() == (status != 0)
    fixture()
    # Real elapsed-time regression: socket appears after the old 15s cutoff but
    # within the composed 25s budget. Only the backend/socket is a test double.
    import threading
    import time
    (root / "run/ctl.sock").unlink()
    ready = threading.Timer(16, lambda: (root / "run/ctl.sock").touch())
    started = time.monotonic()
    ready.start()
    try:
        code, calls = run("scripts/postinstall")
        assert code == 0 and "ctl commit" in calls, (code, calls)
        assert time.monotonic() - started >= 16
    finally:
        ready.cancel()
        ready.join()
    fixture()
    code, calls = run("scripts/postinstall", INSTALL_FAIL="1")
    assert code != 0 and "ctl commit" not in calls and not any("bootstrap" in x for x in calls)
    fixture()
    code, calls = run("scripts/postinstall", COMMIT_FAIL="1")
    assert code != 0 and (root / "private/enrolled.json").exists()
    fixture()
    (root / "private/rollback.cleanup").mkdir()
    code, calls = run("scripts/postinstall")
    assert code == 0 and calls.count("ctl system-install") == 2, calls
    fixture()
    (root / "private/rollback").mkdir()
    (root / "private/rollback/sentinel").write_text("pending")
    code, calls = run("scripts/postinstall")
    assert code != 0 and (root / "private/rollback/sentinel").exists() and "ctl commit" not in calls
    fixture()
    # id/owner checks above are isolated; these test path shape and control flow.
    code, calls = run("scripts/preinstall")
    assert code == 0 and not any("bootout" in x for x in calls), calls
    (base / "loaded").touch()
    code, calls = run("scripts/preinstall", BOOTOUT_FAIL="1")
    assert code != 0 and (base / "loaded").exists()
    fixture()
    (base / "loaded").touch()
    code, calls = run("scripts/preinstall")
    assert code == 0 and not (base / "loaded").exists()
    fixture()
    (root / "private/rollback").mkdir()
    code, calls = run("scripts/preinstall")
    assert code != 0 and calls == []
    fixture()
    (root / "private").chmod(0o777)
    code, calls = run("scripts/preinstall")
    assert code != 0 and calls == []
    fixture()
    (root / "aegishook").unlink()
    (root / "aegishook").symlink_to(launch)
    code, calls = run("scripts/preinstall")
    assert code != 0 and calls == []
    fixture()
    (base / "loaded").touch()
    code, calls = run("payload/uninstall.sh", UNINSTALL_FAIL="1")
    assert code != 0 and (root / "aegishook").exists() and (base / "loaded").exists(), calls
    assert any("bootstrap" in x for x in calls)
    cleanup_refusal = b'terminal cleanup pending; run aegishook ctl repair and retry uninstall\n'
    for race in (False, True):
        fixture()
        (root / "private/rollback.cleanup").mkdir()
        (base / "loaded").touch()
        code, calls = run("payload/uninstall.sh", race_cleanup=race)
        assert code != 0 and (base / "stderr").read_bytes() == cleanup_refusal, (code, calls)
        assert calls == [], calls  # Neither launchctl nor any ctl verb may run.
        assert (root / "aegishook").exists() and plist.exists() and (base / "loaded").exists()
        assert (root / "private/rollback.cleanup").exists() == (not race)
        if race:
            assert (base / "cleanup-race-fired").exists()
    fixture()
    (base / "loaded").touch()
    code, calls = run("payload/uninstall.sh")
    assert code == 0 and not root.exists() and not plist.exists(), calls
    assert calls.index("launchctl bootout system/com.tg-sentry.endpoint") < calls.index("ctl system-uninstall"), calls
    guard_binary = base / "guard-binary"
    refusal = "client install cannot use the package binary; use hook.sh or hook.ps1 to create a verified private copy"
    for kind in ("guarded", "removed", "mutated"):
        message = refusal if kind != "removed" else "endpoint unavailable"
        mutate = 'touch "$HOME/.aegishook-client/mutated"\n' if kind == "mutated" else ""
        guard_binary.write_text('#!/bin/bash\n' + mutate + "printf '%s\\n' '" + message + "' >&2\nexit 1\n")
        guard_binary.chmod(0o755)
        result = subprocess.run(["/bin/bash", str(source / "test-pkg.sh"), "--assert-package-guard", str(guard_binary)], capture_output=True)
        assert (result.returncode == 0) == (kind == "guarded"), (kind, result.returncode)
print("PASS: isolated script control flow, stalled readiness, cleanup refusal/race and guard mutations (no root, install or real launchctl)")
PY
}
status_code() {
    status=0
    "$root/aegishook" ctl status --require "$1" >/dev/null 2>&1 || status=$?
    [ "$status" -eq "$2" ] || fail "unexpected $1 status: $status (expected $2)"
}
assert_package_guard() {
    guard=$(mktemp -d "${TMPDIR:-/tmp}/tg-sentry-guard-test.XXXXXX")
    trap 'rm -rf -- "$guard"' EXIT
    mkdir -p "$guard/state/home/.aegishook-client" "$guard/state/project/.claude"
    printf '%s\n' 'private client sentinel' > "$guard/state/home/.aegishook-client/sentinel"
    printf '%s\n' '{"sentinel":"unchanged"}' > "$guard/state/project/.claude/settings.json"
    hook_state() {
        find "$guard/state" -exec stat -f '%N %p %u %g' {} \;
        find "$guard/state" -type f -exec shasum -a 256 {} \;
    }
    hook_state > "$guard/before"
    guard_status=0
    # Valid agent/scope/project/endpoint and synthetic code; a removed guard must
    # NOT pass just because a missing endpoint caused some unrelated failure.
    printf '%064d\n' 0 | HOME="$guard/state/home" "$1" client install \
        --agent claude --scope project --project "$guard/state/project" \
        --client-dir "$guard/state/home/.aegishook-client" \
        --endpoint http://127.0.0.1:1 --code-stdin > "$guard/stdout" 2> "$guard/stderr" || guard_status=$?
    [ "$guard_status" -eq 1 ] || fail 'package client guard returned the wrong exit code'
    [ ! -s "$guard/stdout" ] || fail 'package client guard produced unexpected stdout'
    [ "$(cat "$guard/stderr")" = 'client install cannot use the package binary; use hook.sh or hook.ps1 to create a verified private copy' ] || fail 'package-specific client refusal was not reached'
    hook_state > "$guard/after"
    cmp "$guard/before" "$guard/after" || fail 'package client guard modified user-hook state'
    rm -rf -- "$guard"
    trap - EXIT
}
native() {
    [ "$(id -u)" -eq 0 ] || fail 'native lifecycle requires runner root; do not use sudo here'
    [ "${TG_SENTRY_NATIVE_DISPOSABLE:-}" = 1 ] || fail 'native lifecycle requires an explicitly disposable runner'
    [ ! -e "$root" ] && [ ! -L "$root" ] || fail 'native lifecycle requires a clean machine root'
    [ ! -e "$plist" ] && [ ! -L "$plist" ] || fail 'native lifecycle requires no prior plist'
    if /bin/launchctl print "$label" >/dev/null 2>&1; then fail 'daemon already registered'; fi
    # T5 fresh, duplicate, then upgrade if a second package is supplied.
    /usr/sbin/installer -pkg "$1" -target /
    status_code installed 0
    status_code service 0
    status_code enrolled 30
    [ "$(stat -f '%u:%g:%Lp' "$root/private")" = 0:0:700 ]
    identity=$(shasum -a 256 "$root/private/client.json")
    node=$(/usr/bin/plutil -extract nodeId raw -o - "$root/private/client.json")
    /usr/sbin/installer -pkg "$1" -target /
    [ "$(shasum -a 256 "$root/private/client.json")" = "$identity" ]
    if [ "$#" -eq 2 ]; then
        /usr/sbin/installer -pkg "$2" -target /
        status_code service 0
        [ "$(/usr/bin/plutil -extract nodeId raw -o - "$root/private/client.json")" = "$node" ]
    else
        printf '%s\n' 'NOT RUN: distinct-version upgrade (supply second PKG)'
    fi
    # T8: main.go maps refusePackageClient's exact error to exit 1. Compare the
    # package-specific message and full isolated user-hook state, not any failure.
    assert_package_guard "$root/aegishook"
    # Use a documented managed destination, only on this explicitly clean runner.
    managed='/Library/Application Support/ClaudeCode/managed-settings.json'
    [ ! -e "$managed" ] && [ ! -L "$managed" ] || fail 'managed fixture destination already exists'
    mkdir -p -- "$(dirname -- "$managed")"
    printf '{"reference":"%s/aegishook"}\n' "$root" > "$managed"
    managed_hash=$(shasum -a 256 "$managed")
    if "$root/uninstall.sh"; then fail 'managed reference did not block uninstall'; fi
    [ -f "$root/aegishook" ] && [ "$(shasum -a 256 "$managed")" = "$managed_hash" ]
    rm -- "$managed"
    # T8 unmanaged data blocks removal, preserving the payload. A core refusal
    # can already have removed owned state; bootstrap restores registration only.
    printf '%s\n' 'foreign native-test sentinel' > "$root/private/foreign-test"
    chmod 600 "$root/private/foreign-test"
    if "$root/uninstall.sh"; then fail 'foreign state did not block uninstall'; fi
    [ -f "$root/aegishook" ] && [ -f "$root/private/foreign-test" ]
    rm "$root/private/foreign-test"
    # Restore manifest/resources if the ownership-exact refusal removed owned data.
    /usr/sbin/installer -pkg "${2:-$1}" -target /
    "$root/uninstall.sh"
    [ ! -e "$root/aegishook" ] && [ ! -e "$plist" ]
    if /bin/launchctl print "$label" >/dev/null 2>&1; then fail 'daemon survived uninstall'; fi
    printf '%s\n' 'PASS: native unprovisioned fresh/duplicate and foreign-retention/uninstall'
    printf '%s\n' 'NOT RUN: provisioned identity/cache upgrade, injected failure/retry, managed-hook fixtures, different runtime user, reboot/KeepAlive; require release-runner fixtures'
}

case ${1:-} in
    --check-scripts) [ "$#" -eq 1 ]; check_scripts ;;
    --script-behavior) [ "$#" -eq 1 ]; check_scripts; script_behavior ;;
    --assert-package-guard) [ "$#" -eq 2 ]; assert_package_guard "$2" ;;
    --inspect) [ "$#" -eq 2 ]; check_scripts; inspect "$2" ;;
    '') fail 'usage: test-pkg.sh --check-scripts | --inspect PKG | PKG [UPGRADE_PKG] (disposable native runner)' ;;
    *) [ "$#" -le 2 ]; check_scripts; inspect "$1"; native "$@" ;;
esac
