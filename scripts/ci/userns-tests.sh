#!/bin/sh
# The namespace rung for a caller with no capabilities (T-670): the entry
# of pod-enter in a user namespace (tests/userns.rs) and the leg of
# pod-hostprobe (tests/userns_leg.rs). Each test runs as a user with no
# capabilities: as this user, or as uid 65534 where this user is root.
#
# Ubuntu 24.04 gives an unconfined process a user namespace with no
# capabilities (kernel.apparmor_restrict_unprivileged_userns=1): the
# script sets the value to 0, as root, before the run. uid 65534 must
# reach each test binary: the script copies it into a directory of mode
# 755. A skip line fails the run, so the check cannot pass by a skip.
#
#   sh scripts/ci/userns-tests.sh
set -eu
cd "$(dirname "$0")/../.." || exit 71
as_root() {
    if [ "$(id -u)" = 0 ]; then "$@"; else sudo -n "$@"; fi
}
restrict=/proc/sys/kernel/apparmor_restrict_unprivileged_userns
if [ -f "$restrict" ] && [ "$(cat "$restrict")" != 0 ]; then
    as_root sh -c "echo 0 > $restrict"
fi
bins=$(mktemp -d)
trap 'rm -rf "$bins"' EXIT
chmod 755 "$bins"
rc=0
for spec in "pod-enter userns" "pod-hostprobe userns_leg"; do
    crate=${spec%% *}
    t=${spec#* }
    bin=$(cargo test --locked -p "$crate" --all-features --test "$t" --no-run 2>&1 |
        sed -n "s/.*Executable tests\/$t\.rs (\(.*\))\$/\1/p" | tail -1)
    [ -n "$bin" ] && [ -x "$bin" ] || { echo "userns-tests: no test binary of $crate tests/$t.rs" >&2; exit 1; }
    cp "$bin" "$bins/$t"
    chmod 755 "$bins/$t"
    if ! out=$("$bins/$t" 2>&1); then
        printf '%s\n' "$out"
        echo "userns-tests: $crate tests/$t.rs failed" >&2
        rc=1
        continue
    fi
    printf '%s\n' "$out"
    if printf '%s\n' "$out" | grep -q -e '^skipping' -e '^SKIP:'; then
        echo "userns-tests: $crate tests/$t.rs skipped" >&2
        rc=1
    fi
done
exit $rc
