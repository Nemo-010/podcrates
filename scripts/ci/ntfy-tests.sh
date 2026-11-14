#!/bin/sh
# The meeting point of pod-wormhole at an ntfy server (T-554, call C572)
# against ntfy's own server: the release archive of ntfy 2.37.2 for Linux
# x86_64 (a static binary), checked by the SHA-256 that its checksums.txt
# names (scripts/ci/fetch-tool.sh). The script starts `ntfy serve` on
# 127.0.0.1 alone with its cache in a file, and runs tests/ntfy.rs against
# it. POD_WORMHOLE_TEST_NTFY_SERVER=required makes a skip a failure, and the
# run must say that ntfy paired two ends, so the check cannot pass by a
# skip. The archive goes to RUNNER_TEMP, else TMPDIR, else /tmp.
set -eu
cd "$(dirname "$0")/../.." || exit 71
version=2.37.2
sha256=e67f53d7fbed529b83faf3993b584110921ef3567b0ac0b033c6910879a4ffd1
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) ;;
    *) echo "ntfy-tests: the pinned archive is for Linux x86_64 alone" >&2; exit 1 ;;
esac
tmp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
dir=$tmp/ntfy-$version
name=ntfy_${version}_linux_amd64
sh scripts/ci/fetch-tool.sh \
    "https://github.com/binwiederhier/ntfy/releases/download/v$version/$name.tar.gz" \
    "$sha256" "$name/ntfy" "$dir"
work=$(mktemp -d "$tmp/ntfy-tests.XXXXXX")
pid=
stop() {
    if [ -n "$pid" ]; then
        kill "$pid" 2> /dev/null || true
        wait "$pid" 2> /dev/null || true
    fi
    rm -rf "$work"
}
trap stop EXIT
trap 'exit 1' INT TERM
port=28417
# An empty configuration: the defaults of a server with no account, the
# limits of a visitor of ntfy.sh, and a cache that keeps each message.
: > "$work/server.yml"
"$dir/ntfy" serve --config "$work/server.yml" --listen-http "127.0.0.1:$port" \
    --cache-file "$work/cache.db" --base-url "http://127.0.0.1:$port" \
    > "$work/ntfy.log" 2>&1 &
pid=$!
ready=0
for _ in $(seq 1 60); do
    code=$(curl -qsS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' \
        "http://127.0.0.1:$port/v1/health" 2> /dev/null) || code=000
    if [ "$code" = 200 ]; then
        ready=1
        break
    fi
    if ! kill -0 "$pid" 2> /dev/null; then
        break
    fi
    sleep 1
done
if [ "$ready" != 1 ]; then
    cat "$work/ntfy.log" >&2
    echo "ntfy-tests: ntfy did not answer /v1/health (last status $code)" >&2
    exit 1
fi
out=$(POD_WORMHOLE_TEST_NTFY_SERVER=required POD_WORMHOLE_TEST_NTFY="http://127.0.0.1:$port/" \
    cargo test --locked -p pod-wormhole --features standin --test ntfy -- --nocapture 2>&1) ||
    { printf '%s\n' "$out"; tail -n 50 "$work/ntfy.log" >&2; exit 1; }
printf '%s\n' "$out"
if ! printf '%s\n' "$out" | grep -qxF 'binwiederhier/ntfy: two ends paired'; then
    echo "ntfy-tests: no test paired two ends through ntfy" >&2
    exit 1
fi
