#!/bin/sh
# The meeting point of pod-wormhole at a WebTorrent tracker (T-551) against
# webtorrent/bittorrent-tracker: the release and the packages that
# scripts/ci/bittorrent-tracker/package-lock.json pins, each by its
# integrity hash, installed by `npm ci` with no install scripts, and its
# WebSocket on 127.0.0.1 alone. POD_WORMHOLE_TEST_WEBTORRENT=required makes
# a skip a failure, and the run must say that bittorrent-tracker paired two
# ends, so the check cannot pass by a skip. It needs node and npm.
set -eu
cd "$(dirname "$0")/../.." || exit 71
root=$(pwd)
port=8417
dir="${RUNNER_TEMP:-${TMPDIR:-/tmp}}/pod-wormhole-tracker-$$"
mkdir -p "$dir"
cp scripts/ci/bittorrent-tracker/package.json scripts/ci/bittorrent-tracker/package-lock.json \
    scripts/ci/bittorrent-tracker/serve.mjs "$dir/"
(cd "$dir" && sh "$root/scripts/retry.sh" npm ci --ignore-scripts --no-audit --no-fund --omit=optional)
node "$dir/serve.mjs" "$port" > "$dir/tracker.log" 2>&1 &
pid=$!
trap 'kill "$pid" 2> /dev/null || true; tail -n 40 "$dir/tracker.log"; rm -rf "$dir"' EXIT
# Wait for the listener, at most 60 s.
python3 -I - "$port" <<'PY'
import socket, sys, time
deadline = time.monotonic() + 60
while True:
    try:
        socket.create_connection(("127.0.0.1", int(sys.argv[1])), 1).close()
        break
    except OSError:
        if time.monotonic() > deadline:
            sys.exit("tracker-tests: bittorrent-tracker did not listen within 60 s")
        time.sleep(0.5)
PY
out=$(POD_WORMHOLE_TEST_WEBTORRENT=required POD_WORMHOLE_TEST_TRACKER="ws://127.0.0.1:$port/" \
    cargo test --locked -p pod-wormhole --features standin --test tracker -- --nocapture 2>&1) || { printf '%s\n' "$out"; exit 1; }
printf '%s\n' "$out"
if ! printf '%s\n' "$out" | grep -q '^webtorrent/bittorrent-tracker: two ends paired'; then
    echo "tracker-tests: no test paired two ends through bittorrent-tracker" >&2
    exit 1
fi
