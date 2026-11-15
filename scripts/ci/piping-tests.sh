#!/bin/sh
# The Piping Server carrier of pod-piping (T-032) against nwtgck's two
# servers on 127.0.0.1: nwtgck/piping-server 1.12.9, the server of ppng.io,
# from the packages that scripts/ci/piping-server/package-lock.json pins,
# each by its integrity hash, installed by `npm ci` with no install
# scripts; and the release archive of nwtgck/piping-server-rust 0.18.0 for
# Linux x86_64 (a static binary), checked by the SHA-256 that its
# sha256sums.txt names (scripts/ci/fetch-tool.sh). tests/piping.rs starts
# each server on a free port of the loopback. A test whose server is not
# there says "did not run", which fails this script, so the check cannot
# pass by a skip. It needs node and npm. The files go to RUNNER_TEMP, else
# TMPDIR, else /tmp.
set -eu
cd "$(dirname "$0")/../.." || exit 71
root=$(pwd)
version=0.18.0
sha256=4a17e197829c3f56e47316cc9e02d72113f266671561f285c853e36fbbc60863
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) ;;
    *) echo "piping-tests: the pinned archive is for Linux x86_64 alone" >&2; exit 1 ;;
esac
tmp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
name=piping-server-x86_64-unknown-linux-musl
rust=$tmp/piping-server-rust-$version
sh scripts/ci/fetch-tool.sh \
    "https://github.com/nwtgck/piping-server-rust/releases/download/v$version/$name.tar.gz" \
    "$sha256" "./$name/piping-server" "$rust"
js=$(mktemp -d "$tmp/piping-server-js.XXXXXX")
trap 'rm -rf "$js"' EXIT
cp scripts/ci/piping-server/package.json scripts/ci/piping-server/package-lock.json "$js/"
(cd "$js" && sh "$root/scripts/retry.sh" npm ci --ignore-scripts --no-audit --no-fund --omit=optional)
out=$(POD_PIPING_TEST_JS="$js/node_modules/.bin/piping-server" POD_PIPING_TEST_RUST="$rust/piping-server" \
    cargo test --locked -p pod-piping --test piping -- --nocapture 2>&1) || { printf '%s\n' "$out"; exit 1; }
printf '%s\n' "$out"
if printf '%s\n' "$out" | grep -q 'did not run'; then
    echo "piping-tests: a test did not run" >&2
    exit 1
fi
