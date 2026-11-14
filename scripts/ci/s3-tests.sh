#!/bin/sh
# The s3 carrier of pod-link against SeaweedFS, an S3-compatible server
# (T-623, call C540): the release archive of SeaweedFS 4.53 for Linux
# x86_64, checked by its SHA-256 (scripts/ci/fetch-tool.sh). The script
# starts `weed mini` on 127.0.0.1 alone with the bucket `links` and the
# made-up key of crates/pod-link/src/s3/standin.rs, and runs the test
# target s3_seaweedfs against it. POD_LINK_TEST_S3=required makes a skip
# a failure, and the run must say each line below, so the check cannot
# pass by a skip. The archive goes to RUNNER_TEMP, else TMPDIR, else /tmp.
set -eu
cd "$(dirname "$0")/../.." || exit 71
version=4.53
sha256=d1a7dec9f48d8b33895a0ea8951971defc2dc5312906dcc76fa5a5f74a6ee90d
case "$(uname -s)-$(uname -m)" in
    Linux-x86_64) ;;
    *) echo "s3-tests: the pinned archive is for Linux x86_64 alone" >&2; exit 1 ;;
esac
tmp=${RUNNER_TEMP:-${TMPDIR:-/tmp}}
dir=$tmp/seaweedfs-$version
sh scripts/ci/fetch-tool.sh \
    "https://github.com/seaweedfs/seaweedfs/releases/download/$version/linux_amd64.tar.gz" \
    "$sha256" weed "$dir"
"$dir/weed" version
work=$(mktemp -d "$tmp/s3-tests.XXXXXX")
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
# The key of the tests is made up; the identity may read, write and list,
# and cannot make a bucket.
access=PODLINKTESTKEY
secret=pod-link-test-secret-not-real
cat > "$work/s3.json" << EOF
{"identities": [{"name": "pod-link", "credentials": [{"accessKey": "$access", "secretKey": "$secret"}],
  "actions": ["Read", "Write", "List"]}]}
EOF
mkdir "$work/data"
# Each port is on 127.0.0.1; each gRPC port is the port plus 10000.
port=28333
"$dir/weed" -logdir="$work" mini -dir="$work/data" -ip=127.0.0.1 -ip.bind=127.0.0.1 \
    -master.port=29333 -volume.port=29340 -filer.port=28888 -s3.port=$port \
    -webdav=false -admin.ui=false -admin.port=22535 -admin.port.legacy=0 \
    -s3.port.iceberg=0 -s3.port.lance=0 -master.volumeSizeLimitMB=64 \
    -s3.config="$work/s3.json" -s3.autoCreateBucket=false -bucket=links \
    > "$work/weed.log" 2>&1 &
pid=$!
endpoint=http://127.0.0.1:$port
# Ready: a signed listing of the bucket answers 200. The key goes to curl
# on its standard input, not on its command line.
ready=0
for _ in $(seq 1 60); do
    code=$(printf 'user = "%s:%s"\n' "$access" "$secret" |
        curl -K - -qsS --noproxy '*' --max-time 5 -o /dev/null -w '%{http_code}' \
            --aws-sigv4 "aws:amz:us-east-1:s3" "$endpoint/links?list-type=2" 2> /dev/null) || code=000
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
    cat "$work/weed.log" >&2
    echo "s3-tests: SeaweedFS gave no listing of the bucket links (last status $code)" >&2
    exit 1
fi
out=$(POD_LINK_TEST_S3=required POD_LINK_TEST_S3_ENDPOINT=$endpoint POD_LINK_TEST_S3_BUCKET=links \
    cargo test --locked -p pod-link --all-features --test s3_seaweedfs -- --nocapture 2>&1) ||
    { printf '%s\n' "$out"; tail -n 50 "$work/weed.log" >&2; exit 1; }
printf '%s\n' "$out"
for line in 'seaweedfs: a link carried three streams each way over objects' \
    'seaweedfs: prune removed each object of a session' \
    'seaweedfs: If-None-Match, If-Match and the pages of a listing held' \
    'seaweedfs: a wrong secret got 403 and a missing bucket 404' \
    'seaweedfs: a listener took no session older than its bind' \
    'seaweedfs: the budget ended a session whose peer removed nothing'; do
    if ! printf '%s\n' "$out" | grep -qxF "$line"; then
        echo "s3-tests: the run did not say: $line" >&2
        exit 1
    fi
done
