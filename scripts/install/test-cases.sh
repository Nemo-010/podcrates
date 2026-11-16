#!/bin/sh
# SPDX-License-Identifier: 0BSD
# More cases of scripts/install/test.sh, which includes this file and gives
# its functions and variables: downloaders, proxy, exe and sig.
# shellcheck disable=SC2154,SC2034 # test.sh sets and reads each variable.

c_downloaders() {
    for d in curl wget python3 busybox; do
        p=$work/p-dl-$d
        # shellcheck disable=SC2086 # osenv is a list of words.
        if ! (env -i $osenv PATH="$PATH" PODLAB_DOWNLOADER=$d INST_NAME=podlab INST_ENV=PODLAB sh -c ". '$here/core.sh'; . '$here/core-net.sh'; inst_detect_downloader" > /dev/null 2>&1); then
            skip "$d" "downloaders: $d is not on this host"
            continue
        fi
        env="PODLAB_DOWNLOADER=$d"
        first sh "$p"
        reset
        expect "downloader: $d" "the run names its downloader"
        [ "$d" != busybox ] || expect 'warning: busybox wget' "the warning of busybox wget"
        ok "downloaders: $d"
    done
}

c_proxy() {
    # A shim of each downloader logs its argv; the proxy is the mirror.
    mkdir -p "$work/argv"
    for d in curl wget python3 busybox; do
        real=$(command -v "$d") || { skip "$d" "proxy: $d is not on this host"; continue; }
        printf '#!/bin/sh\nprintf "%%s\\n" "$*" >> "%s"\nexec "%s" "$@"\n' "$work/argv.log" "$real" > "$work/argv/$d"
        chmod 0755 "$work/argv/$d"
        # A made-up credential of the test proxy.
        secret=proxy-test-made-up-secret cred=user:proxy-test-made-up-secret
        p=$work/p-proxy-$d
        : > "$work/argv.log"
        a=$(gets 'proxy auth=yes')
        # No mirror listens on port 9: only the proxy reaches the file.
        xpath=$work/argv mirror=http://127.0.0.1:9/good
        env="http_proxy=http://$cred@127.0.0.1:$port PODLAB_DOWNLOADER=$d"
        first sh "$p"
        reset
        [ "$(gets 'proxy auth=yes')" -gt "$a" ] || fail "$d did not reach the proxy with its credential"
        [ -s "$work/argv.log" ] || fail "the shim of $d did not run"
        ! grep -q "$secret" "$work/argv.log" || fail "the credential of the proxy is in the argv of $d"
        ! grep -q "$secret" "$work/out" || fail "the credential of the proxy is in the output"
        ! grep -r -q "$secret" "$p" "$work/home" || fail "the credential of the proxy is in a file"
        expect 'proxy: http://127.0.0.1:' "the run names the proxy with no credential"
        ok "proxy: $d through the proxy of the environment; the credential is in no argv, file or output"
    done
}

# The names of Windows on each host: the target of Windows gives
# podlab.exe; a prefix of Windows (C:\...) goes through cygpath.
c_exe() {
    p=$work/p-exe
    env="PODLAB_TARGET=x86_64-pc-windows-msvc"
    run sh "$p" || fail "the install of the .exe of Windows"
    reset
    [ "$(sum "$p/podlab.exe")" = "$(sum "$work/m/good/$wasset")" ] || fail "$p/podlab.exe is not $wasset"
    expect "installed $p/podlab.exe \\($wasset," "the run names the .exe"
    mkdir -p "$work/cyg"
    cat > "$work/cyg/cygpath" << END
#!/bin/sh
# A stand-in of cygpath: one path of Windows to its POSIX form.
[ "\$1" = -u ] && [ "\$2" = 'C:\\pod\\bin' ] && echo '$work/p-drive'
END
    chmod 0755 "$work/cyg/cygpath"
    xpath=$work/cyg
    run sh 'C:\pod\bin' || fail "a prefix of Windows (C:\\pod\\bin) through cygpath"
    reset
    [ -f "$work/p-drive/$bin" ] || fail "the prefix of Windows is not the path of cygpath"
    # curl of Windows ends a line of its error with a CR: the output of the
    # installer stays printable ASCII (run checks it).
    mkdir -p "$work/wcurl"
    printf '#!/bin/sh\nprintf "curl: (22) The requested URL returned error: 404\\r\\n" >&2\nexit 22\n' > "$work/wcurl/curl"
    chmod 0755 "$work/wcurl/curl"
    xpath=$work/wcurl env=PODLAB_DOWNLOADER=curl
    run sh "$work/p-wcurl" && fail "a download that fails installs"
    reset
    expect '^curl: \(22\) The requested URL returned error: 404$' "the reason of curl"
    expect "error: $asset: the download from .* failed \\(curl\\)" "the refusal names the downloader"
    ok "exe: the target of Windows installs podlab.exe; a prefix C:\\... goes through cygpath; the CR of curl is not shown"
}

# The signature of SHA256SUMS: a stand-in of cosign checks its arguments,
# and the SHA-256 of the blob against its stand-in bundle (a line
# "stand-in SHA256"). No network.
sig_mirror() { # DIR: SHA256SUMS of the release and its stand-in bundle
    # shellcheck disable=SC2086 # assets is a list of names.
    python3 -I "$here/pins.py" sums "$1" $assets podlab-install.sh > /dev/null || fail "pins.py sums"
    echo "stand-in $(sum "$1/SHA256SUMS")" > "$1/SHA256SUMS.sigstore.json"
}
c_sig() {
    m=$work/m
    # The issuer is a name in the certificate: the test reaches no host.
    id=https://github.com/PodUtils/podcrates/.github/workflows/release.yml@refs/tags/v$version
    iss=https://token.actions.githubusercontent.com
    cp "$installer" "$m/good/podlab-install.sh"
    sig_mirror "$m/good"
    mkdir -p "$work/cosign" "$m/sig-changed" "$m/sig-other" "$m/sig-nobundle" "$work/sig"
    cat > "$work/cosign/cosign" << END
#!/bin/sh
printf '%s\n' "\$*" >> '$work/cosign.log'
d=\${TUF_ROOT:-\$HOME/.sigstore/root}
mkdir -p "\$d" && : > "\$d/stand-in.json" || exit 3
[ \$# = 8 ] && [ "\$1" = verify-blob ] && [ "\$2" = --bundle ] && [ "\$4" = --certificate-identity ] &&
    [ "\$6" = --certificate-oidc-issuer ] || { echo "Error: stand-in: unknown arguments" >&2; exit 2; }
[ "\$5" = '$id' ] && [ "\$7" = '$iss' ] ||
    { echo "Error: none of the expected identities matched what was in the certificate" >&2; exit 1; }
h=\$($shacmd < "\$8" | cut -d ' ' -f 1)
grep -q -x "stand-in \$h" "\$3" || { echo "Error: invalid signature when validating ASN.1 encoded signature" >&2; exit 1; }
echo "Verified OK" >&2
END
    chmod 0755 "$work/cosign/cosign"
    : > "$work/cosign.log"

    s=$(gets 'get /good/SHA256SUMS$') b=$(gets 'get /good/SHA256SUMS.sigstore.json$')
    xpath=$work/cosign
    first sh "$work/p-sig"
    reset
    expect 'the signature of SHA256SUMS: ok' "the signature check with cosign"
    grep -q -F -e "--certificate-identity $id --certificate-oidc-issuer $iss" "$work/cosign.log" ||
        fail "the signature check with cosign: not the identity $id"
    if [ "$(gets 'get /good/SHA256SUMS$')" != $((s + 1)) ] || [ "$(gets 'get /good/SHA256SUMS.sigstore.json$')" != $((b + 1)) ]; then
        fail "the signature check with cosign: SHA256SUMS and its bundle not downloaded once"
    fi
    [ ! -e "$work/home/.sigstore" ] || fail "cosign wrote a file outside the prefix"
    ok "sig: cosign checks SHA256SUMS for $id, and each pin and the installer agree"

    xpath=$work/cosign
    run sh "$work/p-sig-dry" --dry-run || fail "the dry run with cosign"
    expect 'dry run: .*/SHA256SUMS and its signature, checked with cosign' "the dry run names the check"
    run sh "$work/p-sig-off" --offline "$work/m/good" || fail "the offline run with cosign"
    expect 'offline: the signature of SHA256SUMS is not checked' "the offline run says so"
    reset
    ok "sig: the dry run names the check; the offline run says that it does not check"

    # A changed SHA256SUMS: its signature does not cover it.
    awk 'NR == 1 { $0 = (substr($0, 1, 1) == "0" ? "1" : "0") substr($0, 2) } { print }' \
        "$m/good/SHA256SUMS" > "$m/sig-changed/SHA256SUMS"
    cp "$m/good/SHA256SUMS.sigstore.json" "$m/sig-changed/"
    # A signed SHA256SUMS with another SHA-256 for the asset of this host.
    for f in $assets podlab-install.sh; do cp "$m/good/$f" "$m/sig-other/"; done
    printf 'x' >> "$m/sig-other/$asset"
    sig_mirror "$m/sig-other"
    cp "$m/good/SHA256SUMS" "$m/sig-nobundle/"
    cp "$installer" "$work/sig/podlab-install.sh"
    echo '# changed' >> "$work/sig/podlab-install.sh"
    for c in changed other nobundle installer; do
        p=$work/p-sig-$c
        xpath=$work/cosign mirror=http://127.0.0.1:$port/sig-$c
        [ "$c" != installer ] || { inst=$work/sig/podlab-install.sh mirror=$good; }
        case $c in
            changed) why='a SHA256SUMS that its signature does not cover installs' want='Error: invalid signature' ;;
            other) why='a pin that the signed SHA256SUMS does not hold installs' want="$asset: the pin of this installer does not agree with the signed SHA256SUMS" ;;
            nobundle) why='a SHA256SUMS with no signature installs' want='SHA256SUMS.sigstore.json: the download from .* failed' ;;
            installer) why='a changed installer installs' want='podlab-install.sh is not podlab-install.sh of the signed SHA256SUMS' ;;
        esac
        run sh "$p" && fail "$why"
        reset
        expect "$want" "$why"
        expect 'no file was changed' "$why"
        [ ! -e "$p/$bin" ] || fail "$why"
        [ "$(temps "$p")" = 0 ] || fail "$why: a temporary file stayed"
    done
    ok "sig: a changed SHA256SUMS, a pin that it does not hold, no bundle and a changed installer are refused"

    # A copy with no pins of its own, which sets them at run time before
    # inst_main (as the copy of podnet's tree does from the signed
    # SHA256SUMS), is no asset of the release: it is not compared (T-773).
    awk -v pins="$work/sig/pins.txt" '
        /^# BEGIN PINS/ { print; inpins = 1; next }
        /^# END PINS/ { print "INST_VERSION=\"\""; print "INST_TARGETS=\"\""; print; inpins = 0; close(pins); next }
        inpins { print > pins; next }
        /^inst_main / { while ((getline l < pins) > 0) print l }
        { print }' "$installer" > "$work/sig/tree-install.sh"
    xpath=$work/cosign inst=$work/sig/tree-install.sh
    first sh "$work/p-sig-tree" || fail "a copy with no pins of its own, with cosign"
    reset
    expect 'the signature of SHA256SUMS: ok' "a copy with no pins of its own"
    expect 'this installer holds no pins of its own: it is not compared' "a copy with no pins of its own"
    ok "sig: a copy with no pins of its own takes them at run time, and is not compared with the installer of the release"

    # No cosign on PATH: one note, and the pins check each file.
    s=$(gets 'get /good/SHA256SUMS$')
    first sh "$work/p-sig-none" || fail "the run with no cosign"
    [ "$(grep -c 'the signature of SHA256SUMS is not checked' "$work/out")" = 1 ] || fail "the run with no cosign: not one note"
    expect 'cosign is not on PATH: the signature of SHA256SUMS is not checked; the pins' "the run with no cosign"
    [ "$(gets 'get /good/SHA256SUMS$')" = "$s" ] || fail "the run with no cosign downloaded SHA256SUMS"
    c=$(wc -l < "$work/cosign.log")
    xpath=$work/cosign env=PODLAB_COSIGN=none
    first sh "$work/p-sig-off2" || fail "the run with PODLAB_COSIGN=none"
    reset
    expect 'PODLAB_COSIGN=none: the signature of SHA256SUMS is not checked' "the run with PODLAB_COSIGN=none"
    [ "$(wc -l < "$work/cosign.log")" = "$c" ] || fail "PODLAB_COSIGN=none ran cosign"
    env="PODLAB_COSIGN=$work/no/cosign"
    run sh "$work/p-sig-missing" && fail "a PODLAB_COSIGN that does not exist installs"
    reset
    expect 'PODLAB_COSIGN=.*: no such command' "the refusal names the variable"
    ok "sig: no cosign, or PODLAB_COSIGN=none, gives one note and installs; a missing PODLAB_COSIGN is refused"
}
