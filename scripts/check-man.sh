#!/bin/sh
# The man page of a command line of pod-manual against two man(7)
# renderers that pod-manual did not write: groff and mandoc.
#
#   sh scripts/check-man.sh BINARY
#
# BINARY runs here: `BINARY man --roff` writes the page and `BINARY man
# --json` gives each flag. The checks: groff -ww gives no warning; mandoc
# -Tlint gives no warning; each flag spelling of the JSON is in the text of
# both renderings; a planted page with no term of one flag fails the same
# check, so the check is not vacuous. Each check prints ok or FAIL.
#
# Exit 0: each check holds. Exit 1: a check failed. Exit 2: groff, mandoc
# or python3 is missing, or the binary does not give its page.

set -u
B=${1:?usage: sh scripts/check-man.sh BINARY}
for t in groff mandoc python3; do
    command -v "$t" > /dev/null || { echo "check-man: no $t" >&2; exit 2; }
done
W=$(mktemp -d)
trap 'rm -rf "$W"' EXIT
fail=0
ok() { echo "ok   $1: $2"; }
bad() { echo "FAIL $1: $2"; [ -n "${3:-}" ] && sed 's/^/     /' "$3"; fail=1; }

"$B" man --roff > "$W/page.1" || { echo "check-man: $B man --roff failed" >&2; exit 2; }
"$B" man --json > "$W/manual.json" || { echo "check-man: $B man --json failed" >&2; exit 2; }
python3 -I -c '
import json, sys
m = json.load(open(sys.argv[1]))
for c in m["commands"]:
    for f in c["flags"]:
        if f.get("long"):
            print("--" + f["long"])
        if f.get("short"):
            print("-" + f["short"])
' "$W/manual.json" | sort -u > "$W/flags.txt"
count=$(wc -l < "$W/flags.txt")
[ "$count" -ge 2 ] || { echo "check-man: only $count flags in the JSON" >&2; exit 2; }

bs=$(printf '\b')
# render PAGE: PAGE.groff and PAGE.mandoc, as plain text.
render() {
    groff -man -Tascii -P-cbu -rLL=300n -ww "$1" > "$1.groff" 2> "$1.groff.err" || return 1
    mandoc -Tascii -Owidth=300 "$1" > "$1.mandoc.raw" || return 1
    sed "s/.$bs//g" "$1.mandoc.raw" > "$1.mandoc"
}
# missing PAGE: each flag spelling that a rendering lacks, in PAGE.missing.
missing() {
    : > "$1.missing"
    for r in groff mandoc; do
        while IFS= read -r f; do
            grep -qe "$f\\b" "$1.$r" || echo "$r lacks $f" >> "$1.missing"
        done < "$W/flags.txt"
    done
}

if render "$W/page.1"; then
    missing "$W/page.1"
    if [ -s "$W/page.1.missing" ]; then
        bad render.flags "a rendering lacks a flag:" "$W/page.1.missing"
    else
        ok render.flags "groff and mandoc show each of the $count flag spellings"
    fi
    if [ -s "$W/page.1.groff.err" ]; then
        bad render.groff "groff -ww warns:" "$W/page.1.groff.err"
    else
        ok render.groff "groff -ww: no warning"
    fi
else
    bad render.flags "groff or mandoc cannot render the page"
fi
if mandoc -Tlint -W warning "$W/page.1" > "$W/lint.txt" 2>&1; then
    ok lint "mandoc -Tlint -W warning: no warning"
else
    bad lint "mandoc -Tlint:" "$W/lint.txt"
fi

# The plant: the page with no line that holds the term of the first long
# flag. The check must fail.
first=$(grep -e '^--' "$W/flags.txt" | head -n 1)
term=$(printf '%s' "$first" | sed 's/-/\\-/g')
grep -vF "\\fB$term\\fR" "$W/page.1" > "$W/planted.1"
if render "$W/planted.1"; then
    missing "$W/planted.1"
    if grep -qe "lacks $first\$" "$W/planted.1.missing"; then
        ok plant "a page with no term of $first fails"
    else
        bad plant "a page with no term of $first passed: the check is vacuous"
    fi
else
    bad plant "the planted page does not render"
fi
[ "$fail" -eq 0 ] || exit 1
