#!/bin/sh
# The man page of a command line of pod-manual against two man(7)
# renderers that pod-manual did not write: groff and mandoc.
#
#   sh scripts/check-man.sh BINARY
#
# BINARY runs here: `BINARY man --roff` writes the page and `BINARY man
# --json` gives each flag. The checks: groff -ww gives no warning; mandoc
# -Tlint gives no warning; each flag spelling of the JSON is in the text of
# both renderings, as a word of its own. The plant: a flag of a generated
# name that no text of the page holds must be missing from the page, and
# found when the page gets an item of it, so the check is not vacuous.
# Each check prints ok or FAIL.
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
# missing PAGE FLAGS: each spelling of the file FLAGS that a rendering of
# PAGE lacks, in PAGE.missing.
missing() {
    : > "$1.missing"
    for r in groff mandoc; do
        while IFS= read -r f; do
            # A spelling counts as a word of its own: --add is not in --add-door.
            grep -qE -e "(^|[^A-Za-z0-9-])$f([^A-Za-z0-9-]|\$)" "$1.$r" || echo "$r lacks $f" >> "$1.missing"
        done < "$2"
    done
}

if render "$W/page.1"; then
    missing "$W/page.1" "$W/flags.txt"
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

# The plant: a flag of a generated name that no text of the page holds.
# The check must find it missing from the page, and must find it in the
# page with one more item for it. A flag of the program can be named in the
# help of another flag, so the plant does not take one of them.
n=0
while :; do
    plant="--plant-$(od -An -N4 -tx4 /dev/urandom | tr -d ' ')"
    grep -qF -e "$(printf '%s' "$plant" | sed 's/-/\\-/g')" "$W/page.1" || grep -qF -e "${plant#--}" "$W/page.1" || break
    n=$((n + 1))
    [ "$n" -lt 9 ] || { echo "check-man: no unique name for the plant" >&2; exit 2; }
done
printf '%s\n' "$plant" > "$W/plant.txt"
cp "$W/page.1" "$W/planted.1"
printf '.TP\n\\fB%s\\fR\nThe planted flag.\n' "$(printf '%s' "$plant" | sed 's/-/\\-/g')" > "$W/item.1"
cat "$W/page.1" "$W/item.1" > "$W/added.1"
if render "$W/planted.1" && render "$W/added.1"; then
    missing "$W/planted.1" "$W/plant.txt"
    missing "$W/added.1" "$W/plant.txt"
    lacks=$(grep -c -e "lacks $plant\$" "$W/planted.1.missing")
    if [ "$lacks" -ne 2 ]; then
        bad plant "the page has no $plant, and the check found it in $((2 - lacks)) renderings: the check is vacuous"
    elif [ -s "$W/added.1.missing" ]; then
        bad plant "the page with an item of $plant, and the check did not find it:" "$W/added.1.missing"
    else
        ok plant "a flag that the page does not hold fails, and its item passes ($plant)"
    fi
else
    bad plant "the planted page does not render"
fi
[ "$fail" -eq 0 ] || exit 1
