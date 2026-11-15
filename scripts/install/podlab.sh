#!/bin/sh
# SPDX-License-Identifier: 0BSD
# The installer of podlab, the command line of pod-lab (docs/install.md).
# A release publishes it as podlab-install.sh, with the core inline and the
# pins of the release (scripts/install/pins.py stamp). This copy of the tree
# has no pins: it refuses to install.
#
#   sh podlab-install.sh [--prefix DIR] [--dry-run] [--offline FILE]
INST_NAME=podlab
INST_ENV=PODLAB
INST_REPO=PodUtils/podcrates

# BEGIN PINS (scripts/install/pins.py writes this block; do not edit it)
INST_VERSION=""
INST_TARGETS=""
# END PINS

# BEGIN CORE (scripts/install/pins.py puts scripts/install/core.sh here)
# shellcheck source=scripts/install/core.sh
. "$(dirname "$0")/core.sh"
# END CORE

# The self-check: the table of the profiles, with no network and no lab.
inst_selfcheck() {
    if "$1/podlab$inst_exe" list > /dev/null 2>&1; then
        inst_say "self-check: podlab list: ok"
        return 0
    fi
    "$1/podlab$inst_exe" list 2>&1 | tail -n 5 >&2
    return 1
}

inst_main "$@"
