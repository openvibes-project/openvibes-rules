#!/usr/bin/env bash
# Cases for scripts/ci-docs.sh.
set -euo pipefail
cd "$(dirname "$0")/.."
fail=0
check() { # expected, then changed files
    local want=$1 got
    shift
    got=$(printf '%s\n' "$@" | bash scripts/ci-docs.sh)
    [[ $got == "docs=$want" ]] || { echo "FAIL: $*: want docs=$want, got $got"; fail=1; }
}
check true  README.md docs/components/alarms.md
check true  hardening/README.md
check false README.md checker/src/main.rs
check false docs/diagram.svg
check false .github/workflows/ci.yml
check false
[[ $fail == 0 ]] && echo "ci-docs: ok"
exit $fail
