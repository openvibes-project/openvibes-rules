#!/usr/bin/env bash
# Builds openvibes-rules-baseline (noarch) from baseline/ into OUT_DIR and
# checks it: rpmlint without errors, exactly the four files (baseline and
# alarm rule sets, with their keys), the licence and NOTICE, and two directories. The version is the signed envelope's rule set version.
# Usage: build-rpm.sh OUT_DIR   (Fedora: rpm-build rpmlint jq)
set -euo pipefail
[[ $# == 1 ]] || { echo "usage: $0 OUT_DIR" >&2; exit 2; }
out=$1
root=$(cd "$(dirname "$0")/.." && pwd)
version=$(jq -er .rule_set_version "$root/baseline/baseline.json")
rm -rf "$root/target/rpm"
rpmbuild -bb --quiet \
    --define "_topdir $root/target/rpm" \
    --define "_sourcedir $root/baseline" \
    --define "alarms_dir $root/alarms" \
    --define "license_dir $root" \
    --define "rule_version $version" \
    "$root/openvibes-rules-baseline.spec"
mkdir -p "$out"
rpm=$(ls "$root"/target/rpm/RPMS/noarch/openvibes-rules-baseline-"$version"-*.noarch.rpm)
cp "$rpm" "$out/"
rpmlint "$rpm"
want='/usr/share/licenses/openvibes-rules-baseline/LICENSE
/usr/share/licenses/openvibes-rules-baseline/NOTICE
/usr/share/openvibes
/usr/share/openvibes/rules
/usr/share/openvibes/rules/alarms.json
/usr/share/openvibes/rules/alarms.key
/usr/share/openvibes/rules/baseline.json
/usr/share/openvibes/rules/baseline.key'
got=$(rpm -qlp "$rpm")
[[ $got == "$want" ]] || { printf 'build-rpm: unexpected files:\n%s\n' "$got" >&2; exit 1; }
echo "build-rpm: $(basename "$rpm")"
