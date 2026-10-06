#!/usr/bin/env bash
# Cut a release: check the signed baseline's version, tag it, push the tag.
#
# Pushing the tag vN starts .github/workflows/release.yml, which builds the RPM
# and publishes the GitHub Release. Releases here are whole numbers (v1, v2,
# ...), and the workflow fails unless the tag equals rule_set_version in
# baseline/baseline.json, is on main and is above the last release.
#
# That version sits inside the envelope the maintainer signs, so this script
# cannot bump it: sign baseline.json at the new version, merge it to main, then
# run this. Without a VERSION argument you are prompted, with the next number
# offered.
#
# Usage: bash scripts/release.sh [VERSION]
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

remote=origin
branch=main

die() { echo "error: $*" >&2; exit 1; }

[[ $(git rev-parse --abbrev-ref HEAD) == "$branch" ]] || die "run this from the $branch branch"
[[ -z $(git status --porcelain) ]] || die "working tree is not clean"

git fetch --quiet --tags "$remote" "$branch"
[[ $(git rev-parse HEAD) == "$(git rev-parse "$remote/$branch")" ]] \
  || die "$branch is not in sync with $remote/$branch (pull or push first)"

# The version the baseline is signed at, as release.yml reads it.
signed=$(jq -er .rule_set_version baseline/baseline.json) \
  || die "cannot read rule_set_version from baseline/baseline.json"
[[ $signed =~ ^[1-9][0-9]*$ ]] || die "rule_set_version '$signed' is not a whole number"

# The highest version already released: tags, not just the envelope.
highest=0
while read -r tag; do
  if (( ${tag#v} > highest )); then highest=${tag#v}; fi
done < <(git tag --list 'v*' | grep -E '^v[1-9][0-9]*$' || true)
suggested=$((highest + 1))

echo "baseline.json is signed at: v$signed"
echo "Highest release:            v$highest"

version=${1:-}
if [[ -z $version ]]; then
  read -r -p "New version [$suggested]: " version
  version=${version:-$suggested}
fi
version=${version#v}

[[ $version =~ ^[1-9][0-9]*$ ]] || die "'$version' is not a whole number like 3"
(( version > highest )) || die "v$version is not higher than the existing release v$highest"
[[ $version == "$signed" ]] \
  || die "baseline.json is signed at v$signed; sign it at v$version and merge that to $branch first"

read -r -p "Tag v$version and push to $remote? [y/N] " answer
[[ $answer == [yY]* ]] || die "cancelled"

git tag -a "v$version" -m "v$version"
git push "$remote" "v$version"

echo "Released v$version. Watch the Release workflow in the repository's Actions tab."
