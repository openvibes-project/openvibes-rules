#!/usr/bin/env bash
# Release the rules in one command: check, sign every rule set at the next
# version, open the pull request, merge it once CI is green, tag it.
#
# Pushing the tag vN starts .github/workflows/release.yml, which builds the RPM
# and publishes the GitHub Release. Releases are whole numbers (v1, v2, ...);
# every rule set is signed at vN, so the tag equals each envelope's version.
#
# The signing key is the maintainer's, encrypted with a passphrase
# (gpg --symmetric). It is decrypted into $XDG_RUNTIME_DIR (memory, only you
# can read it) for the signing alone and removed straight after, also on an
# error or Ctrl-C. It never reaches git, GitHub or CI.
#
#   OPENVIBES_RULES_KEY   the encrypted key (default: the one file matching
#                         /run/media/$USER/*/openvibes/openvibes-rules.key.gpg)
#
# Stopped after the pull request (CI failed, Ctrl-C)? Fix it on the
# release-vN branch if needed and run this again: an open release pull request
# is picked up where it was, without signing again.
#
# Usage: bash scripts/release.sh [VERSION]
set -euo pipefail

cd "$(git rev-parse --show-toplevel)"

remote=origin
branch=main

die() { echo "error: $*" >&2; exit 1; }

# Waits until every check run on commit $1 has finished, and stops if one failed.
# RELEASE_SKIP_CI=1 skips it; RELEASE_CI_TIMEOUT (seconds, default 2700) and
# RELEASE_CI_POLL (seconds, default 20) tune the wait.
wait_for_ci() {
  local sha=$1 deadline=$((SECONDS + ${RELEASE_CI_TIMEOUT:-2700})) runs failed pending total
  if [[ ${RELEASE_SKIP_CI:-} == 1 ]]; then
    echo "RELEASE_SKIP_CI=1: not checking CI."
    return
  fi
  command -v gh > /dev/null || die "gh is needed to check CI before tagging (https://cli.github.com)"
  echo "Checking CI on ${sha:0:7}..."
  while :; do
    runs=$(gh api --paginate "repos/{owner}/{repo}/commits/$sha/check-runs?per_page=100" \
      --jq '.check_runs[] | [.name, .status, (.conclusion // "")] | @tsv') \
      || die "could not read the CI checks from GitHub (is gh logged in? try: gh auth status)"
    failed=$(awk -F'\t' '$2 == "completed" && $3 !~ /^(success|neutral|skipped)$/ { print "  " $1 " (" $3 ")" }' <<<"$runs")
    [[ -z $failed ]] || die "CI failed on ${sha:0:7}:"$'\n'"$failed"$'\n'"Fix it, or re-run the failed jobs (a cancelled job is often a stuck runner), then run this again."
    pending=$(awk -F'\t' 'NF && $2 != "completed" { n++ } END { print n + 0 }' <<<"$runs")
    total=$(grep -c . <<<"$runs" || true)
    if (( total > 0 && pending == 0 )); then
      echo "CI is green ($total checks)."
      return
    fi
    (( SECONDS < deadline )) || die "CI on ${sha:0:7} is not finished after ${RELEASE_CI_TIMEOUT:-2700}s ($pending of $total checks pending)"
    if (( total == 0 )); then echo "  no checks reported yet"; else echo "  $pending of $total checks still running"; fi
    sleep "${RELEASE_CI_POLL:-20}"
  done
}

# The rule sets this repository signs: directory, sources, envelope, rule set
# id, and the check that verifies the signed envelope. A set is signed only once
# its trust line exists (committed by the maintainer, public).
sets=(
  "baseline|rules.json|baseline.json|baseline.key|baseline|rules-check -- --dir baseline --cases tests/cases.json --allowlist facts.allowlist"
  "alarms|rules.json|alarms.json|alarms.key|baseline-alarms|alarms-check -- --dir alarms --cases tests/alarm-cases.json"
  "hardening/linux-l1|rules.json|hardening-linux-l1.json|hardening-linux-l1.key|hardening-linux-l1|hardening-check -- --dir hardening/linux-l1 --cases tests/hardening-l1-cases.json --allowlist hardening.allowlist --set hardening-linux-l1"
)

# Runs every set's check: on the sources ($1 = --sources-only) or signed.
check_sets() {
  local entry dir rules env key id check
  cargo test --locked --quiet > /dev/null || die "cargo test failed"
  for entry in "${sets[@]}"; do
    IFS='|' read -r dir rules env key id check <<<"$entry"
    [[ -f $dir/$key ]] || continue
    # shellcheck disable=SC2086 # the check is a word list
    cargo run --locked --quiet -p $check ${1:-} || die "the $id check failed"
  done
}

# Decrypts the key into $XDG_RUNTIME_DIR, signs every trusted set at $1, and
# removes the key again.
sign_sets() {
  local version=$1 enc=${OPENVIBES_RULES_KEY:-} tmp entry dir rules env key id check issuer
  if [[ -z $enc ]]; then
    local found=(/run/media/"$USER"/*/openvibes/openvibes-rules.key.gpg)
    [[ ${#found[@]} == 1 && -f ${found[0]} ]] \
      || die "set OPENVIBES_RULES_KEY to the encrypted key (no single /run/media/$USER/*/openvibes/openvibes-rules.key.gpg)"
    enc=${found[0]}
  fi
  [[ -f $enc ]] || die "no encrypted key at $enc"
  [[ -n ${XDG_RUNTIME_DIR:-} && -d $XDG_RUNTIME_DIR ]] || die "XDG_RUNTIME_DIR is not set; the key is only decrypted there (memory)"
  tmp=$(umask 077 && mktemp -d "$XDG_RUNTIME_DIR/openvibes-rules.XXXXXX")
  # shellcheck disable=SC2064 # $tmp is fixed now
  trap "rm -rf '$tmp'" EXIT INT TERM
  echo "Decrypting the signing key ($enc)..."
  # At a terminal gpg asks for the passphrase itself; otherwise it is read
  # from standard input. --no-symkey-cache: gpg-agent does not keep it.
  local pass=(--pinentry-mode loopback)
  [[ -t 0 ]] || pass+=(--passphrase-fd 0)
  (umask 077 && gpg --quiet --batch --no-symkey-cache "${pass[@]}" --decrypt --output "$tmp/key" "$enc") \
    || die "could not decrypt the key (wrong passphrase?)"
  for entry in "${sets[@]}"; do
    IFS='|' read -r dir rules env key id check <<<"$entry"
    [[ -f $dir/$key ]] || continue
    issuer=$(awk '{ print $2 }' "$dir/$key")
    rm -f "$dir/$env"
    openvibes-admin rules sign "$tmp/key" "$dir/$rules" --rule-set "$id" --version "$version" \
      --issuer "$issuer" -o "$dir/$env" > /dev/null || die "signing $id failed"
    echo "  signed $id v$version"
  done
  rm -rf "$tmp"
  trap - EXIT INT TERM
}

command -v gh > /dev/null || die "gh is needed (https://cli.github.com)"
[[ -z $(git status --porcelain) ]] || die "working tree is not clean"
git fetch --quiet --tags "$remote"

# An open release pull request: carry on with it.
pr=$(gh pr list --state open --json number,headRefName \
  --jq '[.[] | select(.headRefName | test("^release-v[1-9][0-9]*$"))] | first | "\(.number) \(.headRefName)"' 2>/dev/null || true)
if [[ -n $pr && $pr != null* && $pr != " " ]]; then
  number=${pr%% *}
  version=${pr##*release-v}
  echo "Continuing the open release pull request #$number (v$version)."
else
  [[ $(git rev-parse --abbrev-ref HEAD) == "$branch" ]] || die "run this from the $branch branch"
  [[ $(git rev-parse HEAD) == "$(git rev-parse "$remote/$branch")" ]] \
    || die "$branch is not in sync with $remote/$branch (pull or push first)"

  # The highest version already released: tags, not just the envelope.
  highest=0
  while read -r tag; do
    if (( ${tag#v} > highest )); then highest=${tag#v}; fi
  done < <(git tag --list 'v*' | grep -E '^v[1-9][0-9]*$' || true)
  version=${1:-$((highest + 1))}
  version=${version#v}
  [[ $version =~ ^[1-9][0-9]*$ ]] || die "'$version' is not a whole number like 3"
  (( version > highest )) || die "v$version is not higher than the existing release v$highest"

  echo "Checking the rules..."
  check_sets --sources-only
  read -r -p "Release v$version (sign every rule set at v$version)? [y/N] " answer
  [[ $answer == [yY]* ]] || die "cancelled"

  sign_sets "$version"
  echo "Checking the signed rule sets..."
  check_sets

  git switch --quiet -c "release-v$version"
  git add -A -- '*.json'
  git commit --quiet -m "Release v$version: sign every rule set at v$version"
  git push --quiet -u "$remote" "release-v$version"
  number=$(gh pr create --base "$branch" --head "release-v$version" --title "Release v$version" \
    --body "Every rule set signed at v$version by \`scripts/release.sh\`." | grep -oE '[0-9]+$')
  echo "Opened pull request #$number."
fi

wait_for_ci "$(gh pr view "$number" --json headRefOid --jq .headRefOid)"
gh pr merge "$number" --merge > /dev/null || die "could not merge #$number"
echo "Merged #$number."
git switch --quiet "$branch"
git pull --quiet --ff-only "$remote" "$branch"
wait_for_ci "$(git rev-parse HEAD)"

git tag -a "v$version" -m "v$version"
git push --quiet "$remote" "v$version"
echo "Released v$version. Watch the Release workflow in the repository's Actions tab."
