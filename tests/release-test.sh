#!/usr/bin/env bash
# Tests scripts/release.sh end to end against a throwaway key, a local bare
# repository standing in for GitHub and a fake gh. Never touches the real key
# or the real repository.
#
# Usage: bash tests/release-test.sh   (needs openvibes-admin, gpg, cargo)
set -euo pipefail

repo=$(git rev-parse --show-toplevel)
work=$(mktemp -d)
trap 'rm -rf "$work"' EXIT
export CARGO_TARGET_DIR=$repo/target GNUPGHOME=$work/gnupg XDG_RUNTIME_DIR=$work/run RELEASE_SKIP_CI=1
mkdir -m 700 "$GNUPGHOME" "$XDG_RUNTIME_DIR"

fail() { echo "FAIL: $*" >&2; exit 1; }
pass() { echo "ok: $*"; }

# GitHub: a bare repository with main, the throwaway key's trust lines in it.
git clone --quiet --bare --branch main "$repo" "$work/remote.git"
git clone --quiet "$work/remote.git" "$work/clone"
cd "$work/clone"
git config user.name test && git config user.email test@example.invalid
openvibes-admin rules keygen --rule-set baseline --issuer test-1 "$work/key" > /dev/null
public=$(openvibes-admin rules keygen --show-public --rule-set baseline --issuer test-1 "$work/key" | awk '{ print $3 }')
echo "baseline test-1 $public" > baseline/baseline.key
echo "baseline-alarms test-1 $public" > alarms/alarms.key
git commit --quiet -am "test: throwaway trust lines"
git push --quiet origin main
gpg --quiet --batch --pinentry-mode loopback --passphrase right --symmetric --output "$work/key.gpg" "$work/key"
rm "$work/key"
export OPENVIBES_RULES_KEY=$work/key.gpg

# gh: pull requests are files under $work/prs; merge merges into the bare main.
mkdir "$work/bin" "$work/prs"
cat > "$work/bin/gh" <<'EOF'
#!/usr/bin/env bash
set -euo pipefail
prs=$FAKE_GH_PRS
case "$1 $2" in
  # Each file: "head cross-repository". Like the real --jq, only this repository's.
  "pr list")   for f in "$prs"/*; do [[ -e $f ]] && read -r h c < "$f" && [[ $c == false ]] && echo "$(basename "$f") $h"; done | head -1 ;;
  "pr create") n=$(( $(ls "$prs" | wc -l) + 7 )); echo "${*: -1}" > /dev/null
               head=$(sed -n 's/.*--head \([^ ]*\).*/\1/p' <<<"$*"); echo "$head false" > "$prs/$n"
               echo "https://github.com/example/rules/pull/$n" ;;
  "pr view")   read -r h _ < "$prs/$3"; git ls-remote "$FAKE_GH_REMOTE" "refs/heads/$h" | cut -f1 ;;
  "pr merge")  [[ -z ${FAKE_GH_MERGE_FAIL:-} ]] || exit 1
               read -r head _ < "$prs/$3"; tmp=$(mktemp -d); git clone --quiet "$FAKE_GH_REMOTE" "$tmp"
               if [[ -n ${FAKE_GH_PUSH_BEFORE_MERGE:-} ]]; then   # someone pushes to the branch meanwhile
                 git -C "$tmp" switch --quiet "$head"
                 echo '{"schema_version":1,"rules":[]}' > "$tmp/baseline/rules.json"
                 git -C "$tmp" -c user.name=x -c user.email=x@example.invalid commit --quiet -am "late change"
                 git -C "$tmp" push --quiet origin "$head"; git -C "$tmp" switch --quiet main
               fi
               # GitHub refuses --match-head-commit when the head moved.
               want=$(sed -n 's/.*--match-head-commit \([0-9a-f]*\).*/\1/p' <<<"$*")
               [[ -n $want && $want == "$(git -C "$tmp" rev-parse "origin/$head")" ]] || { echo "head moved" >&2; exit 1; }
               git -C "$tmp" -c user.name=gh -c user.email=gh@example.invalid merge --quiet --no-ff -m "Merge #$3" "origin/$head"
               git -C "$tmp" push --quiet origin main; rm -rf "$tmp" "$prs/$3" ;;
  *) echo "fake gh: unexpected $*" >&2; exit 2 ;;
esac
EOF
chmod +x "$work/bin/gh"
export PATH=$work/bin:$PATH FAKE_GH_PRS=$work/prs FAKE_GH_REMOTE=$work/remote.git

highest=$(git tag --list 'v*' | grep -E '^v[0-9]+$' | sed 's/^v//' | sort -n | tail -1)
next=$((highest + 1))
run_dir_empty() { [[ -z $(ls -A "$XDG_RUNTIME_DIR") ]]; }

# 1. A wrong passphrase: nothing signed, no key left, no branch, no tag.
if printf 'y\nwrong\n' | bash "$repo/scripts/release.sh" > "$work/out1" 2>&1; then fail "a wrong passphrase released"; fi
grep -q 'could not decrypt' "$work/out1" || { cat "$work/out1"; fail "no decrypt error"; }
run_dir_empty || fail "a key was left in XDG_RUNTIME_DIR after a failure"
[[ -z $(git status --porcelain) ]] || fail "a failed run changed files"
[[ -z $(git ls-remote "$work/remote.git" "refs/tags/v$next") ]] || fail "a failed run tagged"
pass "a wrong passphrase stops before signing and leaves no key"

# 2. Signed, pull request opened, the merge fails (CI red): stops there.
if printf 'y\nright\n' | FAKE_GH_MERGE_FAIL=1 bash "$repo/scripts/release.sh" > "$work/out2" 2>&1; then fail "a failed merge released"; fi
grep -q "Opened pull request" "$work/out2" || { cat "$work/out2"; fail "no pull request"; }
run_dir_empty || fail "the key was left in XDG_RUNTIME_DIR after signing"
for f in baseline/baseline.json alarms/alarms.json; do
  v=$(git show "release-v$next:$f" | jq -r .rule_set_version)
  [[ $v == "$next" ]] || fail "$f is signed at v$v, not v$next"
done
[[ -z $(git ls-remote "$work/remote.git" "refs/tags/v$next") ]] || fail "tagged before the merge"
pass "every set signed at v$next, the key removed, nothing tagged before the merge"

# 3. A pull request from a fork named release-vN is never picked up, and a
#    commit pushed to the release branch after the checks is never merged.
echo "release-v$next true" > "$work/prs/1"
git switch --quiet main
if OPENVIBES_RULES_KEY=/nonexistent FAKE_GH_PUSH_BEFORE_MERGE=1 bash "$repo/scripts/release.sh" < /dev/null > "$work/out3a" 2>&1; then
  cat "$work/out3a"; fail "merged a branch that moved after the checks"
fi
grep -q "Continuing the open release pull request #7" "$work/out3a" || { cat "$work/out3a"; fail "did not resume our own pull request"; }
[[ -z $(git ls-remote "$work/remote.git" "refs/tags/v$next") ]] || fail "tagged a moved branch"
pass "a fork's release-vN is ignored; a branch that moved after the checks is not merged"
if OPENVIBES_RULES_KEY=/nonexistent bash "$repo/scripts/release.sh" < /dev/null > "$work/out3b" 2>&1; then
  cat "$work/out3b"; fail "released an unsigned change"
fi
grep -q "check failed" "$work/out3b" || { cat "$work/out3b"; fail "the late change was not caught by the signed check"; }
pass "resuming checks the signed sets on the pull request's head first"
# Undo the late change on the branch, as the maintainer would.
git fetch --quiet origin && git switch --quiet main
git push --quiet --force origin "origin/release-v$next~1:refs/heads/release-v$next"
rm "$work/prs/1"

# 4. Run again without the key: the open pull request is merged and tagged.
git switch --quiet main
if ! OPENVIBES_RULES_KEY=/nonexistent bash "$repo/scripts/release.sh" < /dev/null > "$work/out3" 2>&1; then
  cat "$work/out3"; fail "resuming failed"
fi
grep -q "Continuing the open release pull request" "$work/out3" || fail "did not resume"
[[ -n $(git ls-remote "$work/remote.git" "refs/tags/v$next") ]] || fail "v$next was not tagged"
tagged=$(git -C "$work/remote.git" rev-parse "v$next^{commit}")
[[ $tagged == "$(git -C "$work/remote.git" rev-parse main)" ]] || fail "the tag is not on main's merge commit"
[[ $(git -C "$work/remote.git" show "v$next:baseline/baseline.json" | jq -r .rule_set_version) == "$next" ]] \
  || fail "the tagged baseline is not v$next"
pass "a second run resumes the open pull request, merges and tags v$next on main"

echo "all release tests passed"
