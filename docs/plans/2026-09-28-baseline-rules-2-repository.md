# Baseline rules 2: the `openvibes-rules` repository Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** The first baseline rule set (16 rules) with tests, a checker that CI runs on every PR, and a noarch RPM `openvibes-rules-baseline` released from `v*` tags and picked up by the Pages package repository.

**Architecture:** `baseline/rules.json` is the reviewed source; `baseline/baseline.json` is the envelope the user signs offline with `openvibes-admin rules sign` (platform #63); `baseline/baseline.key` is the trust line. A small Rust binary `rules-check` (in `checker/`, depending on the agent's `openvibes-core` and `openvibes-rules` at the rev platform pins) runs spec §6 checks 1–5; the RPM job is check 6. The release workflow copies the platform's (build, sign with the org RPM key, publish, dispatch Pages). Pages' `collect.sh` gains the third repository.

**Tech Stack:** Rust 1.95.0, serde_json, ed25519-dalek 3, openvibes-core/openvibes-rules (git rev 40f99114bbf1c61a24be3c00c8b782609b757b2a), rpmbuild on Fedora 44, GitHub Actions.

**Spec:** openvibes-platform `docs/specs/2026-09-28-baseline-rules-design.md` §5–§7 (merged with platform #63; until then on branch `baseline-rules`).

## Global Constraints

- Rule set id `baseline`, issuer key id `openvibes-1`, key line `baseline openvibes-1 PUBLIC_KEY`.
- The 16 rules of spec §5, exactly: ids, severities, conditions; confidence 90 for port rules, 100 for package rules.
- Envelope payload equals `rules.json` byte for byte; envelope version > the latest `v*` tag's; ≥ 365 days left at check time.
- Facts a rule may read: only those in `facts.allowlist`; read only as `facts['<key>']`.
- Every rule: ≥ 1 `match` case and ≥ 1 `no_match` case.
- RPM: `noarch`, Version = envelope version, files `/usr/share/openvibes/rules/{baseline.json,baseline.key}` 0644 root, owns `%dir` `/usr/share/openvibes` and `/usr/share/openvibes/rules`, no scriptlets.
- CI job names are exactly `Rule checks` and `RPM (fedora:44)` (the ruleset requires them).
- Actions pinned by commit SHA as in the other repositories; `persist-credentials: false`.
- The private signing key never enters the repository or CI.
- Commits end with `Co-Authored-By: Claude Opus 5.5 <noreply@anthropic.com>`.

## Review Focus

- A payload that differs from `rules.json` only in whitespace or key order must fail check 2 (byte equality, not JSON equality) → test `payload_must_match_bytes`.
- An expression that reads a fact through a form other than `facts['…']` (e.g. `facts["x"]`, `facts.x`) must fail check 4, not slip past the allowlist → test `other_fact_access_is_refused`.
- A test case naming a rule id that does not exist must fail, not be skipped → test `case_for_unknown_rule_fails`.
- Tag `vN` whose number differs from the envelope version must stop the release → release workflow step "The tag is the envelope version".
- `baseline.key` with extra whitespace or a trailing newline must parse; one with 2 or 4 fields must fail → test `key_line_parsing`.

---

### Task 1: Rules, tests and allowlist (data only)

**Files:**
- Create: `baseline/rules.json`, `tests/cases.json`, `facts.allowlist`

- [ ] **Step 1:** `facts.allowlist` (one key per line; the facts agent v0.1.0 collects, per agent `docs/components/openvibes-collectors.md`):

```text
process.names
process.count
package.names
package.count
port.tcp.exposed
port.tcp.local
port.tcp.listeners
port.tcp.exposed.count
port.udp.exposed
port.udp.local
port.udp.listeners
port.udp.exposed.count
```

- [ ] **Step 2:** `baseline/rules.json`: schema 1, the 16 rules of spec §5 in table order, compact JSON with one rule per line (reviewable diffs). Port rule shape:

```json
{"id":"port.docker_api.exposed","version":1,"title":"Docker API is exposed","severity":"critical","confidence":90,"expression":"'2375' in facts['port.tcp.exposed']","finding_message":"The unencrypted Docker API (tcp 2375) listens on a non-loopback address; anyone who reaches it controls the host. Bind it to a Unix socket or loopback, or use TLS on 2376."}
```

Multi-port: `"'512' in facts['port.tcp.exposed'] || '513' in facts['port.tcp.exposed'] || '514' in facts['port.tcp.exposed']"`. SNMP reads `port.udp.exposed`. Package rules: `"'telnet-server' in facts['package.names']"`, confidence 100. Every `finding_message` names the port and the usual fix and says "listens on a non-loopback address" (bound, not proven reachable).

- [ ] **Step 3:** `tests/cases.json`: an array of `{"rule": ID, "name": TEXT, "facts": {KEY: VALUE}, "expect": "match"|"no_match"|"unavailable"}`; a JSON array value is a string list, a number an integer. Per port rule: the port exposed → `match`; the same port only in `port.tcp.local` and an empty `port.tcp.exposed` → `no_match`. Per package rule: present → `match`; absent → `no_match`. Plus one `unavailable` case (facts `{}`) for `port.ssh.exposed`.

- [ ] **Step 4:** Commit: `rules: baseline v1 rule set, test cases, fact allowlist`.

### Task 2: `rules-check`

**Files:**
- Create: `checker/Cargo.toml`, `checker/src/main.rs`, `checker/src/checks.rs`, `rust-toolchain.toml`, `Cargo.lock` (generated), `.gitignore` (`/target`)

**Interfaces:**
- Produces: CLI `rules-check --dir baseline --cases tests/cases.json --allowlist facts.allowlist [--previous-version N] [--min-days 365] [--sources-only]`. `--sources-only` runs checks 1, 4, 5 (no envelope yet). Prints `ok: R rules, C cases[, vV expires TIME]`; otherwise one `error: …` line per failure and exit 1.
- In `checks.rs`: `pub fn rule_set(bytes: &[u8]) -> Result<RuleSet, String>`; `pub fn key_line(text: &str) -> Result<(Identifier, Identifier, [u8; 32]), String>`; `pub fn envelope(bytes: &[u8], key: &(Identifier, Identifier, [u8; 32]), rules_bytes: &[u8], now_ms: i64) -> Result<SignedRuleEnvelope, String>`; `pub fn fact_keys(expression: &str) -> Result<Vec<String>, String>`; `pub fn run_cases(rules: &[u8], cases: &[Case], now_ms: i64) -> Vec<String>` (errors).

- [ ] **Step 1: Write the failing unit tests** (`checks.rs`, `#[cfg(test)] mod tests`), each against a small inline fixture and an ephemeral key (`SigningKey::from_bytes(&[7; 32])`):

```rust
#[test] fn key_line_parsing() {
    let key = URL_SAFE_NO_PAD.encode(SigningKey::from_bytes(&[7; 32]).verifying_key().to_bytes());
    assert!(key_line(&format!("baseline openvibes-1 {key}\n")).is_ok());
    assert!(key_line(&format!("  baseline  openvibes-1 {key}  ")).is_ok());
    assert!(key_line(&format!("baseline {key}")).is_err());
    assert!(key_line(&format!("baseline openvibes-1 {key} extra")).is_err());
}
#[test] fn payload_must_match_bytes() {
    let rules = br#"{"schema_version":1,"rules":[RULE]}"#; // RULE: a valid one-rule fixture
    let reformatted = /* same JSON with a space after the first colon */;
    let signed = sign_fixture(reformatted, 1, 400);          // test helper: signs with [7;32]
    let err = envelope(&signed, &fixture_key(), rules, now()).unwrap_err();
    assert!(err.contains("payload differs from rules.json"), "{err}");
}
#[test] fn envelope_accepts_matching_signed_bytes() { /* sign_fixture(rules) → Ok(version 1) */ }
#[test] fn envelope_refuses_other_key() { /* signed with [8;32] → Err containing "untrusted" or "signature" */ }
#[test] fn fact_keys_extracts_literals() {
    assert_eq!(fact_keys("'22' in facts['port.tcp.exposed'] || facts['process.count'] > 1").unwrap(),
               vec!["port.tcp.exposed", "process.count"]);
}
#[test] fn other_fact_access_is_refused() {
    for expression in [r#"'22' in facts["port.tcp.exposed"]"#, "facts.x > 1", "size(facts) > 0"] {
        assert!(fact_keys(expression).is_err(), "{expression}");
    }
}
#[test] fn cases_evaluate_through_the_agent_evaluator() { /* match, no_match, unavailable each as expected; a wrong expectation yields one error naming rule and case */ }
#[test] fn case_for_unknown_rule_fails() { /* case.rule = "nope" → error "unknown rule nope" */ }
#[test] fn rule_without_both_cases_fails() { /* only a match case → error "port.x.exposed: needs a match and a no_match case" */ }
```

Write each `/* … */` body out in full when implementing (the fixture helpers `sign_fixture`, `fixture_key`, `now` live in the test module).

- [ ] **Step 2:** Run `cargo test --locked` in the repository root → FAIL (functions missing).

- [ ] **Step 3: Implement.** `checker/Cargo.toml`:

```toml
[package]
name = "rules-check"
version = "0.1.0"
edition = "2024"
license = "MIT"
publish = false

[dependencies]
openvibes-core = { git = "https://github.com/openvibes-project/openvibes-agent.git", rev = "40f99114bbf1c61a24be3c00c8b782609b757b2a" }
openvibes-rules = { git = "https://github.com/openvibes-project/openvibes-agent.git", rev = "40f99114bbf1c61a24be3c00c8b782609b757b2a" }
base64 = { version = "0.23.1", default-features = false, features = ["std"] }
ed25519-dalek = { version = "3.0.0", default-features = false, features = ["fast"] }
serde = { version = "1.0.228", features = ["derive"] }
serde_json = "1.0.145"
sha2 = { version = "0.11", default-features = false }
```

Root `Cargo.toml`: `[workspace] members = ["checker"] resolver = "3"`. `rust-toolchain.toml` as the agent's (1.95.0, clippy, rustfmt, minimal).

Core of `checks.rs`:

```rust
/// Every `facts[...]` access must be `facts['<key>']`; returns the keys.
pub fn fact_keys(expression: &str) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    let mut rest = expression;
    while let Some(at) = rest.find("facts") {
        let after = &rest[at + "facts".len()..];
        let Some(tail) = after.strip_prefix("['") else {
            return Err(format!("facts must be read as facts['KEY']: {expression}"));
        };
        let end = tail.find("']").ok_or_else(|| format!("unterminated facts['…']: {expression}"))?;
        keys.push(tail[..end].to_owned());
        rest = &tail[end + 2..];
    }
    Ok(keys)
}
```

`run_cases`: sign `rules` in memory with an ephemeral key (`SigningKey::from_bytes(&[1; 32])`, `signing_preimage`, as platform `rules_sign.rs` does), load it with `RuleLoader` (id `baseline`, issuer `check`), then for each case build a `FactSet { schema_version: V1, scan_id: "check", collected_at_unix_ms: now_ms - 1, facts, errors: vec![] }` where each fact's `source` is `ports` / `packages` / `processes` from its key prefix and the value maps JSON array → `StringList`, number → `Integer`; evaluate with `Evaluator::new(ResourceLimits::V1)` and a clock `struct Now(i64)` (`elapsed` → `Duration::ZERO`, `unix_ms` → `self.0`); compare the rule's `RuleOutcome` (`Match` / `NoMatch` / `Unavailable`; `Failed` is always an error). A case whose rule id is not in the set is an error; each rule without both a `match` and a `no_match` case is an error.

`envelope`: `RuleLoader::load_json` with the key line's key at `now_ms`, then parse the envelope bytes as `SignedRuleEnvelope` and compare `payload.as_bytes()` with `rules_bytes` (error `payload differs from rules.json`).

`main.rs`: parse the flags by hand (no clap: six flags), run checks 1 (`rule_set` + unique ids), 4 (`fact_keys` of every expression ⊆ allowlist), 5 (`run_cases`), and unless `--sources-only`: 2 (`envelope`), 3 (`version > previous` when given; `expires - now ≥ min_days × 86 400 000`). Collect every error before exiting.

- [ ] **Step 4:** `cargo test --locked` → all pass; `cargo run --locked -p rules-check -- --dir baseline --cases tests/cases.json --allowlist facts.allowlist --sources-only` → `ok: 16 rules, 33 cases`.

- [ ] **Step 5:** `cargo fmt --check && cargo clippy --locked --all-targets -- -D warnings`, then commit: `checker: rules-check runs the baseline checks`.

### Task 3: RPM

**Files:**
- Create: `openvibes-rules-baseline.spec`, `scripts/build-rpm.sh`, `packaging/openvibes-packages.gpg` (copy of platform `packaging/rpm/openvibes-packages.gpg`), `scripts/sign-rpms.sh` (copy of platform `scripts/sign-rpms.sh`, unchanged)

- [ ] **Step 1:** Spec:

```spec
Name:           openvibes-rules-baseline
Version:        %{rule_version}
Release:        1%{?dist}
Summary:        OpenVIBES signed baseline rule set
License:        MIT
URL:            https://github.com/openvibes-project/openvibes-rules
BuildArch:      noarch
Source0:        baseline.json
Source1:        baseline.key

%description
The OpenVIBES project's signed baseline rule set and its public key.
openvibes-admin Setup trusts the key and publishes the rule set.

%prep

%build

%install
install -D -m 0644 %{SOURCE0} %{buildroot}%{_datadir}/openvibes/rules/baseline.json
install -D -m 0644 %{SOURCE1} %{buildroot}%{_datadir}/openvibes/rules/baseline.key

%files
%dir %{_datadir}/openvibes
%dir %{_datadir}/openvibes/rules
%{_datadir}/openvibes/rules/baseline.json
%{_datadir}/openvibes/rules/baseline.key
```

- [ ] **Step 2:** `scripts/build-rpm.sh OUT_DIR`: reads the version with `jq -er .rule_set_version baseline/baseline.json`, runs `rpmbuild -bb --define "_topdir $PWD/target/rpm" --define "_sourcedir $PWD/baseline" --define "rule_version $version" openvibes-rules-baseline.spec`, copies the RPM to `OUT_DIR`, then checks it: `rpmlint` has no errors and `rpm -qlp` lists exactly the two files and two directories.

- [ ] **Step 3:** Run in `podman run --rm -v "$PWD:/w:z" -w /w registry.fedoraproject.org/fedora:44 bash -c 'dnf -q -y install rpm-build rpmlint jq && bash scripts/build-rpm.sh dist'` against a temporary `baseline.json` made with `openvibes-admin rules sign` and a throwaway key (not committed) → the RPM builds and the listing check passes. Delete the temporary files.

- [ ] **Step 4:** Commit: `rpm: openvibes-rules-baseline, noarch`.

### Task 4: CI and release workflows

**Files:**
- Create: `.github/workflows/ci.yml`, `.github/workflows/release.yml`

- [ ] **Step 1:** `ci.yml` (on `pull_request` and `push` to `main`), two jobs:
  - `Rule checks` (ubuntu-latest): checkout with `fetch-depth: 0`, `cargo fmt --check`, `cargo clippy --locked --all-targets -- -D warnings`, `cargo test --locked`, then `prev=$(git tag -l 'v*' --sort=-v:refname | head -1 | tr -d v)` and `cargo run --locked -p rules-check -- --dir baseline --cases tests/cases.json --allowlist facts.allowlist ${prev:+--previous-version $prev}`. On a PR that does not touch `baseline/baseline.json`, pass `--previous-version $((prev-1))` instead (an unchanged envelope must not fail; only a changed one must advance).
  - `RPM (fedora:44)` (container fedora:44): `dnf install rpm-build rpmlint jq`, `bash scripts/build-rpm.sh dist`, upload `dist/*.rpm` as artifact `rules-rpms`.
  Pin `actions/checkout` and `actions/upload-artifact` to the SHAs the platform uses.

- [ ] **Step 2:** `release.yml` (on tags `v*`, `permissions: contents: write`, container fedora:44), mirroring platform `release.yml`: step "The tag is the envelope version" (`test "v$(jq -er .rule_set_version baseline/baseline.json)" = "$GITHUB_REF_NAME"`), build (`scripts/build-rpm.sh dist`), run `rules-check` without `--previous-version`, sign and check (`RPM_SIGNING_KEY`, `RPM_SIGNING_PASSPHRASE`, `bash scripts/sign-rpms.sh dist packaging/openvibes-packages.gpg`, `SHA256SUMS`), publish the release, dispatch `release-published` with `PAGES_DISPATCH_TOKEN`.

- [ ] **Step 3:** `actionlint` on both files (or `podman run rhysd/actionlint`) → no findings. Commit: `ci: rule checks, RPM and release workflows`.

### Task 5: Repository docs

**Files:**
- Create: `AGENTS.md`, `CLAUDE.md` (`@AGENTS.md`), `CONTRIBUTING.md` (AI disclosure, as the other repositories), `docs/components/README.md`, `docs/components/baseline.md`, `docs/components/rules-check.md`
- Modify: `README.md`

- [ ] **Step 1:** Write them: what the repository is, the signer's routine (spec §6: edit rules and cases → `openvibes-admin rules sign … --version N` → commit `baseline.json` → PR → merge → tag `vN`), how to add a rule (id convention `port.<service>.exposed` / `package.<name>.installed`, message style, cases required, allowlist), and each component page's purpose/interfaces/failure/how-to-test. Commit: `docs: repository guide and component pages`.

### Task 6: First signed baseline and PR

- [ ] **Step 1:** Push branch `baseline`, open the PR (spec, this plan, test results). CI `Rule checks` is red until the envelope exists — expected; `--sources-only` passes locally.
- [ ] **Step 2:** The user, on their machine, with `openvibes-admin` built from platform main (#63):

```sh
openvibes-admin rules keygen /OFFLINE/PATH/openvibes-rules.key --rule-set baseline --issuer openvibes-1 > baseline/baseline.key
openvibes-admin rules sign /OFFLINE/PATH/openvibes-rules.key baseline/rules.json --rule-set baseline --version 1 --issuer openvibes-1 -o baseline/baseline.json
```

then commits both files to the branch (or hands them over for the commit). CI goes green; `@claude` reviews; the user merges and tags `v1`.

### Task 7: Pages picks up the rules RPMs (separate PR in `openvibes-project.github.io`)

**Files:**
- Modify: `scripts/collect.sh` (loop `for repo in openvibes-platform openvibes-agent openvibes-rules`), `.github/workflows/ci.yml` (download the latest `main` artifact `rules-rpms` from openvibes-rules like the other two), and the header comment.

- [ ] **Step 1:** Change, run the repository's own CI checks locally as its README says, open the PR for `@claude`. Merge after the rules repository has a green `main`.
