# openvibes-rules: guidance for coding agents

The project's signed baseline rule set, its tests, the `rules-check` checker
and the `openvibes-rules-baseline` RPM. Read `README.md` first and follow
`CONTRIBUTING.md` for rule changes.

- Never create, read or ask for the rule-signing private key. Agents change
  `rules.json` and `tests/cases.json`; the maintainer signs `baseline.json`
  and commits it with `baseline.key`.
- Before a pull request: `cargo fmt --check`, `cargo clippy --locked
  --all-targets -- -D warnings`, `cargo test --locked`, and `rules-check`
  (`--sources-only` until the maintainer has signed). For RPM changes also
  `bash scripts/build-rpm.sh dist` in `registry.fedoraproject.org/fedora:44`.
- `checker/` pins the agent's `openvibes-core` and `openvibes-rules` at the
  **oldest agent release the project still supports**, not at the newest:
  the pinned evaluator runs every test case, so it is also the allowlist of
  CEL functions (a rule using a newer function fails its cases). Move the pin
  only when that minimum agent version moves, together with
  `facts.allowlist`. A later rule set that needs newer CEL (for example
  alarms on the subset-v2 functions) gets its own pin and allowlist; do not
  move the baseline's pin up for it.
- CI refuses a changed `baseline.key` once a release exists; a pull request
  runs its own workflow files, so changes to `baseline.key` or `.github/`
  still need a deliberate human review. Never change either unasked.
- CI job names `Rule checks` and `RPM (fedora:44)` are required by the
  repository ruleset; renaming them needs the ruleset changed first.
- `scripts/sign-rpms.sh` and `packaging/openvibes-packages.gpg` are copies from
  openvibes-platform; change them there first.
- Every component has a page in `docs/components/`, updated in the same change.
- Commits end with a co-author trailer naming the tool. Git identity:
  `itismelime`, `26064407+itismelime@users.noreply.github.com`.
