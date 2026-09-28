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
  same revision as openvibes-platform; move both pins together.
- CI job names `Rule checks` and `RPM (fedora:44)` are required by the
  repository ruleset; renaming them needs the ruleset changed first.
- `scripts/sign-rpms.sh` and `packaging/openvibes-packages.gpg` are copies from
  openvibes-platform; change them there first.
- Every component has a page in `docs/components/`, updated in the same change.
- Commits end with a co-author trailer naming the tool. Git identity:
  `itismelime`, `26064407+itismelime@users.noreply.github.com`.
