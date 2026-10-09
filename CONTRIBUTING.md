# Contributing

By submitting a contribution, you agree that it is licensed under the project's
[MIT License](LICENSE).

## Rules

- One rule per finding a person can act on; quiet by default. A rule that
  fires on most healthy hosts does not belong in the baseline.
- Ids: `port.<service>.exposed` or `package.<name>.installed`
  (`test.openvibes.running` is the one test trigger).
- Every rule carries `attack`: its MITRE ATT&CK pairs, primary first, e.g.
  `[{"tactic":"TA0001","technique":"T1190"}]`. Only the test triggers have
  none. Changing a mapping does not change what a rule matches, so it keeps
  its `version`.
- `finding_message` names what was seen (port and protocol) and the usual fix.
  Port rules say "listens on a non-loopback address": the agent sees the bind
  address, not whether a firewall blocks it.
- Read facts only as `facts['KEY']`, and only facts in `facts.allowlist`. A new
  fact needs an agent release first, and the allowlist follows the oldest
  agent the project still supports.
- Every rule needs at least one `match` and one `no_match` case in
  `tests/cases.json`. List facts are sorted and unique, as agents send them.
- Pull requests change `rules.json`; the maintainer signs `baseline.json`.
- A pull request that touches `baseline/baseline.key` or `.github/` gets a
  deliberate look from the maintainer: CI refuses a changed key after the
  first release, but a pull request runs its own workflow files, so that
  check is a guard against mistakes, not against a hostile change.

## Alarm rules (`alarms/`)

- Quiet over complete: a false alarm costs more than a missed one. A rule
  must not fire on a healthy web, database or build host.
- Ids: `alarm.<what>.<how>`. Map every rule to ATT&CK in `attack`, as for
  the baseline (`alarm.openvibes.test` is the exception). `kind` is always `process_event`. Use
  `programs` whenever the rule only concerns some programs.
- Match parents by `parent.name`, not `parent.exe`: a parent the agent read
  from `/proc` may have no readable exe. Allow for `dash` wherever a rule
  means `sh`.
- CEL subset v2 only: no list literals (write `a == 'x' || a == 'y'`).
  `alarms-check` refuses anything the agent would.
- Every rule needs `match` and `no_match` cases in `tests/alarm-cases.json`,
  including the near misses it is designed to ignore.

## AI-Assisted Contributions

AI coding tools may be used to prepare contributions, under these conditions:

1. **Disclose it.** A commit containing substantial AI-generated code or text
   carries a trailer naming the tool, for example
   `Co-Authored-By: Claude <noreply@anthropic.com>`. Alternatively, state in the
   pull request which parts were AI-assisted and with which tool.
2. **The human submitter is responsible.** You must understand, review, and test
   every line you submit. "The tool wrote it" is not a justification in review,
   and AI-assisted changes meet the same review bar as any other change.
3. **Never share secrets with AI tools.** Do not paste credentials or private
   keys into prompts; the rule-signing key never leaves the maintainer's
   offline storage.

Repository guidance for coding agents lives in [`AGENTS.md`](AGENTS.md).
