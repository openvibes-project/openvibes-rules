# alarms-check

## Purpose

Checks the baseline alarm rule set (`alarms/`) on every change, using the
agent's own compiler and evaluator, so a rule that agents would refuse or
mis-evaluate never reaches a signature.

## Interfaces

```text
alarms-check --dir alarms --cases tests/alarm-cases.json
             [--previous-version N] [--min-days 365] [--sources-only]
```

Checks, each reported as one `error:` line (exit 1):

1. Every rule is `kind: process_event`, and the pinned agent's `check_rule`
   accepts it (CEL subset v2, the closed `event` keys, the cost bound).
2. Every rule has at least one `match` case and one `no_match` case, and
   every case names an existing rule.
3. Every case is evaluated by the agent's `CompiledEventRules::evaluate`
   (the `programs` prefilter included) on `rules.json` signed in memory
   with a throwaway key. The outcome must be the expected `match`,
   `no_match` or `unavailable`.
4. ATT&CK: every rule except the test triggers (`test.openvibes.running`,
   `alarm.openvibes.test`) carries 1 to 16 distinct, well-formed ATT&CK
   pairs in `attack` (protocol P18; `checker/src/attack.rs`, shared by both
   checkers). The pinned agent ignores the field, so this is the only check
   on it.
5. Without `--sources-only`: `alarms.json` verifies against `alarms.key`,
   carries exactly `rules.json`, has `--min-days` left, and is above
   `--previous-version`.

## Configuration

`alarms-checker/Cargo.toml` pins `openvibes-core` and `openvibes-rules` at
the oldest agent that evaluates `process_event` rules. That pin is
independent of `rules-check`'s pin, which follows the oldest agent overall.

## Failure behaviour

A refused rule or a wrong case fails CI's `Rule checks` job. Before the
maintainer has signed, CI runs it with `--sources-only`.

## How to test

```sh
cargo test --locked -p alarms-check
```
