# `rules-check`

**Purpose.** Everything a baseline change must satisfy before merge and
release, using the agent's own `openvibes-core` and `openvibes-rules` crates
(pinned in `checker/Cargo.toml`), so the checks cannot drift from what agents
accept.

**Interface.**

```text
rules-check --dir baseline --cases tests/cases.json --allowlist facts.allowlist
            [--previous-version N] [--min-days 365] [--sources-only]
            [--set baseline]
```

Prints `ok: R rules, C cases, vN expires in D days`, or one `error: …` line per
failure and exits 1 (2 for bad arguments). Checks:

1. `rules.json` is a valid schema-1 rule set (unique ids, limits).
2. `baseline.json` loads with `baseline.key` in the agent's loader, and its
   payload equals `rules.json` byte for byte.
3. Its version is above `--previous-version`, and at least `--min-days` remain.
4. Every expression reads facts only as `facts['KEY']`, with KEY in the allowlist.
5. Every case evaluates to its expected outcome in the agent's evaluator (the
   rules signed in memory with a throwaway key), every rule has a `match` and a
   `no_match` case, and case facts are valid agent facts (lists sorted, unique).
6. ATT&CK: every rule except the test triggers (`test.openvibes.running`,
   `alarm.openvibes.test`) carries 1 to 16 distinct, well-formed ATT&CK
   pairs in `attack` (protocol P18; `checker/src/attack.rs`, shared by both
   checkers). The pinned agent ignores the field, so this is the only check
   on it.

`--sources-only` runs 1, 4, 5 and 6, for work before the maintainer signs. CI
passes `--previous-version` from the latest `v*` tag: the tag's number when
`baseline.json` changed since that tag, one less when it did not.

The pin (`checker/Cargo.toml`) is the oldest supported agent, so check 5 also
refuses CEL functions that agent does not know (for example the subset-v2
string functions), without a separate list.

`--set NAME` names the signed envelope and trust line (`NAME.json`,
`NAME.key`; default `baseline`). The same source builds
[`hardening-check`](hardening-check.md).

**Failure behaviour.** All failures are collected and printed before exiting.

**How to test.** `cargo test --locked` (unit tests with fixed keys and times).
