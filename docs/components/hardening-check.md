# `hardening-check`

**Purpose.** The checks of [`rules-check`](rules-check.md) for the hardening
rule sets: the same source (`checker/src`), built in `hardening-checker/`
against another agent pin, the first agent with the hardening collector
(P19). Its evaluator is the CEL allowlist for these sets (subset v2 string
methods), so the baseline's pin stays at the oldest agent (AGENTS.md).

**Interface.** As `rules-check`, plus `--set NAME` (both checkers): the
signed envelope and trust line are `NAME.json` and `NAME.key` in `--dir`
(default `baseline`).

```text
hardening-check --dir hardening/linux-l1 --cases tests/hardening-l1-cases.json \
                --allowlist hardening.allowlist --set hardening-linux-l1 [--sources-only]
```

**Pin.** `hardening-checker/Cargo.toml` pins agent #64's commit until the
agent release that ships the hardening collector; it moves to that release
then, with `hardening.allowlist` from the protocol's fact catalog.

**Failure behaviour and tests.** As `rules-check`.

**CI.** The "Rule checks" job runs it on every pull request and push to
`main`: sources only until `hardening/linux-l1/hardening-linux-l1.json`
(the signed set) exists, then with `--set hardening-linux-l1`.
