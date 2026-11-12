# Maintaining the rule sets

Where everything is, and how a release is signed and published. The
[README](../README.md) says what the rule sets are.

## Layout

| Path | What |
|---|---|
| `baseline/rules.json` | the rule set (schema 1), one rule per line |
| `baseline/baseline.json` | the signed envelope over the exact bytes of `rules.json` |
| `baseline/baseline.key` | `baseline openvibes-1 PUBLIC_KEY`, the trust line |
| `tests/cases.json` | facts and the expected outcome per rule |
| `facts.allowlist` | facts the oldest supported agent collects |
| `checker/` | `rules-check`, run by CI on every change |
| `alarms/rules.json` | the baseline alarm rules (`process_event`, rule set `baseline-alarms`) |
| `alarms/alarms.key` | the alarm rules' trust line (same key, scoped to `baseline-alarms`) |
| `tests/alarm-cases.json` | events and the expected outcome per alarm rule |
| `alarms-checker/` | `alarms-check`, run by CI on every change |
| `hardening/linux-l1/rules.json` | Linux level 1 hardening rules (`hardening-linux-l1`, P19), signed (`hardening-linux-l1.json` and `.key` beside it), shipped in the RPM |
| `tests/hardening-l1-cases.json` | facts and the expected outcome per hardening rule |
| `hardening.allowlist` | facts the hardening rules may read (P19 catalog) |
| `hardening-checker/` | `hardening-check`: `rules-check`'s source against the hardening agent pin (checked in CI and at release) |
| `openvibes-rules-baseline.spec` | the noarch RPM |

The rules are signed offline by the maintainer with `openvibes-admin rules
sign`; CI never holds the signing key. Design: openvibes-platform
`docs/specs/2026-09-28-baseline-rules-design.md`. Components:
[`docs/components/`](components/README.md).

## Releasing

One command, from an up-to-date `main`:

```sh
bash scripts/release.sh
```

It checks every rule set, asks once to release the next version (vN), asks
for the signing key's passphrase, and signs **every** rule set at vN
(baseline, alarms, and any set whose trust line exists). Then it checks the
signed envelopes, opens the pull request, merges it when CI is green, and
tags vN. The release workflow builds, signs and publishes the RPM and tells
the package repository to rebuild. If it stops partway (CI failed, Ctrl-C),
run it again: it continues the open `release-vN` pull request without
signing again.

At a terminal gpg asks for the passphrase, up to three times. The signing key stays offline and encrypted: `release.sh` decrypts it into
`$XDG_RUNTIME_DIR` (memory, only you can read it) for the signing alone and
removes it straight after, also on an error. It never reaches git, GitHub or
CI. By default it uses the one file matching
`/run/media/$USER/*/openvibes/openvibes-rules.key.gpg` (the stick);
`OPENVIBES_RULES_KEY=path` names another. To encrypt a plain key once (then
remove the plain copy):

```sh
gpg --symmetric --cipher-algo AES256 --no-symkey-cache \
    -o /run/media/$USER/STICK/openvibes/openvibes-rules.key.gpg \
    /run/media/$USER/STICK/openvibes/openvibes-rules.key
```

`bash tests/release-test.sh` tests the script with a throwaway key, a local
repository and a fake `gh`.

Release again (same rules are fine) before the envelopes have less than a
year left; CI refuses an envelope with less than 365 days.

The RPM version, the release tag and every envelope's `rule_set_version` are
the same number, so any change, alarm-only included, is one release.

