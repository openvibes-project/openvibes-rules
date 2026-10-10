# openvibes-rules

Signed baseline rule sets for OpenVIBES agents.

The baseline is a small, quiet set of rules that flags risky exposure on a
Linux host: services listening beyond loopback that are usually meant to stay
local (Docker API, Redis, databases, kubelet, etcd, Ollama, Kafka, RDP, WinRM,
NFS, X11, telnet, …) and insecure server packages (NIS, TFTP, xinetd, talk,
telnet and rsh servers), matched by both Fedora/RHEL and Debian/Ubuntu package
names. The alarm rules raise threat alarms from process starts. Every rule
except the two test rules carries its MITRE ATT&CK techniques (`attack`); the
two info-level test rules fire on `openvibes-test` (agent 0.2.6), so a host
can be checked end to end.

A fresh OpenVIBES platform installs it as the RPM `openvibes-rules-baseline`;
Setup trusts its key and publishes it, a newer package publishes itself on
upgrade (platform 0.2.6), and every enrolled agent evaluates it. Version 3:
baseline v3 (42 rules), alarms v2 (6 rules).

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
| `hardening/linux-l1/rules.json` | Linux level 1 hardening rules (`hardening-linux-l1`, P19), not signed yet |
| `tests/hardening-l1-cases.json` | facts and the expected outcome per hardening rule |
| `hardening.allowlist` | facts the hardening rules may read (P19 catalog) |
| `hardening-checker/` | `hardening-check`: `rules-check`'s source against the hardening agent pin (not in CI yet) |
| `openvibes-rules-baseline.spec` | the noarch RPM |

The rules are signed offline by the maintainer with `openvibes-admin rules
sign`; CI never holds the signing key. Design: openvibes-platform
`docs/specs/2026-09-28-baseline-rules-design.md`. Components:
[`docs/components/`](docs/components/README.md).

## Checking locally

```sh
cargo test --locked
cargo run --locked -p rules-check -- --dir baseline --cases tests/cases.json \
    --allowlist facts.allowlist            # add --sources-only before signing
```

## Releasing (maintainer)

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

Apache-2.0 licensed. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
