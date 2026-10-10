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

1. Change `baseline/rules.json` and `tests/cases.json`; `--sources-only` passes.
2. Sign with the next version (the private key stays offline). `rules sign`
   refuses a key file others can read, and FAT/exFAT sticks show every file
   as 0644, so sign from a private copy in memory and remove it after:

   ```sh
   K="$XDG_RUNTIME_DIR/openvibes-rules.key"   # tmpfs, only you can read it
   install -m 0600 /run/media/$USER/STICK/openvibes/openvibes-rules.key "$K"
   rm -f baseline/baseline.json
   openvibes-admin rules sign "$K" baseline/rules.json --rule-set baseline \
       --version N --issuer openvibes-1 -o baseline/baseline.json
   rm -f "$K"
   ```
3. Open a pull request; CI must be green; merge.
4. Tag `vN` on the merge commit. The release workflow builds, signs and
   publishes the RPM and tells the package repository to rebuild.

Re-sign (a new version, same rules) before the envelope has less than a
year left; CI refuses an envelope with less than 365 days.

The RPM version (and the release tag) is the baseline's `rule_set_version`.
The alarm rules (`alarms/`, rule set `baseline-alarms`) ship in the same
package, so an alarm-only change also re-signs the baseline at the next
version (same rules) to give the package a new version.

Apache-2.0 licensed. Contributions: [`CONTRIBUTING.md`](CONTRIBUTING.md).
