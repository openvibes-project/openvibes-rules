<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/openvibes-project/openvibes-agent/main/docs/brand/openvibes-wordmark-dark.svg">
    <img src="https://raw.githubusercontent.com/openvibes-project/openvibes-agent/main/docs/brand/openvibes-wordmark-light.svg" alt="OpenVIBES" width="520">
  </picture>
</p>

<h3 align="center">OpenVIBES Rules</h3>

<p align="center">
  The signed rule sets that every <a href="https://github.com/openvibes-project">OpenVIBES</a> agent runs out of the box.
</p>

## The rule sets

| Set | Rules | What it checks |
|---|---|---|
| `baseline` | 42 | Risky exposure on a Linux host: services listening beyond the host that should stay local (Docker API, Redis, databases, etcd, RDP, telnet, …) and insecure server packages (NIS, TFTP, rsh, …). |
| `baseline-alarms` | 6 | Threat alarms from program starts, each with a plain explanation and what to check. |
| `hardening-linux-l1` | 43 | Linux hardening, level 1: sshd, kernel settings, file permissions, mounts, services, accounts, audit and login settings. |

Every rule names the MITRE ATT&CK techniques it covers, except two harmless
test rules that fire on `openvibes-test`, so you can check a host end to end.

## How they reach your hosts

You don't install anything from here. The platform comes with these sets
as the package `openvibes-rules-baseline`: Setup publishes them, and a
newer package publishes itself when the platform upgrades. Every enrolled
agent then runs the baseline and the alarms. Hardening runs on every Linux
host by default; turn it off for all hosts or per host group in the console.

The rules are signed offline by the maintainer; CI never holds the signing
key, and agents refuse anything that isn't signed by a key they trust.

## Check locally

```sh
cargo test --locked
cargo run --locked -p rules-check -- --dir baseline --cases tests/cases.json \
    --allowlist facts.allowlist
```

Where everything is and how a release is made:
[`docs/maintaining.md`](docs/maintaining.md). One page per rule set and
checker: [`docs/components/`](docs/components/README.md).

## Contributing

Issues and pull requests are welcome; see [`CONTRIBUTING.md`](CONTRIBUTING.md).
Security problems: please use private vulnerability reporting, not a public
issue.

**AI disclosure:** OpenVIBES is built with the help of AI coding tools
(Claude Code and Codex). Every change goes through a pull request and the
full CI before it is merged.

Licensed under the [Apache License 2.0](LICENSE).
