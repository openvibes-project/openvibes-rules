# Hardening rules, Linux level 1 (`hardening-linux-l1`)

## Purpose

Configuration checks a typical Linux server should pass without any service
impact (platform spec `2026-10-09-hardening-rules-design.md`, protocol P19):
SSH, kernel and network sysctls, permissions of key system files, accounts
and login policy, unneeded services, and SELinux/AppArmor. Each rule judges
facts the agent's root-facts helper collects (the `hardening` collector);
no external scanner runs on hosts. The selection was approved by the user
from the proposal in `docs/plans/2026-10-10-hardening-l1-proposal.md` (#14).

| Rule | Severity | Title |
|---|---|---|
| `harden.ssh.permit_root_login` | high | SSH allows root to log in with a password |
| `harden.ssh.password_authentication` | medium | SSH accepts passwords |
| `harden.ssh.permit_empty_passwords` | high | SSH allows empty passwords |
| `harden.ssh.hostbased_authentication` | medium | SSH trusts other hosts |
| `harden.ssh.ignore_rhosts` | medium | SSH reads .rhosts files |
| `harden.ssh.permit_user_environment` | medium | SSH lets users set the login environment |
| `harden.ssh.max_auth_tries` | low | SSH allows many login attempts per connection |
| `harden.ssh.login_grace_time` | low | SSH waits long for a login |
| `harden.ssh.x11_forwarding` | low | SSH forwards X11 |
| `harden.ssh.log_level` | low | SSH logs too little |
| `harden.ssh.config_permissions` | medium | sshd_config is open to other users |
| `harden.kernel.aslr` | high | Address space randomisation is weakened |
| `harden.kernel.ptrace_scope` | medium | Any process can trace another of the same user |
| `harden.kernel.unprivileged_bpf` | medium | Unprivileged users can load BPF programs |
| `harden.kernel.kptr_restrict` | low | Kernel addresses are visible to users |
| `harden.kernel.dmesg_restrict` | low | Users can read the kernel log |
| `harden.fs.protected_links` | medium | Link protections are off |
| `harden.fs.suid_dumpable` | medium | Privileged programs can write core dumps |
| `harden.net.ip_forward` | low | The host forwards IP packets |
| `harden.net.send_redirects` | low | The host sends ICMP redirects |
| `harden.net.accept_source_route` | medium | The host accepts source-routed IPv4 packets |
| `harden.net.accept_source_route_v6` | medium | The host accepts source-routed IPv6 packets |
| `harden.net.accept_redirects` | low | The host accepts IPv4 ICMP redirects |
| `harden.net.accept_redirects_v6` | low | The host accepts IPv6 ICMP redirects |
| `harden.net.icmp_broadcasts` | low | The host answers broadcast pings |
| `harden.net.syncookies` | low | SYN cookies are off |
| `harden.net.rp_filter` | low | Reverse path filtering is off |
| `harden.files.shadow` | high | /etc/shadow is open to other users |
| `harden.files.gshadow` | high | /etc/gshadow is open to other users |
| `harden.files.passwd` | medium | /etc/passwd or /etc/group can be changed by other users |
| `harden.files.crontab` | low | System cron files can be changed by other users |
| `harden.files.grub_cfg` | low | The boot loader configuration is readable by all users |
| `harden.accounts.extra_uid0` | critical | An account other than root has uid 0 |
| `harden.accounts.empty_password` | critical | An account has an empty password |
| `harden.accounts.system_shell` | low | A system account has a login shell |
| `harden.login.hash_method` | medium | Passwords are hashed with a weak method |
| `harden.login.pwquality_minlen` | low | Passwords may be shorter than 12 characters |
| `harden.login.faillock` | low | Failed logins never lock an account |
| `harden.services.avahi` | low | Avahi (mDNS) is enabled |
| `harden.modules.rare_protocols` | medium | A rarely used network protocol module is loaded |
| `harden.lsm.selinux_off` | medium | SELinux is disabled |
| `harden.lsm.selinux_permissive` | low | SELinux only logs |
| `harden.lsm.apparmor_off` | medium | AppArmor is disabled |

Every rule carries its MITRE ATT&CK pairs in `attack` (protocol P18).

## Interfaces

- `hardening/linux-l1/rules.json`: the rule set (schema 1), snapshot rules
  over `facts`, CEL subset v2 (`startsWith`, `endsWith`).
- `hardening.allowlist`: the fact keys these rules may read: the P19
  catalog's `hardening` facts plus `os.*` and `package.names`.
- `tests/hardening-l1-cases.json`: per rule, a match, a no_match and an
  `unavailable` case (the source the rule reads is missing), and one case
  per OS family where a rule branches on `os.id_like`.
- Signing: the maintainer adds the trust line and the signed envelope
  (`hardening/linux-l1/hardening-linux-l1.key` and `.json`, checked with
  `--set hardening-linux-l1`); not signed yet.

## Design choices (quiet over complete)

- **Unset means the program's default.** sshd settings not set are `""` or
  `-1`; rules fire on an unset value only where the default is the weak one
  (PasswordAuthentication, MaxAuthTries 6, LoginGraceTime 120).
- **A missing fact makes the whole rule unavailable** (the evaluator checks
  every referenced fact first), so IPv4 and IPv6 sysctls are separate rules
  (`*_v6`): a host without IPv6 keeps its IPv4 checks. This makes 43 rules,
  two more than the 41 proposed.
- **File modes are compared with accepted values** (0644 or stricter for
  `/etc/passwd`, `/etc/group` and `/etc/crontab`; 0755 or stricter for
  `/etc/cron.d`; 0600/0640 or stricter for `sshd_config`): the subset has no
  list literals, and testing each permission digit exactly exceeds the
  evaluator's node budget. An unusual mode, not only a writable one, fires.
- **IP forwarding is skipped on container hosts** (user decision): a
  runtime installed (`package.names`) or running (`service.active`).
  `send_redirects` fires only when the host is not forwarding (a router
  sends redirects on purpose).
- **Accounts are counted** (`accounts.*.count`, user decision), so a rule
  says "more than one uid 0" without listing names.
- **Password expiry is left out** (user decision: NIST SP 800-63B advises
  against forced rotation).
- **Our own wording and logic.** ComplianceAsCode (BSD-3-Clause) was a
  reference for which settings matter; no CIS text or numbering (see
  `NOTICE`).

## Failure behaviour

A rule whose facts are missing (the helper could not read the file, or the
kernel has no such setting) is `unavailable`, never a pass or a finding.

## How to test

```text
cargo run -p hardening-check -- --dir hardening/linux-l1 \
  --cases tests/hardening-l1-cases.json --allowlist hardening.allowlist --sources-only
```

prints `ok: 43 rules, 149 cases`. After signing, drop `--sources-only` and add
`--set hardening-linux-l1`.
