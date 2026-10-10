# Proposal: the first `hardening-linux-l1` rules (for review)

For the user's review before any rule is written. Spec: platform
`docs/specs/2026-10-09-hardening-rules-design.md` (#229); facts: protocol
P19 (`vectors/fact-catalog.json`, #45); collector: agent #64.

**Goal:** about 40 checks a typical Linux server should pass without
breaking anything, quiet by default. Every check judges facts the root
helper already collects. Our own wording and logic (ComplianceAsCode,
BSD-3, as reference; no CIS text or numbering). Each rule names its ATT&CK
pair (verified against ATT&CK 19.2).

**How to review:** for each line, keep, drop or change the severity. The
defaults are noted where a setting is unset (`""` / `-1` means "not set",
so the program's default applies).

## Decisions (user, 2026-10-10)

1. **Password expiry stays out** (`PASS_MAX_DAYS`): NIST SP 800-63B advises
   against forced rotation.
2. **IP forwarding is skipped on container hosts**: a container runtime
   installed (`package.names`: docker, docker-ce, moby-engine, podman,
   containerd, containerd.io, cri-o, kubelet) or running
   (`service.active`: docker, podman, containerd, crio, kubelet); flagged
   everywhere else.
3. **Three count facts join P19**: `accounts.uid0.count`,
   `accounts.empty_password.count`, `accounts.shell_users.count` (int),
   so rules can count accounts (protocol #45, agent #64).

The build waits until bulk triage (v0.2.7) is done.

## SSH (sshd settings)

| Rule | Sev. | Fires when | ATT&CK | Noise |
|---|---|---|---|---|
| `harden.ssh.permit_root_login` | high | `permitrootlogin` is `yes` (unset = `prohibit-password` since OpenSSH 7.0: passes) | TA0001 T1078.003 · TA0008 T1021.004 | low |
| `harden.ssh.password_authentication` | medium | `passwordauthentication` is not `no` (unset = `yes`) | TA0006 T1110 | **medium**: many hosts allow passwords |
| `harden.ssh.permit_empty_passwords` | high | `permitemptypasswords` is `yes` | TA0001 T1078.003 | very low |
| `harden.ssh.hostbased_authentication` | medium | `hostbasedauthentication` is `yes` | TA0008 T1021.004 | very low |
| `harden.ssh.ignore_rhosts` | medium | `ignorerhosts` is `no` | TA0008 T1021.004 | very low |
| `harden.ssh.permit_user_environment` | medium | `permituserenvironment` is `yes` | TA0004 T1548 | very low |
| `harden.ssh.max_auth_tries` | low | `maxauthtries` above 4, or unset (default 6) | TA0006 T1110 | medium |
| `harden.ssh.login_grace_time` | low | `logingracetime` above 60 s, or unset (default 120) | TA0006 T1110 | medium |
| `harden.ssh.x11_forwarding` | low | `x11forwarding` is `yes` | TA0008 T1021.004 | low |
| `harden.ssh.log_level` | low | `loglevel` is `quiet`, `fatal` or `error` | TA0112 T1685 | very low |
| `harden.ssh.config_permissions` | medium | `/etc/ssh/sshd_config` readable or writable by others, or not owned by root | TA0006 T1003 | low |

## Kernel and network (sysctl)

| Rule | Sev. | Fires when | ATT&CK | Noise |
|---|---|---|---|---|
| `harden.kernel.aslr` | high | `kernel.randomize_va_space` is not 2 | TA0004 T1068 | very low |
| `harden.kernel.ptrace_scope` | medium | `kernel.yama.ptrace_scope` is 0 | TA0004 T1055.008 | low (Debian/Ubuntu default 1) |
| `harden.kernel.unprivileged_bpf` | medium | `kernel.unprivileged_bpf_disabled` is 0 | TA0004 T1068 | low |
| `harden.kernel.kptr_restrict` | low | `kernel.kptr_restrict` is 0 | TA0004 T1068 | low |
| `harden.kernel.dmesg_restrict` | low | `kernel.dmesg_restrict` is 0 | TA0007 T1082 | medium |
| `harden.fs.protected_links` | medium | `fs.protected_hardlinks` or `fs.protected_symlinks` is 0 | TA0004 T1068 | very low |
| `harden.fs.suid_dumpable` | medium | `fs.suid_dumpable` is not 0 and cores are not piped to a handler | TA0006 T1003 | low |
| `harden.net.ip_forward` | low | `net.ipv4.ip_forward` is 1 on a host with no container runtime installed or running (decision 2) | TA0112 T1599 | low with the skip |
| `harden.net.send_redirects` | low | `conf.all.send_redirects` or `conf.default.send_redirects` is 1, not a router | TA0006 T1557 | medium |
| `harden.net.accept_source_route` | medium | IPv4 or IPv6 `accept_source_route` (all) is 1 | TA0006 T1557 | very low |
| `harden.net.accept_redirects` | low | IPv4 or IPv6 `accept_redirects` (all) is 1 | TA0006 T1557 | medium |
| `harden.net.icmp_broadcasts` | low | `icmp_echo_ignore_broadcasts` is 0 | TA0040 T1499 | very low |
| `harden.net.syncookies` | low | `tcp_syncookies` is 0 | TA0040 T1499 | very low |
| `harden.net.rp_filter` | low | `conf.all.rp_filter` is 0 | TA0006 T1557 | low |

## Files

| Rule | Sev. | Fires when | ATT&CK | Noise |
|---|---|---|---|---|
| `harden.files.shadow` | high | `/etc/shadow` (or its `-` backup) readable by others, or not owned by root | TA0006 T1003.008 | very low |
| `harden.files.gshadow` | high | the same for `/etc/gshadow` (and backup) | TA0006 T1003.008 | very low |
| `harden.files.passwd` | medium | `/etc/passwd` or `/etc/group` writable by group or others | TA0003 T1078.003 | very low |
| `harden.files.crontab` | low | `/etc/crontab` or `/etc/cron.d` writable by group or others | TA0003 T1053.003 | low |
| `harden.files.grub_cfg` | low | `grub.cfg` (grub2 or grub path) readable by others | TA0006 T1003 | medium (Debian 0444) |

## Accounts and login

| Rule | Sev. | Fires when | ATT&CK | Noise |
|---|---|---|---|---|
| `harden.accounts.extra_uid0` | critical | an account other than `root` has uid 0 (decision 3) | TA0004 T1078.003 | very low |
| `harden.accounts.empty_password` | critical | an account has an empty password field (decision 3) | TA0001 T1078.003 | very low |
| `harden.accounts.system_shell` | low | a system account (uid 1–999) has a login shell (decision 3) | TA0003 T1078.003 | medium |
| `harden.login.hash_method` | medium | `ENCRYPT_METHOD` is set and not `SHA512` or `YESCRYPT` | TA0006 T1110 | very low |
| `harden.login.pwquality_minlen` | low | `pam_pwquality.so` is in a PAM stack and `minlen` is below 12 | TA0006 T1110 | medium |
| `harden.login.faillock` | low | no `pam_faillock.so` in the PAM stacks, or `deny` is 0 | TA0006 T1110 | **medium**: Debian has no faillock by default |

## Services, modules, LSM

| Rule | Sev. | Fires when | ATT&CK | Noise |
|---|---|---|---|---|
| `harden.services.avahi` | low | `avahi-daemon.service` or `.socket` is enabled | TA0007 T1046 | medium (desktops) |
| `harden.modules.rare_protocols` | medium | `dccp`, `sctp`, `rds` or `tipc` is loaded | TA0008 T1210 | very low |
| `harden.lsm.selinux_off` | medium | a Fedora/RHEL-family host (`os.id_like`) with SELinux `disabled` | TA0112 T1685 | low |
| `harden.lsm.selinux_permissive` | low | a Fedora/RHEL-family host with SELinux `permissive` | TA0112 T1685 | low |
| `harden.lsm.apparmor_off` | medium | a Debian/Ubuntu host with AppArmor `disabled` | TA0112 T1685 | low |

**Total: 41 rules** (11 SSH, 14 kernel/network, 5 files, 6 accounts/login,
5 services/modules/LSM). Severity mix: 2 critical, 5 high, 15 medium, 19
low. L2 (audit rules, separate mounts and their options, stricter limits)
comes after this set is in use.

## How the rules are written and tested

- Each rule reads only catalog facts; checker pin and allowlist from the
  first agent release with the hardening collector (agent #64), CEL subset
  v2 (`startsWith`/`endsWith` for modes, as `!facts['file.etc_shadow.mode']
  .endsWith('0')` = others can read).
- Cases per rule: match, no_match, and unavailable (the source missing),
  plus one per OS family where a rule branches on `os.id_like`.
- Messages say what was seen and the fix in one or two sentences, as the
  baseline does ("SSH allows root to log in with a password
  (`PermitRootLogin yes`). Set it to `prohibit-password` or `no`.").
