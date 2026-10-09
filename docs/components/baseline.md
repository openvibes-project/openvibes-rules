# Baseline rule set and `openvibes-rules-baseline`

**Purpose.** Quiet default findings for a fresh platform: 41 rules, 35 on
listening ports bound beyond loopback and 6 on insecure server packages
(openvibes-platform spec `2026-09-28-baseline-rules-design.md` §5, widened
in version 2 to more applications). Package rules match both Fedora/RHEL and
Debian/Ubuntu package names. The set is Linux-only; other operating systems
get their own rule sets, so an agent loads only its own OS's rules.

**Interfaces.**
- `baseline/rules.json`: schema-1 rule set, id `baseline`.
- `baseline/baseline.json`: Ed25519-signed envelope, issuer `openvibes-1`,
  730 days valid when signed, payload = the exact bytes of `rules.json`.
- `baseline/baseline.key`: `baseline openvibes-1 PUBLIC_KEY`.
- RPM `openvibes-rules-baseline` (noarch, Version = envelope version) installs
  the last two to `/usr/share/openvibes/rules/` (0644). openvibes-admin Setup
  step 11 and Repair read exactly these paths: `rules trust add` with the key
  line, then `rules publish` of the envelope; the local agent gets the same key.

**Key pinning.** Once a release exists, CI refuses a change to
`baseline.key` (the key Setup trusts from the RPM); rotating it needs its own
design.

**Configuration.** None; operators who want other rules sign their own sets
with `openvibes-admin rules keygen|sign`.

**Failure behaviour.** An expired envelope is refused by `rules publish` and by
agents; CI refuses one with less than 365 days left, and Health warns under
90 days on a platform. A rule whose fact an older agent lacks evaluates to
`Unavailable`; the allowlist check keeps such rules out.

**How to test.** `rules-check` (see [rules-check.md](rules-check.md));
`bash scripts/build-rpm.sh dist` in `fedora:44` builds and checks the RPM.
