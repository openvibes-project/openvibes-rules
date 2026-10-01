# Baseline alarm rules (`baseline-alarms`)

## Purpose

A small, quiet starter set of threat-alarm rules (protocol P14,
`process_event`), so a fresh install with `process_events` on raises alarms
without the operator writing rules first. Each rule names a process start
that healthy hosts almost never make:

| Rule | Fires when |
|---|---|
| `alarm.web_server.shell` | `nginx`, `httpd`, `apache2`, `lighttpd`, `caddy` or `php-fpm*` starts a shell |
| `alarm.database.shell` | `mysqld`, `mariadbd`, `redis-server` or `mongod` starts a shell |
| `alarm.exec.dev_shm` | a program runs from `/dev/shm/` |
| `alarm.shell.dev_tcp` | a shell command line uses `/dev/tcp/` or `/dev/udp/` (reverse shell) |
| `alarm.netcat.exec` | netcat runs with `-e`, `--exec` or `--sh-exec` |

## Interfaces

- `alarms/rules.json`: the rule set (schema 1), every rule `kind:
  process_event`, CEL subset v2 over the `event` keys.
- `alarms/alarms.key`: the trust line `baseline-alarms openvibes-1 KEY`. It
  is the same maintainer key as the baseline, scoped to this rule set.
- `alarms/alarms.json`: the signed envelope, made by the maintainer (not yet
  signed; see Releasing).
- `tests/alarm-cases.json`: an `event` map and the expected outcome per case.

## Design choices (quiet over complete)

- **Shells.** A shell is `sh`, `dash`, `bash`, `zsh`, `ksh`, `ash` or
  `busybox`. On Debian and Ubuntu `/bin/sh` is dash and `process.name` is
  `dash`.
- **Parents are matched by name, not exe.** A parent the agent learnt from
  `/proc` (started before the agent, or a worker forked without exec) may
  have no readable exe, but always has a name (its `comm`).
- **Postgres is left out.** `archive_command` and `restore_command`
  legitimately run shells.
- **`/tmp` is left out.** Build and test tools run binaries from it all the
  time; `/dev/shm` does not have that problem.
- **`nc -c` is left out.** On `nc.openbsd` it means TLS, not exec.
- **CGI.** CGI scripts written in shell are the known false positive of
  `alarm.web_server.shell` (confidence 70). Suppress per host, or per
  program, in the console.
- **Prefilters.** `programs` lists let the agent skip a rule for any other
  program. `alarm.exec.dev_shm` cannot have one; its check is a single
  `startsWith`.

## Failure behaviour

An agent before P14 must not be given this rule set: it would fail every
rule. Platform Setup publishes it, and an agent uses it, only together with
`process_events`. `alarms-check` refuses any rule the pinned agent would
refuse: list literals, unknown keys, `facts`, or a cost over the bound.

## How to test

```sh
cargo run --locked -p alarms-check -- --dir alarms --cases tests/alarm-cases.json --sources-only
```

## Releasing (maintainer)

1. Sign `alarms/rules.json` with the same offline key as the baseline, as
   rule set `baseline-alarms`:

   ```sh
   openvibes-admin rules sign "$K" alarms/rules.json --rule-set baseline-alarms \
       --version N --issuer openvibes-1 -o alarms/alarms.json
   ```

2. In the same pull request, add `alarms.json` and `alarms.key` to the RPM
   (`openvibes-rules-baseline.spec`).
3. CI then checks the envelope too: it must verify, carry exactly
   `rules.json`, and have a year left.
