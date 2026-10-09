//! `rules-check`: the checks every baseline change must pass (openvibes-platform
//! `docs/specs/2026-09-28-baseline-rules-design.md` §6).
//!
//! ```text
//! rules-check --dir baseline --cases tests/cases.json --allowlist facts.allowlist
//!             [--previous-version N] [--min-days 365] [--sources-only]
//! ```
//!
//! `--sources-only` skips the signed envelope (checks 2 and 3), for work in
//! progress before the signer has signed. Prints `ok: …` or one `error: …`
//! line per failure and exits 1.

mod attack;
mod checks;

use std::{
    fs,
    path::PathBuf,
    process::ExitCode,
    time::{SystemTime, UNIX_EPOCH},
};

const DAY_MS: i64 = 86_400_000;

struct Args {
    dir: PathBuf,
    cases: PathBuf,
    allowlist: PathBuf,
    previous_version: Option<u64>,
    min_days: i64,
    sources_only: bool,
}

fn args() -> Result<Args, String> {
    let (mut dir, mut cases, mut allowlist) = (None, None, None);
    let (mut previous_version, mut min_days, mut sources_only) = (None, 365, false);
    let mut it = std::env::args().skip(1);
    while let Some(flag) = it.next() {
        let mut value = || it.next().ok_or(format!("{flag} needs a value"));
        match flag.as_str() {
            "--dir" => dir = Some(PathBuf::from(value()?)),
            "--cases" => cases = Some(PathBuf::from(value()?)),
            "--allowlist" => allowlist = Some(PathBuf::from(value()?)),
            "--previous-version" => {
                previous_version = Some(value()?.parse().map_err(|_| "--previous-version N")?);
            }
            "--min-days" => min_days = value()?.parse().map_err(|_| "--min-days N")?,
            "--sources-only" => sources_only = true,
            _ => return Err(format!("unknown argument {flag}")),
        }
    }
    Ok(Args {
        dir: dir.ok_or("--dir is required")?,
        cases: cases.ok_or("--cases is required")?,
        allowlist: allowlist.ok_or("--allowlist is required")?,
        previous_version,
        min_days,
        sources_only,
    })
}

fn read(path: &PathBuf) -> Result<Vec<u8>, String> {
    fs::read(path).map_err(|e| format!("{}: {e}", path.display()))
}

fn check(args: &Args, now_ms: i64) -> Result<String, Vec<String>> {
    let one = |error: String| vec![error];
    let rules_bytes = read(&args.dir.join("rules.json")).map_err(one)?;
    let rules = checks::rule_set(&rules_bytes).map_err(one)?;
    let allowed: Vec<String> = String::from_utf8_lossy(&read(&args.allowlist).map_err(one)?)
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .map(str::to_owned)
        .collect();
    let cases: Vec<checks::Case> = serde_json::from_slice(&read(&args.cases).map_err(one)?)
        .map_err(|e| one(format!("{}: {e}", args.cases.display())))?;

    let mut errors = Vec::new();
    for rule in &rules.rules {
        match checks::fact_keys(&rule.expression) {
            Ok(keys) => errors.extend(
                keys.into_iter()
                    .filter(|key| !allowed.contains(key))
                    .map(|key| format!("{}: fact {key} is not in the allowlist", rule.id.as_str())),
            ),
            Err(error) => errors.push(format!("{}: {error}", rule.id.as_str())),
        }
    }
    errors.extend(attack::check(&rules_bytes));
    errors.extend(checks::run_cases(&rules_bytes, &cases, now_ms));
    let mut summary = format!("ok: {} rules, {} cases", rules.rules.len(), cases.len());

    if !args.sources_only {
        let signed = read(&args.dir.join("baseline.json"));
        let key = read(&args.dir.join("baseline.key"))
            .and_then(|bytes| checks::key_line(&String::from_utf8_lossy(&bytes)));
        match (signed, key) {
            (Ok(signed), Ok(key)) => match checks::envelope(&signed, &key, &rules_bytes, now_ms) {
                Ok(envelope) => {
                    if let Some(previous) = args.previous_version
                        && envelope.rule_set_version <= previous
                    {
                        errors.push(format!(
                            "baseline.json: version {} is not above the released {previous}",
                            envelope.rule_set_version
                        ));
                    }
                    let left_days = (envelope.expires_at_unix_ms - now_ms) / DAY_MS;
                    if left_days < args.min_days {
                        errors.push(format!(
                            "baseline.json: expires in {left_days} days, fewer than {} (re-sign)",
                            args.min_days
                        ));
                    }
                    summary.push_str(&format!(
                        ", v{} expires in {left_days} days",
                        envelope.rule_set_version
                    ));
                }
                Err(error) => errors.push(error),
            },
            (signed, key) => errors.extend(signed.err().into_iter().chain(key.err())),
        }
    }
    if errors.is_empty() {
        Ok(summary)
    } else {
        Err(errors)
    }
}

fn main() -> ExitCode {
    let args = match args() {
        Ok(args) => args,
        Err(error) => {
            eprintln!("rules-check: {error}");
            return ExitCode::from(2);
        }
    };
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |elapsed| {
            i64::try_from(elapsed.as_millis()).unwrap_or(i64::MAX)
        });
    match check(&args, now_ms) {
        Ok(summary) => {
            println!("{summary}");
            ExitCode::SUCCESS
        }
        Err(errors) => {
            for error in errors {
                println!("error: {error}");
            }
            ExitCode::FAILURE
        }
    }
}
