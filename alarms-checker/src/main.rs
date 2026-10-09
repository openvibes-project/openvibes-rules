//! `alarms-check`: the checks every change to the baseline alarm rule set
//! (`alarms/`, rule set `baseline-alarms`, protocol P14) must pass.
//!
//! ```text
//! alarms-check --dir alarms --cases tests/alarm-cases.json
//!              [--previous-version N] [--min-days 365] [--sources-only]
//! ```
//!
//! Every rule is a `process_event` rule that the pinned agent compiles (CEL
//! subset v2, the closed `event` key set, the cost bound). Every case runs
//! through the agent's own evaluator, `programs` prefilter included, after
//! signing `rules.json` in memory with a throwaway key. Without
//! `--sources-only` the signed envelope `alarms.json` must verify against
//! `alarms.key`, carry exactly `rules.json`, and have `--min-days` left.

#[path = "../../checker/src/attack.rs"]
mod attack;

use std::{
    collections::BTreeMap,
    fs,
    path::{Path, PathBuf},
    process::ExitCode,
    time::{Duration, SystemTime, UNIX_EPOCH},
};

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Identifier, PayloadEncoding, ResourceLimits, RuleKind, RuleSet, SchemaVersion,
    SignedRuleEnvelope,
};
use openvibes_rules::{
    EvaluationClock, EventValue, LoadContext, ProcessEvent, RuleLoader, TrustedRuleKey,
    VerifiedRuleSet, check_rule, compile_event_rules, signing_preimage,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

const RULE_SET: &str = "baseline-alarms";
const DAY_MS: i64 = 86_400_000;

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct Case {
    rule: String,
    name: String,
    event: BTreeMap<String, serde_json::Value>,
    expect: Expect,
}

#[derive(Clone, Copy, Debug, Deserialize, Eq, PartialEq)]
#[serde(rename_all = "snake_case")]
enum Expect {
    Match,
    NoMatch,
    Unavailable,
}

struct Clock(i64);
impl EvaluationClock for Clock {
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }
    fn unix_ms(&self) -> i64 {
        self.0
    }
}

fn id(value: &str) -> Result<Identifier, String> {
    Identifier::new(value).map_err(|_| format!("{value}: not an identifier"))
}

/// `rules_bytes` signed in memory with a throwaway key, for evaluating cases.
fn throwaway_verified(rules_bytes: &[u8], now_ms: i64) -> Result<VerifiedRuleSet, String> {
    let payload = String::from_utf8(rules_bytes.to_vec()).map_err(|_| "rules.json: not UTF-8")?;
    let key = SigningKey::from_bytes(&[7; 32]);
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id(RULE_SET)?,
        rule_set_version: 1,
        issuer_key_id: id("throwaway")?,
        created_at_unix_ms: now_ms,
        expires_at_unix_ms: now_ms + DAY_MS,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload_encoding: PayloadEncoding::Json,
        payload,
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).map_err(|e| format!("{e:?}"))?;
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let trusted = TrustedRuleKey::new(
        id(RULE_SET)?,
        id("throwaway")?,
        key.verifying_key().to_bytes(),
    )
    .map_err(|e| format!("{e:?}"))?;
    let loader =
        RuleLoader::new(vec![trusted], ResourceLimits::V1).map_err(|e| format!("{e:?}"))?;
    let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    loader
        .load_json(
            &bytes,
            LoadContext {
                expected_rule_set_id: &id(RULE_SET)?,
                now_unix_ms: now_ms,
                last_accepted: None,
            },
        )
        .map_err(|e| format!("rules.json: refused by the agent's loader: {e:?}"))
}

/// A case's `event` object as the agent binds it.
fn event(values: &BTreeMap<String, serde_json::Value>) -> Result<ProcessEvent, String> {
    let mut event = ProcessEvent::default();
    for (key, value) in values {
        let value = match value {
            serde_json::Value::String(text) => EventValue::String(text.clone()),
            serde_json::Value::Bool(flag) => EventValue::Boolean(*flag),
            serde_json::Value::Number(n) => {
                EventValue::Integer(n.as_i64().ok_or(format!("{key}: not an integer"))?)
            }
            serde_json::Value::Array(items) => EventValue::Strings(
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<_>>()
                    .ok_or(format!("{key}: not a list of strings"))?,
            ),
            _ => return Err(format!("{key}: unsupported value")),
        };
        event
            .set(key, value)
            .map_err(|e| format!("{key}: refused by the agent ({e})"))?;
    }
    Ok(event)
}

fn check(dir: &Path, cases_path: &Path, now_ms: i64) -> (Vec<String>, Vec<String>) {
    let mut errors = Vec::new();
    let mut notes = Vec::new();
    let rules_bytes = match fs::read(dir.join("rules.json")) {
        Ok(bytes) => bytes,
        Err(e) => return (vec![format!("rules.json: {e}")], notes),
    };
    let rules: RuleSet = match serde_json::from_slice(&rules_bytes) {
        Ok(rules) => rules,
        Err(e) => return (vec![format!("rules.json: {e}")], notes),
    };
    let cases: Vec<Case> = match fs::read(cases_path)
        .map_err(|e| e.to_string())
        .and_then(|bytes| serde_json::from_slice(&bytes).map_err(|e| e.to_string()))
    {
        Ok(cases) => cases,
        Err(e) => return (vec![format!("{}: {e}", cases_path.display())], notes),
    };

    errors.extend(attack::check(&rules_bytes));
    for rule in &rules.rules {
        let name = rule.id.as_str();
        if rule.kind != RuleKind::ProcessEvent {
            errors.push(format!("{name}: not a process_event rule"));
        }
        if let Err(e) = check_rule(rule, ResourceLimits::V1) {
            errors.push(format!("{name}: the agent refuses it: {e:?}"));
        }
        for expect in [Expect::Match, Expect::NoMatch] {
            if !cases.iter().any(|c| c.rule == name && c.expect == expect) {
                errors.push(format!("{name}: no {expect:?} case"));
            }
        }
    }
    for case in &cases {
        if !rules.rules.iter().any(|rule| rule.id.as_str() == case.rule) {
            errors.push(format!("case {:?}: no rule {}", case.name, case.rule));
        }
    }
    if !errors.is_empty() {
        return (errors, notes);
    }

    let bundle = match throwaway_verified(&rules_bytes, now_ms) {
        Ok(bundle) => bundle,
        Err(e) => return (vec![e], notes),
    };
    let compiled = compile_event_rules(&bundle, ResourceLimits::V1);
    for (rule, error) in &compiled.refused {
        errors.push(format!("{}: refused at compile: {error:?}", rule.as_str()));
    }
    for case in &cases {
        let event = match event(&case.event) {
            Ok(event) => event,
            Err(e) => {
                errors.push(format!("case {:?}: {e}", case.name));
                continue;
            }
        };
        // A rule the `programs` prefilter skips did not match.
        let got = compiled
            .evaluate(&bundle, &event, &Clock(now_ms))
            .into_iter()
            .find(|outcome| outcome.rule_id.as_str() == case.rule)
            .map_or(Ok(Expect::NoMatch), |outcome| match outcome.failure {
                Some(error) => Err(format!("{error:?}")),
                None if outcome.unavailable => Ok(Expect::Unavailable),
                None if outcome.matched => Ok(Expect::Match),
                None => Ok(Expect::NoMatch),
            });
        match got {
            Ok(got) if got == case.expect => {}
            Ok(got) => errors.push(format!(
                "case {:?} ({}): expected {:?}, got {got:?}",
                case.name, case.rule, case.expect
            )),
            Err(e) => errors.push(format!("case {:?} ({}): failed: {e}", case.name, case.rule)),
        }
    }
    notes.push(format!(
        "{} rules, {} cases",
        rules.rules.len(),
        cases.len()
    ));
    (errors, notes)
}

/// The signed envelope: verifies against `alarms.key`, carries exactly
/// `rules.json`. Returns (version, expires at).
fn envelope(dir: &Path, now_ms: i64) -> Result<(u64, i64), String> {
    let signed = fs::read(dir.join("alarms.json")).map_err(|e| format!("alarms.json: {e}"))?;
    let key_line =
        fs::read_to_string(dir.join("alarms.key")).map_err(|e| format!("alarms.key: {e}"))?;
    let [rule_set, issuer, public] = key_line.split_whitespace().collect::<Vec<_>>()[..] else {
        return Err("alarms.key: expected `RULE_SET ISSUER PUBLIC_KEY`".into());
    };
    if rule_set != RULE_SET {
        return Err(format!(
            "alarms.key: rule set {rule_set}, expected {RULE_SET}"
        ));
    }
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("alarms.key: not a base64url Ed25519 key")?;
    let trusted =
        TrustedRuleKey::new(id(RULE_SET)?, id(issuer)?, public).map_err(|e| format!("{e:?}"))?;
    let loader =
        RuleLoader::new(vec![trusted], ResourceLimits::V1).map_err(|e| format!("{e:?}"))?;
    let verified = loader
        .load_json(
            &signed,
            LoadContext {
                expected_rule_set_id: &id(RULE_SET)?,
                now_unix_ms: now_ms,
                last_accepted: None,
            },
        )
        .map_err(|e| format!("alarms.json: refused: {e:?}"))?;
    let envelope: SignedRuleEnvelope =
        serde_json::from_slice(&signed).map_err(|e| e.to_string())?;
    let rules = fs::read(dir.join("rules.json")).map_err(|e| format!("rules.json: {e}"))?;
    if envelope.payload.as_bytes() != rules {
        return Err("alarms.json does not carry exactly rules.json (re-sign)".into());
    }
    Ok((
        verified.accepted_version().version(),
        verified.expires_at_unix_ms(),
    ))
}

fn main() -> ExitCode {
    let (mut dir, mut cases, mut previous, mut min_days, mut sources_only) =
        (None, None, None, 365, false);
    let mut args = std::env::args().skip(1);
    while let Some(flag) = args.next() {
        let value = args.next();
        match (flag.as_str(), value) {
            ("--dir", Some(v)) => dir = Some(PathBuf::from(v)),
            ("--cases", Some(v)) => cases = Some(PathBuf::from(v)),
            ("--previous-version", Some(v)) => previous = v.parse::<u64>().ok(),
            ("--min-days", Some(v)) => min_days = v.parse().unwrap_or(365),
            ("--sources-only", next) => {
                sources_only = true;
                if let Some(next) = next {
                    eprintln!("alarms-check: unexpected {next}");
                    return ExitCode::from(2);
                }
            }
            _ => {
                eprintln!(
                    "usage: alarms-check --dir DIR --cases FILE [--previous-version N] [--min-days N] [--sources-only]"
                );
                return ExitCode::from(2);
            }
        }
    }
    let (Some(dir), Some(cases)) = (dir, cases) else {
        eprintln!("alarms-check: --dir and --cases are required");
        return ExitCode::from(2);
    };
    let now_ms = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map_or(0, |d| i64::try_from(d.as_millis()).unwrap_or(i64::MAX));
    let (mut errors, mut notes) = check(&dir, &cases, now_ms);
    if !sources_only {
        match envelope(&dir, now_ms) {
            Ok((version, expires)) => {
                if previous.is_some_and(|p| version <= p) {
                    errors.push(format!(
                        "alarms.json: version {version} is not above the released one"
                    ));
                }
                let left = (expires - now_ms) / DAY_MS;
                if left < min_days {
                    errors.push(format!(
                        "alarms.json: expires in {left} days, fewer than {min_days} (re-sign)"
                    ));
                }
                notes.push(format!("v{version} expires in {left} days"));
            }
            Err(e) => errors.push(e),
        }
    }
    if errors.is_empty() {
        println!("ok: {}", notes.join(", "));
        ExitCode::SUCCESS
    } else {
        for error in errors {
            println!("error: {error}");
        }
        ExitCode::FAILURE
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn scratch(test: &str, rules: &str, cases: &str) -> (PathBuf, PathBuf) {
        let dir = std::env::temp_dir().join(format!("alarms-check-{test}-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(&dir).unwrap();
        fs::write(dir.join("rules.json"), rules).unwrap();
        fs::write(dir.join("cases.json"), cases).unwrap();
        (dir.clone(), dir.join("cases.json"))
    }

    const RULE: &str = r#"{"schema_version":1,"rules":[{"id":"r","version":1,"title":"t","severity":"high","confidence":80,"kind":"process_event","expression":"event['parent.name'] == 'nginx'","finding_message":"m","attack":[{"tactic":"TA0002"}]}]}"#;

    #[test]
    fn the_shipped_rules_pass() {
        let root = Path::new(env!("CARGO_MANIFEST_DIR")).join("..");
        let (errors, _) = check(
            &root.join("alarms"),
            &root.join("tests/alarm-cases.json"),
            1_790_000_000_000,
        );
        assert!(errors.is_empty(), "{errors:#?}");
    }

    #[test]
    fn a_wrong_expectation_is_reported() {
        let cases = r#"[{"rule":"r","name":"a","event":{"parent.name":"nginx"},"expect":"no_match"},
                        {"rule":"r","name":"b","event":{"parent.name":"x"},"expect":"match"}]"#;
        let (dir, cases) = scratch("wrong", RULE, cases);
        let (errors, _) = check(&dir, &cases, 1_790_000_000_000);
        assert!(
            errors
                .iter()
                .any(|e| e.contains("expected NoMatch, got Match")),
            "{errors:?}"
        );
        assert!(
            errors
                .iter()
                .any(|e| e.contains("expected Match, got NoMatch")),
            "{errors:?}"
        );
    }

    #[test]
    fn every_rule_needs_a_match_and_a_no_match_case() {
        let cases = r#"[{"rule":"r","name":"a","event":{"parent.name":"nginx"},"expect":"match"}]"#;
        let (dir, cases) = scratch("missing", RULE, cases);
        let (errors, _) = check(&dir, &cases, 1_790_000_000_000);
        assert!(
            errors.iter().any(|e| e.contains("no NoMatch case")),
            "{errors:?}"
        );
    }

    #[test]
    fn snapshot_rules_and_unknown_event_keys_are_refused() {
        let snapshot = RULE.replace(r#""kind":"process_event","#, "");
        let cases = r#"[{"rule":"r","name":"a","event":{},"expect":"match"},{"rule":"r","name":"b","event":{},"expect":"no_match"}]"#;
        let (dir, cases_path) = scratch("snapshot", &snapshot, cases);
        assert!(
            check(&dir, &cases_path, 1_790_000_000_000)
                .0
                .iter()
                .any(|e| e.contains("not a process_event"))
        );
        let typo = RULE.replace("parent.name", "parent.nmae");
        let (dir, cases_path) = scratch("typo", &typo, cases);
        assert!(
            check(&dir, &cases_path, 1_790_000_000_000)
                .0
                .iter()
                .any(|e| e.contains("refuses"))
        );
    }

    #[test]
    fn an_unsigned_envelope_is_an_error_unless_sources_only() {
        let (dir, _) = scratch("unsigned", RULE, "[]");
        assert!(envelope(&dir, 1_790_000_000_000).is_err());
    }
}
