//! The individual checks; each returns its errors as text.

use std::time::Duration;

use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Fact, FactSet, FactValue, Identifier, PayloadEncoding, ResourceLimits, RuleSet, SchemaVersion,
    SignedRuleEnvelope, Validate,
};
use openvibes_rules::{
    EvaluationClock, Evaluator, LoadContext, RuleLoader, RuleOutcome, TrustedRuleKey,
    VerifiedRuleSet, signing_preimage,
};
use serde::Deserialize;
use sha2::{Digest, Sha256};

/// One test case from `tests/cases.json`.
#[derive(Debug, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Case {
    pub rule: String,
    pub name: String,
    pub facts: serde_json::Map<String, serde_json::Value>,
    pub expect: Expect,
}

#[derive(Clone, Copy, Debug, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Expect {
    Match,
    NoMatch,
    Unavailable,
}

pub type Key = (Identifier, Identifier, [u8; 32]);

const DAY_MS: i64 = 86_400_000;

fn hex(bytes: &[u8]) -> String {
    bytes.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Check 1: a valid schema-1 rule set (validation also refuses duplicate ids).
pub fn rule_set(bytes: &[u8]) -> Result<RuleSet, String> {
    let rules: RuleSet = serde_json::from_slice(bytes).map_err(|e| format!("rules.json: {e}"))?;
    rules
        .validate(ResourceLimits::V1)
        .map_err(|e| format!("rules.json: {e}"))?;
    Ok(rules)
}

/// Parses `RULE_SET ISSUER_KEY_ID PUBLIC_KEY` (base64url, no padding).
pub fn key_line(text: &str) -> Result<Key, String> {
    let fields: Vec<&str> = text.split_whitespace().collect();
    let [set, issuer, public] = fields.as_slice() else {
        return Err("baseline.key: want RULE_SET ISSUER_KEY_ID PUBLIC_KEY".into());
    };
    let id = |value: &str| Identifier::new(value).map_err(|e| format!("baseline.key: {e}"));
    let public: [u8; 32] = URL_SAFE_NO_PAD
        .decode(public)
        .ok()
        .and_then(|bytes| bytes.try_into().ok())
        .ok_or("baseline.key: the public key is not 32 bytes of base64url")?;
    Ok((id(set)?, id(issuer)?, public))
}

/// Check 2: the envelope loads with the agent's loader and the key, and
/// wraps exactly the bytes of `rules.json`.
pub fn envelope(
    bytes: &[u8],
    key: &Key,
    rules_bytes: &[u8],
    now_ms: i64,
) -> Result<SignedRuleEnvelope, String> {
    let (set, issuer, public) = key;
    let trusted = TrustedRuleKey::new(set.clone(), issuer.clone(), *public)
        .map_err(|e| format!("baseline.key: {e}"))?;
    RuleLoader::new(vec![trusted], ResourceLimits::V1)
        .and_then(|loader| {
            loader.load_json(
                bytes,
                LoadContext {
                    expected_rule_set_id: set,
                    now_unix_ms: now_ms,
                    last_accepted: None,
                },
            )
        })
        .map_err(|e| format!("baseline.json does not load: {e}"))?;
    let envelope: SignedRuleEnvelope =
        serde_json::from_slice(bytes).map_err(|e| format!("baseline.json: {e}"))?;
    if envelope.payload.as_bytes() != rules_bytes {
        return Err(
            "baseline.json: payload differs from rules.json (sign rules.json again)".into(),
        );
    }
    Ok(envelope)
}

/// Check 4 helper: every `facts` access must be `facts['KEY']`; returns the keys.
pub fn fact_keys(expression: &str) -> Result<Vec<String>, String> {
    let mut keys = Vec::new();
    let mut rest = expression;
    while let Some(at) = rest.find("facts") {
        let Some(tail) = rest[at + "facts".len()..].strip_prefix("['") else {
            return Err(format!("facts must be read as facts['KEY']: {expression}"));
        };
        let end = tail
            .find("']")
            .ok_or_else(|| format!("unterminated facts['KEY']: {expression}"))?;
        keys.push(tail[..end].to_owned());
        rest = &tail[end + 2..];
    }
    Ok(keys)
}

struct Now(i64);

impl EvaluationClock for Now {
    fn elapsed(&self) -> Duration {
        Duration::ZERO
    }
    fn unix_ms(&self) -> i64 {
        self.0
    }
}

/// Signs `rules` with a throwaway key so the agent's evaluator will run them.
fn verified(rules: &[u8], now_ms: i64) -> Result<VerifiedRuleSet, String> {
    let payload = std::str::from_utf8(rules).map_err(|e| format!("rules.json: {e}"))?;
    let id = Identifier::new("baseline").map_err(|e| e.to_string())?;
    let issuer = Identifier::new("check").map_err(|e| e.to_string())?;
    let key = SigningKey::from_bytes(&[1; 32]);
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: id.clone(),
        rule_set_version: 1,
        issuer_key_id: issuer.clone(),
        created_at_unix_ms: now_ms - DAY_MS,
        expires_at_unix_ms: now_ms + DAY_MS,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: hex(&Sha256::digest(rules)),
        payload: payload.to_owned(),
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).map_err(|e| e.to_string())?;
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    let bytes = serde_json::to_vec(&envelope).map_err(|e| e.to_string())?;
    let trusted = TrustedRuleKey::new(id.clone(), issuer, key.verifying_key().to_bytes())
        .map_err(|e| e.to_string())?;
    RuleLoader::new(vec![trusted], ResourceLimits::V1)
        .and_then(|loader| {
            loader.load_json(
                &bytes,
                LoadContext {
                    expected_rule_set_id: &id,
                    now_unix_ms: now_ms,
                    last_accepted: None,
                },
            )
        })
        .map_err(|e| format!("rules.json does not load: {e}"))
}

/// The collector that reports a fact, from its key's first segment.
fn source(key: &str) -> &'static str {
    match key.split('.').next() {
        Some("port") => "ports",
        Some("package") => "packages",
        _ => "processes",
    }
}

fn facts(case: &Case, now_ms: i64) -> Result<FactSet, String> {
    let mut facts = Vec::new();
    for (key, value) in &case.facts {
        let value = match value {
            serde_json::Value::Array(items) => FactValue::StringList(
                items
                    .iter()
                    .map(|item| item.as_str().map(str::to_owned))
                    .collect::<Option<_>>()
                    .ok_or("list facts hold strings")?,
            ),
            serde_json::Value::Number(number) => {
                FactValue::Integer(number.as_i64().ok_or("integer facts only")?)
            }
            serde_json::Value::Bool(flag) => FactValue::Boolean(*flag),
            serde_json::Value::String(text) => FactValue::String(text.clone()),
            serde_json::Value::Null | serde_json::Value::Object(_) => {
                return Err(format!("fact {key}: unsupported value"));
            }
        };
        facts.push(Fact {
            key: Identifier::new(key.as_str()).map_err(|e| format!("fact {key}: {e}"))?,
            source: Identifier::new(source(key)).map_err(|e| e.to_string())?,
            value,
        });
    }
    let set = FactSet {
        schema_version: SchemaVersion::V1,
        scan_id: Identifier::new("check").map_err(|e| e.to_string())?,
        collected_at_unix_ms: now_ms - 1,
        facts,
        errors: Vec::new(),
    };
    // The evaluator only says InvalidFacts; the validator says why (for
    // example a string list that is not sorted and unique, as agents send).
    set.validate(ResourceLimits::V1)
        .map_err(|e| format!("invalid facts: {e}"))?;
    Ok(set)
}

/// Check 5: every case gives its expected outcome in the agent's evaluator,
/// and every rule has a match and a no_match case.
pub fn run_cases(rules: &[u8], cases: &[Case], now_ms: i64) -> Vec<String> {
    let set = match verified(rules, now_ms) {
        Ok(set) => set,
        Err(error) => return vec![error],
    };
    let ids: Vec<String> = match rule_set(rules) {
        Ok(parsed) => parsed
            .rules
            .iter()
            .map(|r| r.id.as_str().to_owned())
            .collect(),
        Err(error) => return vec![error],
    };
    let evaluator = match Evaluator::new(ResourceLimits::V1) {
        Ok(evaluator) => evaluator,
        Err(error) => return vec![error.to_string()],
    };
    let agent = Identifier::new("check").expect("static identifier");
    let mut errors = Vec::new();
    for case in cases {
        if !ids.contains(&case.rule) {
            errors.push(format!("case {:?}: unknown rule {}", case.name, case.rule));
            continue;
        }
        let report = facts(case, now_ms).and_then(|facts| {
            evaluator
                .evaluate(&set, &facts, &agent, &Now(now_ms))
                .map_err(|e| e.to_string())
        });
        let outcome = match report {
            Ok(report) => report
                .results
                .into_iter()
                .find(|result| result.rule_id.as_str() == case.rule)
                .map(|result| match result.outcome {
                    RuleOutcome::Match(_) => Ok(Expect::Match),
                    RuleOutcome::NoMatch => Ok(Expect::NoMatch),
                    RuleOutcome::Unavailable => Ok(Expect::Unavailable),
                    RuleOutcome::Failed(error) => Err(error.to_string()),
                })
                .unwrap_or_else(|| Err("no result".into())),
            Err(error) => Err(error),
        };
        match outcome {
            Ok(got) if got == case.expect => {}
            Ok(got) => errors.push(format!(
                "{}: case {:?} expected {:?}, got {got:?}",
                case.rule, case.name, case.expect
            )),
            Err(error) => errors.push(format!(
                "{}: case {:?} failed: {error}",
                case.rule, case.name
            )),
        }
    }
    for id in &ids {
        let has = |want| cases.iter().any(|c| &c.rule == id && c.expect == want);
        if !(has(Expect::Match) && has(Expect::NoMatch)) {
            errors.push(format!("{id}: needs a match and a no_match case"));
        }
    }
    errors
}

#[cfg(test)]
mod tests;
