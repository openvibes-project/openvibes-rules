use base64::{Engine, engine::general_purpose::URL_SAFE_NO_PAD};
use ed25519_dalek::{Signer, SigningKey};
use openvibes_core::{
    Identifier, PayloadEncoding, ResourceLimits, SchemaVersion, SignedRuleEnvelope,
};
use openvibes_rules::signing_preimage;
use sha2::{Digest, Sha256};

use super::*;

const DAY_MS: i64 = 86_400_000;
const NOW: i64 = 1_790_000_000_000;
const RULES: &str = r#"{"schema_version":1,"rules":[{"id":"port.ssh.exposed","version":1,"title":"SSH is exposed","severity":"low","confidence":90,"expression":"'22' in facts['port.tcp.exposed']","finding_message":"SSH listens on a non-loopback address"}]}"#;

fn public(seed: u8) -> String {
    URL_SAFE_NO_PAD.encode(
        SigningKey::from_bytes(&[seed; 32])
            .verifying_key()
            .to_bytes(),
    )
}

fn fixture_key() -> Key {
    key_line(&format!("baseline openvibes-1 {}", public(7)), "baseline").unwrap()
}

/// An envelope over `payload`, signed by the key from `seed`.
fn sign_fixture(payload: &str, seed: u8, version: u64) -> Vec<u8> {
    let mut envelope = SignedRuleEnvelope {
        schema_version: SchemaVersion::V1,
        rule_set_id: Identifier::new("baseline").unwrap(),
        rule_set_version: version,
        issuer_key_id: Identifier::new("openvibes-1").unwrap(),
        created_at_unix_ms: NOW - DAY_MS,
        expires_at_unix_ms: NOW + 400 * DAY_MS,
        payload_encoding: PayloadEncoding::Json,
        payload_sha256_hex: Sha256::digest(payload.as_bytes())
            .iter()
            .map(|byte| format!("{byte:02x}"))
            .collect(),
        payload: payload.to_owned(),
        signature_base64url: String::new(),
    };
    let preimage = signing_preimage(&envelope, ResourceLimits::V1).unwrap();
    let key = SigningKey::from_bytes(&[seed; 32]);
    envelope.signature_base64url = URL_SAFE_NO_PAD.encode(key.sign(&preimage).to_bytes());
    serde_json::to_vec(&envelope).unwrap()
}

fn case(rule: &str, facts: serde_json::Value, expect: Expect) -> Case {
    Case {
        rule: rule.into(),
        name: format!("{rule} {expect:?}"),
        facts: facts.as_object().unwrap().clone(),
        expect,
    }
}

#[test]
fn rule_set_parses_and_refuses_duplicates() {
    assert_eq!(rule_set(RULES.as_bytes()).unwrap().rules.len(), 1);
    let rule = &RULES[RULES.find("{\"id\"").unwrap()..RULES.len() - 2];
    let twice = format!(r#"{{"schema_version":1,"rules":[{rule},{rule}]}}"#);
    let err = rule_set(twice.as_bytes()).unwrap_err();
    assert!(err.contains("duplicate rule identifier"), "{err}");
}

#[test]
fn key_line_parsing() {
    let key = public(7);
    assert!(key_line(&format!("baseline openvibes-1 {key}\n"), "baseline").is_ok());
    assert!(key_line(&format!("  baseline  openvibes-1 {key}  "), "baseline").is_ok());
    assert!(key_line(&format!("baseline {key}"), "baseline").is_err());
    assert!(key_line(&format!("baseline openvibes-1 {key} extra"), "baseline").is_err());
    assert!(key_line("baseline openvibes-1 not-a-key", "baseline").is_err());
}

#[test]
fn envelope_accepts_matching_signed_bytes() {
    let signed = sign_fixture(RULES, 7, 1);
    let envelope = envelope(&signed, &fixture_key(), RULES.as_bytes(), NOW).unwrap();
    assert_eq!(envelope.rule_set_version, 1);
}

#[test]
fn payload_must_match_bytes() {
    let reformatted = RULES.replacen("\"schema_version\":1", "\"schema_version\": 1", 1);
    let signed = sign_fixture(&reformatted, 7, 1);
    let err = envelope(&signed, &fixture_key(), RULES.as_bytes(), NOW).unwrap_err();
    assert!(err.contains("payload differs from rules.json"), "{err}");
}

#[test]
fn envelope_refuses_other_key() {
    let signed = sign_fixture(RULES, 8, 1);
    assert!(envelope(&signed, &fixture_key(), RULES.as_bytes(), NOW).is_err());
}

#[test]
fn fact_keys_extracts_literals() {
    assert_eq!(
        fact_keys("'22' in facts['port.tcp.exposed'] || facts['process.count'] > 1").unwrap(),
        vec!["port.tcp.exposed", "process.count"]
    );
}

#[test]
fn other_fact_access_is_refused() {
    for expression in [
        r#"'22' in facts["port.tcp.exposed"]"#,
        "facts.x > 1",
        "size(facts) > 0",
        "'22' in facts['port.tcp.exposed",
    ] {
        assert!(fact_keys(expression).is_err(), "{expression}");
    }
}

#[test]
fn cases_evaluate_through_the_agent_evaluator() {
    let cases = [
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["22"]}),
            Expect::Match,
        ),
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["80"]}),
            Expect::NoMatch,
        ),
        case(
            "port.ssh.exposed",
            serde_json::json!({}),
            Expect::Unavailable,
        ),
    ];
    assert_eq!(
        run_cases(RULES.as_bytes(), &cases, NOW),
        Vec::<String>::new()
    );
}

#[test]
fn wrong_expectation_names_rule_and_case() {
    let cases = [
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["80"]}),
            Expect::Match,
        ),
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["22"]}),
            Expect::NoMatch,
        ),
    ];
    let errors = run_cases(RULES.as_bytes(), &cases, NOW);
    assert_eq!(errors.len(), 2, "{errors:?}");
    assert!(
        errors[0].contains("port.ssh.exposed") && errors[0].contains("expected Match"),
        "{errors:?}"
    );
}

#[test]
fn case_for_unknown_rule_fails() {
    let cases = [
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["22"]}),
            Expect::Match,
        ),
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["80"]}),
            Expect::NoMatch,
        ),
        case("nope", serde_json::json!({}), Expect::Unavailable),
    ];
    let errors = run_cases(RULES.as_bytes(), &cases, NOW);
    assert!(
        errors.iter().any(|e| e.contains("unknown rule nope")),
        "{errors:?}"
    );
}

#[test]
fn rule_without_both_cases_fails() {
    let cases = [case(
        "port.ssh.exposed",
        serde_json::json!({"port.tcp.exposed": ["22"]}),
        Expect::Match,
    )];
    let errors = run_cases(RULES.as_bytes(), &cases, NOW);
    assert!(
        errors
            .iter()
            .any(|e| e.contains("port.ssh.exposed: needs a match and a no_match case")),
        "{errors:?}"
    );
}

#[test]
fn invalid_case_facts_say_why() {
    let cases = [
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["80", "22"]}),
            Expect::Match,
        ),
        case(
            "port.ssh.exposed",
            serde_json::json!({"port.tcp.exposed": ["80"]}),
            Expect::NoMatch,
        ),
    ];
    let errors = run_cases(RULES.as_bytes(), &cases, NOW);
    assert_eq!(errors.len(), 1, "{errors:?}");
    assert!(errors[0].contains("invalid facts:"), "{errors:?}");
}

#[test]
fn key_line_must_name_the_expected_set() {
    let err = key_line(&format!("baseline2 openvibes-1 {}", public(7)), "baseline").unwrap_err();
    assert!(
        err.contains("baseline.key: the rule set must be baseline"),
        "{err}"
    );
    // A hardening set's key names that set (2026-10-10: the first signed
    // hardening release was refused as "must be baseline").
    let line = format!("hardening-linux-l1 openvibes-1 {}", public(7));
    assert!(key_line(&line, "hardening-linux-l1").is_ok());
    let err = key_line(&line, "baseline").unwrap_err();
    assert!(
        err.contains("must be baseline, not hardening-linux-l1"),
        "{err}"
    );
    let err = key_line(
        &format!("baseline openvibes-1 {}", public(7)),
        "hardening-linux-l1",
    )
    .unwrap_err();
    assert!(
        err.contains("hardening-linux-l1.key: the rule set must be hardening-linux-l1"),
        "{err}"
    );
}
