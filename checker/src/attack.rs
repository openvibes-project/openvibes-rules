//! ATT&CK mapping check (protocol P18), shared with `alarms-check` by path.
//!
//! The pinned (oldest supported) agent ignores `attack`, so this check is
//! the only thing that keeps malformed or missing mappings out of a signed
//! set. IDs are also checked against `data/attack-ids.json`, a copy of the
//! live (not revoked, not deprecated) IDs of the ATT&CK release the
//! platform's console bundles (`attack-enterprise.json`). To refresh it,
//! rebuild the platform file with its `scripts/attack-data.py`, then reduce
//! it with the one-liner in `docs/components/rules-check.md`.

use std::collections::HashSet;
use std::sync::OnceLock;

use serde_json::Value;

/// Rules that cover no ATT&CK technique on purpose (test triggers).
const UNMAPPED: [&str; 2] = ["alarm.openvibes.test", "test.openvibes.running"];

struct Ids {
    tactics: HashSet<String>,
    /// technique ID to the tactics it belongs to.
    techniques: std::collections::HashMap<String, Vec<String>>,
}

fn ids() -> &'static Ids {
    static IDS: OnceLock<Ids> = OnceLock::new();
    IDS.get_or_init(|| {
        let v: Value = serde_json::from_str(include_str!("../data/attack-ids.json"))
            .expect("data/attack-ids.json is valid JSON");
        let strings = |v: &Value| -> Vec<String> {
            v.as_array()
                .into_iter()
                .flatten()
                .filter_map(|s| s.as_str().map(String::from))
                .collect()
        };
        Ids {
            tactics: strings(&v["tactics"]).into_iter().collect(),
            techniques: v["techniques"]
                .as_object()
                .into_iter()
                .flatten()
                .map(|(k, t)| (k.clone(), strings(t)))
                .collect(),
        }
    })
}

/// The pair names a live tactic, and a live technique that sits under it.
fn known(tactic: &str, technique: Option<&str>) -> bool {
    let ids = ids();
    ids.tactics.contains(tactic)
        && technique.is_none_or(|t| {
            ids.techniques
                .get(t)
                .is_some_and(|v| v.iter().any(|x| x == tactic))
        })
}

fn digits(text: &str, count: usize) -> bool {
    text.len() == count && text.bytes().all(|b| b.is_ascii_digit())
}

fn tactic_ok(id: &str) -> bool {
    id.strip_prefix("TA").is_some_and(|d| digits(d, 4))
}

fn technique_ok(id: &str) -> bool {
    id.strip_prefix('T')
        .is_some_and(|rest| match rest.split_once('.') {
            Some((base, sub)) => digits(base, 4) && digits(sub, 3),
            None => digits(rest, 4),
        })
}

/// Every rule but the test triggers has 1 to 16 distinct, well-formed pairs.
pub fn check(rules_bytes: &[u8]) -> Vec<String> {
    let Ok(set) = serde_json::from_slice::<Value>(rules_bytes) else {
        return vec!["rules.json: not JSON".into()];
    };
    let mut errors = Vec::new();
    for rule in set["rules"].as_array().into_iter().flatten() {
        let id = rule["id"].as_str().unwrap_or("?");
        let unmapped = UNMAPPED.contains(&id);
        let error = match (&rule["attack"], unmapped) {
            (Value::Null, true) => None,
            (_, true) => Some("a test rule maps to no ATT&CK technique"),
            (Value::Null, false) => Some("needs an attack mapping"),
            (Value::Array(pairs), false) => {
                let mut seen = HashSet::new();
                let mut unknown = false;
                let well_formed = pairs.iter().all(|pair| {
                    let Some(object) = pair.as_object() else {
                        return false;
                    };
                    let tactic = pair["tactic"].as_str().is_some_and(tactic_ok);
                    let technique = match &pair["technique"] {
                        Value::Null => !object.contains_key("technique"),
                        value => value.as_str().is_some_and(technique_ok),
                    };
                    let keys = object.keys().all(|k| k == "tactic" || k == "technique");
                    let ok = tactic && technique && keys && seen.insert(pair.to_string());
                    if ok
                        && !known(
                            pair["tactic"].as_str().unwrap_or_default(),
                            pair["technique"].as_str(),
                        )
                    {
                        unknown = true;
                    }
                    ok
                });
                if pairs.is_empty() || pairs.len() > 16 || !well_formed {
                    Some("attack must hold 1 to 16 distinct, well-formed pairs")
                } else if unknown {
                    Some(
                        "attack names a tactic or technique that is not in the ATT&CK release (unknown, retired, or under another tactic)",
                    )
                } else {
                    None
                }
            }
            _ => Some("attack must be a list"),
        };
        errors.extend(error.map(|e| format!("{id}: {e}")));
    }
    errors
}

#[cfg(test)]
mod tests {
    use super::check;

    fn one(attack: &str) -> Vec<String> {
        let rules = format!(r#"{{"rules":[{{"id":"r"{attack}}}]}}"#);
        check(rules.as_bytes())
    }

    #[test]
    fn good_mappings_pass() {
        assert!(
            one(r#","attack":[{"tactic":"TA0002","technique":"T1059.004"},{"tactic":"TA0005"}]"#)
                .is_empty()
        );
    }

    #[test]
    fn unknown_and_retired_ids_are_refused() {
        for bad in [
            // well-formed but unknown tactic
            r#","attack":[{"tactic":"TA9999"}]"#,
            // an ID that was never assigned
            r#","attack":[{"tactic":"TA0100"}]"#,
            // unknown technique
            r#","attack":[{"tactic":"TA0002","technique":"T9999"}]"#,
            // retired technique (T1086 PowerShell, replaced by T1059.001)
            r#","attack":[{"tactic":"TA0002","technique":"T1086"}]"#,
            // live technique under a tactic it does not belong to
            r#","attack":[{"tactic":"TA0040","technique":"T1059.004"}]"#,
        ] {
            assert_eq!(one(bad).len(), 1, "{bad}");
        }
    }

    #[test]
    fn missing_and_malformed_mappings_are_refused() {
        for bad in [
            "",
            r#","attack":[]"#,
            r#","attack":[{"technique":"T1059"}]"#,
            r#","attack":[{"tactic":"TA2"}]"#,
            r#","attack":[{"tactic":"TA0002","technique":"T1059.4"}]"#,
            r#","attack":[{"tactic":"TA0002","technique":null}]"#,
            r#","attack":[{"tactic":"TA0002","phase":"x"}]"#,
            r#","attack":[{"tactic":"TA0002"},{"tactic":"TA0002"}]"#,
            r#","attack":"TA0002""#,
        ] {
            assert_eq!(one(bad).len(), 1, "{bad}");
        }
    }

    #[test]
    fn test_rules_must_stay_unmapped() {
        assert!(check(br#"{"rules":[{"id":"alarm.openvibes.test"}]}"#).is_empty());
        let mapped =
            br#"{"rules":[{"id":"test.openvibes.running","attack":[{"tactic":"TA0002"}]}]}"#;
        assert_eq!(check(mapped).len(), 1);
    }
}
