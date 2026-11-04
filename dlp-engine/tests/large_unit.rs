use milvago_dlp_engine::*;
use std::collections::BTreeMap;

fn input(source:&str,texts:Vec<String>)->Input {
    let mut rule=parse(source).unwrap();rule.mode=Mode::Active;
    Input{policy:Policy{schema_version:1,domain:Domain::Endpoint,inspection:true,native_inspection:true,
        journal:true,detectors:vec![],rules:vec![rule]},texts:BTreeMap::from([("prompt".into(),texts)]),
        facts:BTreeMap::from([("channel".into(),"browser".into())]),upload:Some(false)}
}

#[test]
fn large_unit_keeps_one_original_decision_across_all_values() {
    let mut data=input("WHEN prompt CONTAINS \"alpha\" AND prompt CONTAINS \"beta\"\nSCOPE TRUE\nTHEN BLOCK",
        vec![format!("alpha {}","x".repeat(20000)),format!("beta {}","y".repeat(20000))]);
    assert!(evaluate(&data).is_err());
    let result=evaluate_large_unit(&data).unwrap();assert_eq!(result.action,"block");assert_eq!(result.decisions.len(),1);
    data.policy.rules[0].condition=parse("WHEN prompt CONTAINS \"alpha\" XOR prompt CONTAINS \"beta\"\nSCOPE TRUE\nTHEN BLOCK").unwrap().condition;
    assert_eq!(evaluate_large_unit(&data).unwrap().action,"observe");
}

#[test]
fn large_transform_and_final_verification_keep_original_arbitration() {
    let mut data=input("WHEN prompt CONTAINS \"synthetic-secret\"\nSCOPE TRUE\nTHEN REPLACE \"synthetic-secret\" WITH \"REDACTED\"",
        vec!["x".repeat(20000),format!("{} synthetic-secret","y".repeat(20000))]);
    let result=evaluate_large_unit(&data).unwrap();assert_eq!(result.action,"transform");
    assert!(result.texts["prompt"][1].ends_with("REDACTED"));assert_eq!(result.decisions[0].occurrences,1);
    let mut deny=parse("WHEN prompt CONTAINS \"REDACTED\"\nSCOPE TRUE\nTHEN BLOCK").unwrap();deny.id="final.deny".into();deny.mode=Mode::Active;
    data.policy.rules.push(deny);
    let result=evaluate_large_unit(&data).unwrap();assert_eq!(result.action,"block");assert_eq!(result.texts,data.texts);
}

#[test]
fn large_capacity_is_bounded_and_cannot_be_selected_on_the_json_api() {
    let source="WHEN prompt CONTAINS \"never-match\"\nSCOPE TRUE\nTHEN BLOCK";
    let mut data=input(source,vec!["x".repeat(MAX_LARGE_UNIT_TEXT)]);
    assert_eq!(evaluate_large_unit(&data).unwrap().action,"observe");
    data.texts.get_mut("prompt").unwrap()[0].push('x');assert!(evaluate_large_unit(&data).is_err());
    data.texts.insert("prompt".into(),vec![String::new();MAX_LARGE_UNIT_VALUES]);assert!(evaluate_large_unit(&data).is_ok());
    data.texts.get_mut("prompt").unwrap().push(String::new());assert!(evaluate_large_unit(&data).is_err());
    data.texts.insert("prompt".into(),vec!["x".repeat(MAX_TEXT+1)]);
    // A claimed channel cannot change the JSON API's inspection budget.
    data.facts.insert("channel".into(),"native".into());
    for op in ["evaluate","evaluate_large_unit"] {
        let response:serde_json::Value=serde_json::from_slice(&dispatch(&serde_json::to_vec(&serde_json::json!({"op":op,"input":data})).unwrap())).unwrap();
        assert_eq!(response["ok"],false);
    }
}

#[test]
fn many_unmatched_scans_cannot_consume_unbounded_work() {
    let mut data=input("WHEN prompt CONTAINS \"never-match\"\nSCOPE TRUE\nTHEN BLOCK",vec![String::new();MAX_LARGE_UNIT_VALUES]);
    let original=data.policy.rules[0].clone();
    for i in 1..10 {let mut rule=original.clone();rule.id=format!("budget.{i}");data.policy.rules.push(rule);}
    let error=evaluate_large_unit(&data).unwrap_err();assert!(error.starts_with("Inspection work "));
}
