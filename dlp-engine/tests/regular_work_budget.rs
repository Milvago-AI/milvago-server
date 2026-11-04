use milvago_dlp_engine::*;
use serde_json::json;

fn input(tier: Option<&str>, rules: usize, text: &str) -> Input {
    let mut detectors = vec![json!({"id":"terms","name":"Synthetic terms","definition":{
        "kind":"dictionary","values":(0..200).map(|i|format!("absent{i}")).collect::<Vec<_>>(),"exceptions":[]}})];
    let detector = if let Some(tier) = tier {
        detectors.push(json!({"id":"tier","name":"Synthetic tier","definition":{"kind":"keyword_tier","dictionary":"terms","tier":tier}}));
        "tier"
    } else { "terms" };
    serde_json::from_value(json!({"policy":{"schema_version":1,"domain":"endpoint","inspection":true,"journal":true,
        "detectors":detectors,"rules":(0..rules).map(|i|json!({"id":format!("rule{i}"),"revision":1,"name":"Synthetic bounded rule","mode":"active","priority":100,
        "condition":{"op":"matches","field":"prompt","detector":detector,"minimum":1},"scope":{"op":"true"},"consequence":{"action":"block"},"review":false,"message":""})).collect::<Vec<_>>()},
        "texts":{"prompt":[text]},"facts":{},"upload":false})).unwrap()
}

#[test]
fn unmatched_regular_dictionary_scans_consume_cumulative_work() {
    let text = "x".repeat(MAX_TEXT);
    for tier in [None, Some("exact"), Some("unicode")] {
        let data = input(tier, 12, &text);
        validate(&data.policy).unwrap();
        assert!(evaluate(&data).unwrap_err().contains("work"), "{tier:?}");
    }
}

#[test]
fn ordinary_dictionary_decisions_fit_the_same_budget() {
    for tier in [None, Some("exact"), Some("unicode")] {
        assert_eq!(evaluate(&input(tier, 1, "harmless synthetic text")).unwrap().action, "observe");
        let matched = if tier == Some("unicode") { "ａｂｓｅｎｔ４２" } else { "absent42" };
        assert_eq!(evaluate(&input(tier, 1, matched)).unwrap().action, "block");
    }
}
