use milvago_dlp_engine::*;
use serde_json::json;

fn input(texts: &[&str]) -> Input {
    serde_json::from_value(json!({"policy":{"schema_version":1,"domain":"endpoint","inspection":true,"journal":true,
        "detectors":[{"id":"terms","name":"Terms","definition":{"kind":"dictionary","values":["alpha","beta","ALPHA"],"exceptions":[]}},
        {"id":"context","name":"Context","definition":{"kind":"dictionary_context","dictionary":"terms","minimum":2}}],
        "rules":[{"id":"rule","revision":1,"name":"Context rule","mode":"active","priority":100,"condition":{"op":"matches","field":"prompt","detector":"context","minimum":1},"scope":{"op":"true"},"consequence":{"action":"block"},"review":false,"message":""}]},
        "texts":{"prompt":texts},"facts":{},"upload":false})).unwrap()
}

#[test]
fn context_counts_distinct_terms_inside_one_text_value() {
    for (texts,action) in [(&["alpha alpha ALPHA"][..],"observe"),(&["Alpha BETA"][..],"block"),(&["alpha","beta"][..],"observe"),(&["nothing","alphabetabeta"][..],"block"),(&[""][..],"observe")] {
        assert_eq!(evaluate(&input(texts)).unwrap().action,action,"{texts:?}");
    }
}

#[test]
fn context_threshold_and_positive_dictionary_edits_control_recognition() {
    let mut data=input(&["alpha beta"]);
    if let DetectorKind::Dictionary {exceptions,..}=&mut data.policy.detectors[0].definition {exceptions.push("BETA".into());}
    assert_eq!(evaluate(&data).unwrap().action,"observe");
    if let DetectorKind::Dictionary {exceptions,..}=&mut data.policy.detectors[0].definition {*exceptions=vec!["ＢＥＴＡ".into()];}
    assert_eq!(evaluate(&data).unwrap().action,"observe");
    if let DetectorKind::Dictionary {values,exceptions}=&mut data.policy.detectors[0].definition {values.clear();exceptions.clear();}
    assert_eq!(evaluate(&data).unwrap().action,"observe");
    data.policy.detectors[1].definition=DetectorKind::DictionaryContext{dictionary:"terms".into(),minimum:1};
    if let DetectorKind::Dictionary {values,..}=&mut data.policy.detectors[0].definition {values.push("beta".into());}
    assert_eq!(evaluate(&data).unwrap().action,"block");
}

#[test]
fn context_rejects_invalid_shapes_references_thresholds_and_masking() {
    for (dictionary,minimum) in [("terms",0),("terms",201),("missing",2),("context",2)] {
        let mut data=input(&["alpha beta"]);data.policy.detectors[1].definition=DetectorKind::DictionaryContext{dictionary:dictionary.into(),minimum};
        assert!(validate(&data.policy).is_err());
    }
    for value in [json!({"kind":"dictionary_context","dictionary":{"image":"fixture"},"minimum":2}),json!({"kind":"dictionary_context","dictionary":"terms","minimum":true}),json!({"kind":"dictionary_context","dictionary":"terms","minimum":2,"command":"fixture"})] {
        assert!(serde_json::from_value::<DetectorKind>(value).is_err());
    }
    let mut data=input(&["alpha beta"]);data.policy.rules[0].consequence=Effect::Mask{detector:"context".into(),label:"CONTEXT".into()};
    assert!(validate(&data.policy).is_err());
}

#[test]
fn contextual_default_preserves_legacy_medical_truth_per_text_value() {
    let terms=["diagnostic","ordonnance","prescription","medical record","dossier médical"];
    for bits in 0..32 {
        let text=terms.iter().enumerate().filter(|(i,_)|bits&(1<<i)!=0).map(|(_,v)|*v).collect::<Vec<_>>().join(" / ");
        let mut current=input(&[&text]);
        if let DetectorKind::Dictionary{values,..}=&mut current.policy.detectors[0].definition {*values=terms.iter().map(|v|v.to_string()).collect();}
        let mut legacy=current.clone();legacy.policy.detectors[1].definition=DetectorKind::Builtin{category:"medical".into()};
        assert_eq!(evaluate(&current).unwrap().action,evaluate(&legacy).unwrap().action,"{bits}");
    }
}

#[test]
fn context_keeps_existing_input_and_library_bounds() {
    let mut data=input(&["alpha beta"]);
    data.texts.get_mut("prompt").unwrap()[0]="x".repeat(MAX_TEXT+1);
    assert!(evaluate(&data).is_err());
    if let DetectorKind::Dictionary{values,..}=&mut data.policy.detectors[0].definition {*values=(0..201).map(|i|format!("term{i}")).collect();}
    assert!(validate(&data.policy).is_err());
}

#[test]
fn contextual_scans_are_bounded_even_on_the_regular_json_capacity() {
    let text="x".repeat(MAX_TEXT);let mut data=input(&[&text]);
    if let DetectorKind::Dictionary{values,..}=&mut data.policy.detectors[0].definition {*values=(0..200).map(|i|format!("absent{i}")).collect();}
    let rule=data.policy.rules[0].clone();
    data.policy.rules=(0..12).map(|i|{let mut r=rule.clone();r.id=format!("rule{i}");r}).collect();
    validate(&data.policy).unwrap();
    assert!(evaluate(&data).unwrap_err().contains("work"));
}
