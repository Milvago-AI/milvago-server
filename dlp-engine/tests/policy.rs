use milvago_dlp_engine::*;
use std::collections::BTreeMap;

fn rule(source: &str) -> Rule {
    parse(source).expect("valid fixture language")
}
fn input(rules: Vec<Rule>, text: &str) -> Input {
    Input { policy: Policy { schema_version: 1, domain: Domain::Endpoint, inspection: true, native_inspection:false, journal: true, detectors: vec![], rules }, texts: BTreeMap::from([("prompt".into(), vec![text.into()])]), facts: BTreeMap::from([("channel".into(), "browser".into()), ("provider".into(), "chatgpt".into())]), upload: Some(false) }
}
const REPLACE: &str = "WHEN prompt CONTAINS \"Tomate\"\nSCOPE provider = \"chatgpt\" AND channel = \"browser\"\nTHEN REPLACE \"Tomate\" WITH \"Carotte\"";

#[test]
fn language_round_trips_nested_exactly_one_groups() {
    for source in [REPLACE, "WHEN (prompt CONTAINS \"alpha\" XOR prompt CONTAINS \"beta\" XOR prompt CONTAINS \"gamma\") AND NOT UPLOAD\nSCOPE TRUE\nTHEN BLOCK"] {
        let original = rule(source);
        assert_eq!(parse(&print(&original)).unwrap().condition, original.condition);
        assert_eq!(parse(&print(&original)).unwrap().scope, original.scope);
        assert_eq!(parse(&print(&original)).unwrap().consequence, original.consequence);
    }
}

#[test]
fn replacement_is_literal_and_preserves_unicode() {
    let mut r = rule(REPLACE); r.mode = Mode::Active;
    let result = evaluate(&input(vec![r], "été 日本語 Tomate 🍅 Tomate")).unwrap();
    assert_eq!(result.texts["prompt"][0], "été 日本語 Carotte 🍅 Carotte");
    assert_eq!(result.action, "transform");
    assert_eq!(result.decisions[0].occurrences, 2);
}

#[test]
fn simulation_cannot_transform_or_block() {
    let result = evaluate(&input(vec![rule(REPLACE)], "Tomate")).unwrap();
    assert_eq!(result.texts["prompt"][0], "Tomate");
    assert_eq!(result.action, "observe");
    assert_eq!(result.decisions[0].outcome, "simulated");
}

#[test]
fn xor_means_exactly_one_and_unknown_is_not_false() {
    let mut r = rule("WHEN prompt CONTAINS \"alpha\" XOR prompt CONTAINS \"beta\" XOR prompt CONTAINS \"gamma\"\nSCOPE TRUE\nTHEN BLOCK"); r.mode = Mode::Active;
    assert_eq!(evaluate(&input(vec![r.clone()], "alpha beta gamma")).unwrap().action, "observe");
    assert_eq!(evaluate(&input(vec![r], "alpha")).unwrap().action, "block");
    let mut r = rule("WHEN NOT UPLOAD\nSCOPE TRUE\nTHEN BLOCK"); r.mode = Mode::Active;
    let mut data = input(vec![r], "text"); data.upload = None;
    let result = evaluate(&data).unwrap();
    assert_eq!(result.action, "block");
    assert_eq!(result.decisions[0].outcome, "unavailable");
}

#[test]
fn block_overrides_every_transformation() {
    let mut replacement = rule(REPLACE); replacement.mode = Mode::Active;
    let mut blocking = rule("WHEN prompt CONTAINS \"Tomate\"\nSCOPE TRUE\nTHEN BLOCK"); blocking.id = "blocking".into(); blocking.mode = Mode::Active;
    let result = evaluate(&input(vec![replacement, blocking], "Tomate")).unwrap();
    assert_eq!(result.action, "block");
    assert_eq!(result.texts["prompt"][0], "Tomate");
}

#[test]
fn transformations_cannot_introduce_blocked_content() {
    let mut replacement = rule(REPLACE); replacement.mode = Mode::Active;
    let mut blocking = rule("WHEN prompt CONTAINS \"Carotte\"\nSCOPE TRUE\nTHEN BLOCK"); blocking.id = "blocking".into(); blocking.mode = Mode::Active;
    assert_eq!(evaluate(&input(vec![replacement, blocking], "Tomate")).unwrap().action, "block");
}

#[test]
fn malformed_and_resource_exhausting_inputs_are_rejected() {
    for source in ["WHEN prompt CONTAINS 12 SCOPE TRUE THEN BLOCK", "WHEN TRUE SCOPE TRUE THEN EXECUTE \"anything\"", "WHEN TRUE SCOPE TRUE THEN BLOCK trailing"] {
        assert!(parse(source).is_err(), "{source}");
    }
    let mut data = input(vec![rule(REPLACE)], "text"); data.texts.get_mut("prompt").unwrap()[0] = "x".repeat(MAX_TEXT + 1);
    assert!(evaluate(&data).is_err());
    assert!(serde_json::from_str::<Rule>(r#"{"condition":{"op":"true"},"unexpected":"image"}"#).is_err());
}

#[test]
fn masking_uses_priority_and_covers_the_full_overlap() {
    let mut first=rule("WHEN prompt MATCHES detector(\"first\")\nSCOPE TRUE\nTHEN MASK detector(\"first\") AS \"FIRST\"");
    first.id="first".into();first.mode=Mode::Active;first.priority=1;
    let mut second=rule("WHEN prompt MATCHES detector(\"second\")\nSCOPE TRUE\nTHEN MASK detector(\"second\") AS \"SECOND\"");
    second.id="second".into();second.mode=Mode::Active;second.priority=2;
    let mut data=input(vec![first,second],"secret-value-tail");
    data.policy.detectors=vec![
        Detector { id:"first".into(),name:"First".into(),definition:DetectorKind::Regex{pattern:"secret-value".into(),ignore_case:false}},
        Detector { id:"second".into(),name:"Second".into(),definition:DetectorKind::Regex{pattern:"value-tail".into(),ignore_case:false}},
    ];
    let result=evaluate(&data).unwrap();
    assert_eq!(result.texts["prompt"][0],"[FIRST]");
    assert_eq!(result.decisions.iter().find(|d|d.rule_id=="first").unwrap().outcome,"prepared");
}

#[test]
fn generated_numbered_markers_are_not_user_exemptions() {
    let mut r=rule("WHEN prompt MATCHES detector(\"digits\")\nSCOPE TRUE\nTHEN MASK detector(\"digits\") AS \"NUMBER\"");r.mode=Mode::Active;
    let mut data=input(vec![r],"12 34 [NUMBER99]");
    data.policy.detectors=vec![Detector{id:"digits".into(),name:"Numbers".into(),definition:DetectorKind::Regex{pattern:"[0-9]+".into(),ignore_case:false}}];
    let result=evaluate(&data).unwrap();
    assert_eq!(result.action,"transform");
    assert_eq!(result.texts["prompt"][0],"[NUMBER1] [NUMBER2] [NUMBER[NUMBER3]]");
}

#[test]
fn unknown_out_of_scope_does_not_block_and_indeterminate_scope_does() {
    let mut r=rule("WHEN NOT UPLOAD\nSCOPE channel = \"native\"\nTHEN BLOCK");r.mode=Mode::Active;
    let mut data=input(vec![r],"text");data.upload=None;
    assert_eq!(evaluate(&data).unwrap().action,"observe");
    data.facts.remove("channel");
    assert_eq!(evaluate(&data).unwrap().action,"block");
}

#[test]
fn legacy_exact_tier_preserves_unicode_lowercase_expansions() {
    let mut r=rule("WHEN prompt MATCHES detector(\"legacy\")\nSCOPE TRUE\nTHEN BLOCK");r.mode=Mode::Active;
    let mut data=input(vec![r],"İ");
    data.policy.detectors=vec![Detector{id:"legacy".into(),name:"Legacy".into(),definition:DetectorKind::Keyword{value:"i".into(),tier:"exact".into(),exceptions:vec![]}}];
    assert_eq!(evaluate(&data).unwrap().action,"block");
}

#[test]
fn policy_complexity_and_regex_dialects_are_bounded_before_evaluation() {
    let mut data=input(vec![rule(REPLACE)],"Tomate");
    let mut nested=Expr::True;
    for _ in 0..=MAX_DEPTH {nested=Expr::Not{child:Box::new(nested)};}
    data.policy.rules[0].condition=nested;assert!(evaluate(&data).is_err());
    for pattern in [r"(a)\1",r"(?=a)",r"a*",r"(?:)"] {
        let mut data=input(vec![rule(REPLACE)],"Tomate");
        data.policy.detectors=vec![Detector{id:"bad".into(),name:"Bad dialect".into(),definition:DetectorKind::Regex{pattern:pattern.into(),ignore_case:false}}];
        assert!(evaluate(&data).is_err(),"{pattern}");
    }
    let mut data=input(vec![rule(REPLACE)],"Tomate");data.policy.rules.push(data.policy.rules[0].clone());assert!(evaluate(&data).is_err());
    let mut data=input(vec![rule(REPLACE)],"Tomate");data.facts.insert("untrusted_scope".into(),"fixture".into());assert!(evaluate(&data).is_err());
    let oversized=serde_json::json!({"op":"parse","source":"x".repeat(524289)});
    let result:serde_json::Value=serde_json::from_slice(&dispatch(&serde_json::to_vec(&oversized).unwrap())).unwrap();assert_eq!(result["ok"],false);
}

#[test]
fn xor_unknown_is_irrelevant_after_two_true_branches_and_simulation_never_closes() {
    let mut r=rule("WHEN prompt CONTAINS \"alpha\" XOR prompt CONTAINS \"beta\" XOR UPLOAD SCOPE TRUE THEN BLOCK");r.mode=Mode::Active;
    let mut data=input(vec![r.clone()],"alpha beta");data.upload=None;
    assert_eq!(evaluate(&data).unwrap().action,"observe");
    data.texts.get_mut("prompt").unwrap()[0]="alpha".into();assert_eq!(evaluate(&data).unwrap().action,"block");
    data.policy.rules[0].mode=Mode::Simulation;
    let result=evaluate(&data).unwrap();assert_eq!(result.action,"observe");assert_eq!(result.texts["prompt"][0],"alpha");
}

#[test]
fn canadian_and_swiss_identifiers_require_valid_checksums_and_boundaries() {
    for (category,valid,invalid) in [
        ("ca_sin",vec!["100000009","100 000 009","100-000-009","１０００００００９"],vec!["100000000","800000003","X100000009Y","1100000009"]),
        ("ch_avs",vec!["7560000000002","756.0000.0000.02","756 0000 0000 02"],vec!["7560000000000","7570000000001","X7560000000002Y","17560000000002"]),
    ] {
        let mut data=input(vec![rule("WHEN prompt MATCHES detector(\"identifier\") SCOPE TRUE THEN MASK detector(\"identifier\") AS \"PRIVATE\"")],"");
        data.policy.rules[0].mode=Mode::Active;
        data.policy.detectors.push(Detector{id:"identifier".into(),name:"Synthetic identifier".into(),definition:DetectorKind::Builtin{category:category.into()}});
        for sample in valid {data.texts.insert("prompt".into(),vec![sample.into()]);let result=evaluate(&data).unwrap();assert_eq!(result.texts["prompt"][0],"[PRIVATE]","{category} {sample}");}
        for sample in invalid {data.texts.insert("prompt".into(),vec![sample.into()]);assert_eq!(evaluate(&data).unwrap().action,"observe","{category} {sample}");}
    }
}

#[test]
fn rule_application_is_checked_before_transformations_and_during_final_verification() {
    let mut replacement=rule(REPLACE);replacement.mode=Mode::Active;
    let mut blocked=rule("WHEN prompt CONTAINS \"Carotte\" SCOPE TRUE THEN BLOCK");blocked.id="other-device".into();blocked.mode=Mode::Active;
    blocked.application=Some(Application::Device{id:"11111111-1111-4111-8111-111111111111".into()});
    let mut data=input(vec![replacement,blocked],"Tomate");
    data.facts.insert("device_id".into(),"22222222-2222-4222-8222-222222222222".into());
    assert_eq!(evaluate(&data).unwrap().texts["prompt"][0],"Carotte");
    data.facts.insert("device_id".into(),"11111111-1111-4111-8111-111111111111".into());
    assert_eq!(evaluate(&data).unwrap().action,"block");
    data.facts.remove("device_id");data.texts.insert("prompt".into(),vec!["Carotte".into()]);
    assert_eq!(evaluate(&data).unwrap().reason,"control_unavailable");
    data.policy.rules[1].application=Some(Application::Group{id:"invalid".into()});assert!(validate(&data.policy).is_err());
}

#[test]
fn observing_first_never_skips_a_later_block_and_priority_only_arbitrates_rewrites() {
    let mut observation=rule("WHEN prompt CONTAINS \"Tomate\" SCOPE TRUE THEN OBSERVE");observation.id="observe-first".into();observation.priority=0;observation.mode=Mode::Active;
    let mut block=rule("WHEN prompt CONTAINS \"Tomate\" SCOPE TRUE THEN BLOCK");block.id="block-last".into();block.priority=65535;block.mode=Mode::Active;
    let result=evaluate(&input(vec![observation,block],"Tomate")).unwrap();assert_eq!(result.action,"block");assert_eq!(result.decisions.len(),2);
    let mut first=rule(REPLACE);first.id="first".into();first.priority=1;first.mode=Mode::Active;
    let mut second=rule("WHEN prompt CONTAINS \"Tomate\" SCOPE TRUE THEN REPLACE \"Tomate\" WITH \"Patate\"");second.id="second".into();second.priority=10;second.mode=Mode::Active;
    let result=evaluate(&input(vec![second,first],"Tomate")).unwrap();assert_eq!(result.texts["prompt"][0],"Carotte");assert_eq!(result.decisions.len(),2);
}

#[test]
fn dictionary_detectors_can_mask_exact_words_and_reject_approximate_masking() {
    let mut data=input(vec![rule("WHEN prompt MATCHES detector(\"terms\") SCOPE TRUE THEN MASK detector(\"terms\") AS \"PRIVATE\"")],"ProjectOne and ProjectTwo");data.policy.rules[0].mode=Mode::Active;
    data.policy.detectors=vec![Detector{id:"dictionary".into(),name:"Project dictionary".into(),definition:DetectorKind::Dictionary{values:vec!["ProjectOne".into(),"ProjectTwo".into()],exceptions:vec![]}},Detector{id:"terms".into(),name:"Project detector".into(),definition:DetectorKind::KeywordTier{dictionary:"dictionary".into(),tier:"exact".into()}}];
    assert_eq!(evaluate(&data).unwrap().texts["prompt"][0],"[PRIVATE1] and [PRIVATE2]");
    if let DetectorKind::KeywordTier{tier,..}=&mut data.policy.detectors[1].definition {*tier="fuzzy".into();}assert!(validate(&data.policy).is_err());
}

#[test]
fn document_heuristics_mask_the_whole_unit_and_bounded_negative_text_stays_unchanged() {
 for (category,sample) in [("source_code","const value = () => { return {value: 1}; }"),("medical","diagnostic and prescription")] {
    let mut data=input(vec![rule("WHEN prompt MATCHES detector(\"document\") SCOPE TRUE THEN MASK detector(\"document\") AS \"PRIVATE\"")],sample);data.policy.rules[0].mode=Mode::Active;
    data.policy.detectors.push(Detector{id:"document".into(),name:"Document heuristic".into(),definition:DetectorKind::Builtin{category:category.into()}});
    assert_eq!(evaluate(&data).unwrap().texts["prompt"][0],"[PRIVATE]");
    data.texts.insert("prompt".into(),vec!["ordinary neutral prose ".repeat(1000)]);assert_eq!(evaluate(&data).unwrap().action,"observe");
 }
}

#[test]
fn uuid_rule_applications_use_identity_not_hex_letter_case() {
    let mut blocked=rule("WHEN TRUE SCOPE TRUE THEN BLOCK");blocked.mode=Mode::Active;
    blocked.application=Some(Application::Device{id:"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into()});
    let mut data=input(vec![blocked],"synthetic");
    data.facts.insert("device_id".into(),"AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE".into());
    assert_eq!(evaluate(&data).unwrap().action,"block");
    data.policy.rules[0].application=Some(Application::Group{id:"AAAAAAAA-BBBB-4CCC-8DDD-EEEEEEEEEEEE".into()});
    data.facts.insert("group_id".into(),"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into());
    assert_eq!(evaluate(&data).unwrap().action,"block");
}

#[test]
fn multiple_targets_are_a_union_and_match_legacy_scope_projection() {
 let a="aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee";let b="bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee";let other="cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee";
 for groups in [true,false] {
  let mut r=rule("WHEN TRUE SCOPE channel = \"browser\" THEN BLOCK");r.mode=Mode::Active;
  r.application=Some(if groups {Application::Groups{ids:vec![a.into(),b.into()]}}else{Application::Devices{ids:vec![a.into(),b.into()]}});
  let field=if groups {"group_id"}else{"device_id"};
  let mut data=input(vec![r.clone()],"synthetic");
  let mut projected=r.clone();projected.application=None;projected.scope=Expr::All{children:vec![r.scope.clone(),Expr::In{field:field.into(),values:vec![a.into(),b.into()]}]};
  for identity in [Some(a),Some(b),Some(other),None] {
   data.facts.remove(field);if let Some(value)=identity {data.facts.insert(field.into(),value.into());}
   let actual=evaluate(&data).unwrap();let mut legacy=data.clone();legacy.policy.rules=vec![projected.clone()];let wire=evaluate(&legacy).unwrap();
   assert_eq!(actual.action,wire.action);assert_eq!(actual.decisions.len(),wire.decisions.len());assert!(actual.decisions.len()<=1);
   assert_eq!(actual.action,if identity==Some(other){"observe"}else{"block"});
  }
  data.policy.rules[0].application=Some(Application::Groups{ids:vec![]});assert!(validate(&data.policy).is_err());
  data.policy.rules[0].application=Some(Application::Groups{ids:vec![a.into(),a.to_uppercase()]});assert!(validate(&data.policy).is_err());
  data.policy.rules[0].application=Some(Application::Devices{ids:(0..129).map(|i|format!("{i:08x}-bbbb-4ccc-8ddd-eeeeeeeeeeee")).collect()});assert!(validate(&data.policy).is_err());
 }
}

#[test]
fn multiple_device_targets_also_restrict_final_verification() {
 let mut replacement=rule(REPLACE);replacement.mode=Mode::Active;
 let mut blocker=rule("WHEN prompt CONTAINS \"Carotte\" SCOPE TRUE THEN BLOCK");blocker.mode=Mode::Active;blocker.id="restricted-block".into();
 blocker.application=Some(Application::Devices{ids:vec!["aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into(),"bbbbbbbb-bbbb-4ccc-8ddd-eeeeeeeeeeee".into()]});
 let mut data=input(vec![replacement,blocker],"Tomate");data.facts.insert("device_id".into(),"cccccccc-bbbb-4ccc-8ddd-eeeeeeeeeeee".into());assert_eq!(evaluate(&data).unwrap().texts["prompt"][0],"Carotte");
 data.facts.insert("device_id".into(),"aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee".into());assert_eq!(evaluate(&data).unwrap().action,"block");
}

#[test]
fn dictionary_positive_list_preserves_legacy_exclusions_and_all_matching_tiers() {
    for tier in ["exact","unicode","fuzzy"] {
        let mut r=rule("WHEN prompt MATCHES detector(\"terms\") SCOPE TRUE THEN BLOCK");r.mode=Mode::Active;
        let mut original=input(vec![r],"");
        original.policy.detectors=vec![
            Detector{id:"words".into(),name:"Words".into(),definition:DetectorKind::Dictionary{values:vec!["Tomate".into(),"Carotte".into(),"Ｃａｒｏｔｔｅ".into()],exceptions:vec!["CAROTTE".into()]}},
            Detector{id:"terms".into(),name:"Terms".into(),definition:DetectorKind::KeywordTier{dictionary:"words".into(),tier:tier.into()}}
        ];
        let mut compact=original.clone();normalize_dictionaries(&mut compact.policy).unwrap();
        match &compact.policy.detectors[0].definition {DetectorKind::Dictionary{values,exceptions}=>{assert_eq!(values,&vec!["Tomate".to_string()]);assert!(exceptions.is_empty());},_=>panic!("dictionary expected")}
        let once=compact.policy.clone();normalize_dictionaries(&mut compact.policy).unwrap();assert_eq!(compact.policy,once);
        for sample in ["Tomate","Carotte","Ｃａｒｏｔｔｅ","tomate carotte","Tоmate", "Tomat", "aucun terme"] {
            original.texts.insert("prompt".into(),vec![sample.into()]);compact.texts=original.texts.clone();
            assert_eq!(serde_json::to_value(evaluate(&original).unwrap()).unwrap(),serde_json::to_value(evaluate(&compact).unwrap()).unwrap(),"tier {tier}, sample {sample}");
        }
    }
}

#[test]
fn dictionary_normalization_removes_all_excluded_entries_and_rejects_hostile_shapes() {
    let mut data=input(vec![],"");data.policy.detectors=vec![Detector{id:"words".into(),name:"Words".into(),definition:DetectorKind::Dictionary{values:vec!["Carotte".into()],exceptions:vec!["ＣＡＲＯＴＴＥ".into()]}}];
    let response:serde_json::Value=serde_json::from_slice(&dispatch(&serde_json::to_vec(&serde_json::json!({"op":"normalize","policy":data.policy})).unwrap())).unwrap();assert_eq!(response["ok"],true);assert_eq!(response["policy"]["detectors"][0]["definition"]["values"],serde_json::json!([]));assert_eq!(response["policy"]["detectors"][0]["definition"]["exceptions"],serde_json::json!([]));
    for request in [serde_json::json!({"op":"normalize","policy":{"image":"synthetic"}}),serde_json::json!({"op":"normalize","policy":data.policy,"save":true})] {
        let response:serde_json::Value=serde_json::from_slice(&dispatch(&serde_json::to_vec(&request).unwrap())).unwrap();assert_eq!(response["ok"],false);
    }
}

#[test]
fn audit_is_nonblocking_when_context_is_missing_but_prevention_remains_closed() {
 let mut audit=rule("WHEN UPLOAD SCOPE provider = \"missing\" THEN OBSERVE");audit.mode=Mode::Active;
 let mut data=input(vec![audit.clone()],"sample");data.upload=None;data.facts.remove("provider");
 let result=evaluate(&data).unwrap();assert_eq!(result.action,"observe");assert_eq!(result.decisions[0].outcome,"unavailable");
 audit.consequence=Effect::Block;data.policy.rules=vec![audit];assert_eq!(evaluate(&data).unwrap().action,"block");
}

#[test]
fn confirmation_preserves_text_requires_browser_context_and_cannot_override_block() {
 let mut warn=rule("WHEN prompt CONTAINS \"Tomate\" SCOPE channel = \"browser\" THEN WARN MESSAGE \"Check this submission.\"");warn.mode=Mode::Active;
 assert_eq!(parse(&print(&warn)).unwrap().consequence,Effect::Warn);
 let mut data=input(vec![warn.clone()],"Tomate");let result=evaluate(&data).unwrap();assert_eq!(result.action,"review");assert!(result.confirmation);assert!(!result.transformed);assert_eq!(result.texts,data.texts);assert_eq!(result.reason,"Check this submission.");
 let mut block=warn.clone();block.id="block".into();block.consequence=Effect::Block;data.policy.rules.push(block);let result=evaluate(&data).unwrap();assert_eq!(result.action,"block");assert!(!result.confirmation);assert_eq!(result.decisions.iter().find(|d|d.consequence=="warn").unwrap().outcome,"overridden");
 warn.scope=Expr::True;data.policy.native_inspection=true;data.policy.rules=vec![warn];data.facts.insert("channel".into(),"native".into());let result=evaluate(&data).unwrap();assert_eq!(result.action,"block");assert_eq!(result.reason,"control_unavailable");
}

#[test]
fn final_transformation_cannot_introduce_an_unconfirmed_warning() {
 let mut replace=rule(REPLACE);replace.mode=Mode::Active;
 let mut warn=rule("WHEN prompt CONTAINS \"Carotte\" SCOPE channel = \"browser\" THEN WARN MESSAGE \"Review the new value.\"");warn.mode=Mode::Active;warn.id="warning".into();
 let result=evaluate(&input(vec![replace,warn],"Tomate")).unwrap();assert_eq!(result.action,"review");assert!(result.confirmation);assert!(result.transformed);assert_eq!(result.reason,"Review the new value.");
}

#[test]
fn contextual_consequences_require_guaranteed_positive_matches_across_boolean_branches() {
 let mut data=input(vec![],"");data.policy.detectors=vec![Detector{id:"email".into(),name:"Email fixture".into(),definition:DetectorKind::Regex{pattern:"[a-z]+@[a-z]+\\.test".into(),ignore_case:false}}];
 for (source,mask,replace) in [
  ("WHEN prompt MATCHES detector(\"email\") AND prompt CONTAINS \"Tomate\" SCOPE channel = \"browser\" THEN BLOCK",true,true),
  ("WHEN prompt MATCHES detector(\"email\") OR UPLOAD SCOPE channel = \"browser\" THEN BLOCK",false,false),
  ("WHEN prompt MATCHES detector(\"email\") XOR UPLOAD SCOPE channel = \"browser\" THEN BLOCK",false,false),
  ("WHEN NOT prompt MATCHES detector(\"email\") SCOPE channel = \"browser\" THEN BLOCK",false,false),
  ("WHEN UPLOAD SCOPE channel = \"browser\" THEN BLOCK",false,false)] {
  let options=consequences::options(&data.policy,&rule(source)).unwrap();assert_eq!(!options.masks.is_empty(),mask);assert_eq!(!options.replacements.is_empty(),replace);assert!(options.warn);
 }
 let mut r=rule("WHEN UPLOAD SCOPE channel = \"browser\" THEN MASK detector(\"email\") AS \"REDACTED\"");assert_eq!(consequences::options(&data.policy,&r).unwrap().error.as_deref(),Some("mask_requires_positive_match"));
 r.condition=Expr::Matches{field:"prompt".into(),detector:"email".into(),minimum:1};r.consequence=Effect::Mask{detector:"email".into(),label:"a@b.test".into()};assert_eq!(consequences::options(&data.policy,&r).unwrap().error.as_deref(),Some("mask_label_matches_detector"));
}

#[test]
fn newly_introduced_warning_with_unknown_context_is_closed_without_false_attribution(){
 let mut rewrite=rule("WHEN prompt CONTAINS \"Tomate\" SCOPE channel = \"browser\" THEN REPLACE \"Tomate\" WITH \"Carotte\"");rewrite.mode=Mode::Active;rewrite.id="rewrite".into();
 let mut warn=rule("WHEN prompt CONTAINS \"Carotte\" SCOPE channel = \"browser\" AND model = \"restricted\" THEN WARN MESSAGE \"Check\"");warn.mode=Mode::Active;warn.id="warning".into();
 let result=evaluate(&input(vec![rewrite,warn],"Tomate")).unwrap();assert_eq!(result.action,"block");assert!(!result.confirmation);assert_eq!(result.reason,"control_unavailable");assert_eq!(result.decisions.last().unwrap().scope,Truth::Unknown);
}
