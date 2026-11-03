use crate::model::*;
use serde::Serialize;
use std::collections::BTreeSet;

#[derive(Clone,Debug,Serialize)]
pub struct ConsequenceOptions {
 pub masks:Vec<String>,pub replacements:Vec<ReplacementTarget>,pub warn:bool,pub review:bool,pub valid:bool,pub error:Option<String>
}
#[derive(Clone,Debug,Serialize,PartialEq,Eq)]
pub struct ReplacementTarget{pub value:String,pub ignore_case:bool,pub whole_word:bool}

fn guaranteed(expr:&Expr)->BTreeSet<String>{
 match expr {
  Expr::Matches{detector,..}=>BTreeSet::from([serde_json::json!({"detector":detector}).to_string()]),
  Expr::Contains{value,ignore_case,whole_word,..}=>BTreeSet::from([serde_json::json!({"value":value,"ignore_case":ignore_case,"whole_word":whole_word}).to_string()]),
  Expr::All{children}=>children.iter().flat_map(guaranteed).collect(),
  Expr::Any{children}|Expr::One{children}=>{let mut sets=children.iter().map(guaranteed);let mut result=sets.next().unwrap_or_default();for set in sets{result.retain(|value|set.contains(value));}result},
  _=>BTreeSet::new()
 }
}
fn precise(policy:&Policy,id:&str)->bool{
 policy.detectors.iter().find(|d|d.id==id).is_some_and(|d|match &d.definition{
  DetectorKind::Builtin{category}=>!matches!(category.as_str(),"source_code"|"medical"),
  DetectorKind::Keyword{..}|DetectorKind::DictionaryContext{..}=>false,
  DetectorKind::KeywordTier{tier,..}=>tier!="fuzzy",
  _=>true
 })
}
pub fn options(policy:&Policy,rule:&Rule)->Result<ConsequenceOptions,String>{
 // Analyze incomplete action/message drafts, but validate and bound every AST
 // and dictionary before recursively deriving guaranteed positive matches.
 let mut probe=policy.clone();let mut sample=rule.clone();sample.id="draft".into();sample.name="Draft".into();sample.revision=1;sample.application=None;sample.consequence=Effect::Block;sample.review=false;sample.message.clear();probe.rules=vec![sample];crate::validate(&probe)?;
 let mut masks=vec![];let mut replacements=vec![];
 for key in guaranteed(&rule.condition){
  let item:serde_json::Value=serde_json::from_str(&key).map_err(|_|"Invalid consequence target")?;
  if let Some(id)=item["detector"].as_str(){if precise(policy,id){masks.push(id.to_string());}}
  else if let Some(value)=item["value"].as_str(){replacements.push(ReplacementTarget{value:value.into(),ignore_case:item["ignore_case"]==true,whole_word:item["whole_word"]==true});}
 }
 let browser_only=!crate::evaluation::scope_allows_channel(policy,&rule.scope,"native")?;
 let error=match &rule.consequence {
  Effect::Observe if !rule.message.is_empty()=>Some("audit_has_no_user_message"),
  Effect::Warn if !browser_only=>Some("confirmation_requires_browser"),
  Effect::Warn if rule.message.trim().is_empty()=>Some("confirmation_message_required"),
  Effect::Mask{detector,..} if !masks.contains(detector)=>Some("mask_requires_positive_match"),
  Effect::Mask{detector,label} if crate::evaluation::mask_label_matches(policy,detector,label)?=>Some("mask_label_matches_detector"),
  Effect::Replace{value,ignore_case,whole_word,..} if !replacements.contains(&ReplacementTarget{value:value.clone(),ignore_case:*ignore_case,whole_word:*whole_word})=>Some("replace_requires_positive_literal"),
  _ if rule.review&&!browser_only=>Some("review_requires_browser"),
  _=>None
 };
 Ok(ConsequenceOptions{masks,replacements,warn:browser_only,review:browser_only,valid:error.is_none(),error:error.map(str::to_owned)})
}
