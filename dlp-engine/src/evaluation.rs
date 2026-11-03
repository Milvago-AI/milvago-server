use crate::model::*;
use regex::{Regex, RegexBuilder};
use std::collections::{BTreeMap, BTreeSet};
use unicode_normalization::UnicodeNormalization;

const FIELDS: &[&str] = &["channel", "provider", "tool", "device_id", "group_id", "model", "organization_id"];
const TEXT_FIELDS: &[&str] = &["prompt"];

fn bounded(value: &str, max: usize) -> bool { !value.is_empty() && value.len() <= max && !value.chars().any(char::is_control) }
fn identifier(value: &str) -> bool { value.len() <= 100 && !value.is_empty() && value.bytes().all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'-' | b'.')) }
fn regex(pattern: &str, ignore_case: bool) -> Result<Regex, String> {
    if pattern.len() > 1024 { return Err("Pattern exceeds the limit".into()); }
    let re = RegexBuilder::new(pattern).case_insensitive(ignore_case).size_limit(262144).dfa_size_limit(524288).build().map_err(|_| "Unsupported or excessive regular expression")?;
    if re.is_match("") { return Err("Patterns must not match empty input".into()); }
    Ok(re)
}
fn literal(value: &str, ignore_case: bool, whole_word: bool) -> Result<Regex, String> {
    if !bounded(value, 512) { return Err("Invalid literal".into()); }
    let escaped = regex::escape(value);
    regex(&if whole_word { format!(r"\b(?:{escaped})\b") } else { escaped }, ignore_case)
}
fn validate_expr(expr: &Expr, scope: bool, detectors: &BTreeSet<&str>, depth: usize, nodes: &mut usize) -> Result<(), String> {
    *nodes += 1;
    if depth > MAX_DEPTH || *nodes > MAX_NODES { return Err("Condition exceeds the complexity limit".into()); }
    match expr {
        Expr::All { children } | Expr::Any { children } | Expr::One { children } => {
            if !(2..=32).contains(&children.len()) { return Err("A condition group needs 2 to 32 children".into()); }
            for child in children { validate_expr(child, scope, detectors, depth + 1, nodes)?; }
        }
        Expr::Not { child } => validate_expr(child, scope, detectors, depth + 1, nodes)?,
        Expr::True => (),
        Expr::Upload if !scope => (),
        Expr::Contains { field, value, ignore_case, whole_word } if !scope && TEXT_FIELDS.contains(&field.as_str()) => { literal(value, *ignore_case, *whole_word)?; }
        Expr::Matches { field, detector, minimum } if !scope && TEXT_FIELDS.contains(&field.as_str()) && detectors.contains(detector.as_str()) && (1..=MAX_MATCHES).contains(minimum) => (),
        Expr::Eq { field, value } if FIELDS.contains(&field.as_str()) && bounded(value, 256) => (),
        Expr::In { field, values } if FIELDS.contains(&field.as_str()) && !values.is_empty() && values.len() <= 128 && values.iter().all(|v| bounded(v, 256)) => (),
        _ => return Err("Unsupported field, detector or condition".into()),
    }
    Ok(())
}

pub fn validate(policy: &Policy) -> Result<(), String> {
    if policy.schema_version != 1 || policy.rules.len() > MAX_RULES || policy.detectors.len() > MAX_DETECTORS || serde_json::to_vec(policy).map_err(|_| "Invalid policy")?.len() > MAX_POLICY { return Err("Unsupported or excessive policy".into()); }
    let mut detectors = BTreeSet::new();
    for d in &policy.detectors {
        if !identifier(&d.id) || !bounded(&d.name, 100) || !detectors.insert(d.id.as_str()) { return Err("Invalid or duplicate detector".into()); }
        match &d.definition {
            DetectorKind::Literal { value, ignore_case, whole_word, .. } => { literal(value, *ignore_case, *whole_word)?; }
            DetectorKind::Regex { pattern, ignore_case } => { if pattern.len() > 200 { return Err("Custom pattern exceeds the limit".into()); } regex(pattern, *ignore_case)?; }
            DetectorKind::Builtin { category } => { builtin(category)?; }
            DetectorKind::Keyword { value, tier, exceptions } => {
                if !bounded(value, 200) || !["exact", "unicode", "fuzzy"].contains(&tier.as_str()) || exceptions.len() > 200 || exceptions.iter().any(|v| !bounded(v, 200)) { return Err("Invalid legacy keyword detector".into()); }
            }
            DetectorKind::Dictionary { values, exceptions } => {
                if values.len() > 200 || exceptions.len() > 200 || values.iter().chain(exceptions.iter()).any(|v| !bounded(v,200)) { return Err("Dictionary exceeds its limits".into()); }
            }
            DetectorKind::KeywordTier { dictionary, tier } => {
                if !["exact","unicode","fuzzy"].contains(&tier.as_str()) || !policy.detectors.iter().any(|d| d.id == *dictionary && matches!(d.definition, DetectorKind::Dictionary { .. })) { return Err("Invalid dictionary reference".into()); }
            }
            DetectorKind::DictionaryContext { dictionary, minimum } => {
                if !(1..=200).contains(minimum) || !policy.detectors.iter().any(|d| d.id == *dictionary && matches!(d.definition, DetectorKind::Dictionary { .. })) { return Err("Invalid contextual dictionary reference or threshold".into()); }
            }
        }
    }
    let mut ids = BTreeSet::new();
    for r in &policy.rules {
        if !identifier(&r.id) || !ids.insert(&r.id) || r.revision == 0 || r.revision > 9007199254740991 || !bounded(&r.name, 100) || r.message.len() > 1000 || r.message.contains('\0') { return Err("Invalid or duplicate rule".into()); }
        let targets: Vec<&str> = match &r.application {
            Some(Application::Group{id}|Application::Device{id})=>vec![id.as_str()],
            Some(Application::Groups{ids}|Application::Devices{ids})=>ids.iter().map(String::as_str).collect(),
            _=>vec![],
        };
        let multiple=matches!(r.application,Some(Application::Groups{..}|Application::Devices{..}));
        if multiple && !(1..=128).contains(&targets.len()) {return Err("Choose 1 to 128 rule targets".into());}
        let mut identities=BTreeSet::new();
        for id in targets {
            if id.len()!=36 || !id.bytes().enumerate().all(|(i,b)|if [8,13,18,23].contains(&i){b==b'-'}else{b.is_ascii_hexdigit()}) || !identities.insert(id.to_ascii_lowercase()) {return Err("Invalid or duplicate rule application identity".into());}
        }
        let mut nodes = if multiple {2} else {0};
        validate_expr(&r.condition, false, &detectors, 0, &mut nodes)?;
        validate_expr(&r.scope, true, &detectors, usize::from(multiple), &mut nodes)?;
        if r.review && (matches!(r.consequence, Effect::Observe | Effect::Warn | Effect::Block)) { return Err("Review requires an interactive transformation".into()); }
        match &r.consequence {
            Effect::Observe | Effect::Block => (),
            Effect::Warn => {if r.message.trim().is_empty(){return Err("Confirmation requires a message".into());}},
            Effect::Replace { value, replacement, ignore_case, whole_word } => {
                literal(value, *ignore_case, *whole_word)?;
                if replacement.len() > 1024 || replacement.contains('\0') { return Err("Replacement exceeds the limit".into()); }
            }
            Effect::Mask { detector, label } => {
                if !detectors.contains(detector.as_str()) || !bounded(label, 60) || label.chars().any(|c| matches!(c, '[' | ']')) { return Err("Invalid mask target or label".into()); }
                if let Some(Detector { definition: DetectorKind::Regex { pattern, ignore_case }, .. }) = policy.detectors.iter().find(|d| &d.id == detector) {
                    if regex(pattern, *ignore_case)?.is_match(label) { return Err("A mask label must not match its own detector".into()); }
                }
                if policy.detectors.iter().find(|d| &d.id == detector).is_some_and(|d| match &d.definition {DetectorKind::Keyword{..}|DetectorKind::DictionaryContext{..}=>true,DetectorKind::KeywordTier{tier,..}=>tier=="fuzzy",_=>false}) { return Err("Contextual or approximate dictionary matches cannot mask; choose exact or Unicode matching".into()); }
            }
        }
    }
    Ok(())
}

fn builtin(category: &str) -> Result<Regex, String> {
    let pattern = match category {
        "email" => r"[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}",
        "phone" => r"(?:\+[0-9]{1,3}[ .-]?)?(?:[0-9][ .-]?){8,14}[0-9]",
        "iban" => r"[A-Z]{2}[0-9]{2}(?:(?:[ ]{1,2}|\t|\r?\n|[.-])?[A-Z0-9]){11,30}",
        "card" => r"(?:[0-9]{13,19}|[0-9]{4}(?:[ .-][0-9]{4}){3}|[0-9]{4}[ .-][0-9]{6}[ .-][0-9]{5})",
        "social_id" | "fr_nir" => r"\b[12][0-9]{12,14}\b",
        "ca_sin" => r"\b[1-79][0-9]{2}(?:[ -]?[0-9]{3}){2}\b",
        "ch_avs" => r"\b756(?:[. ]?[0-9]{4}){2}[. ]?[0-9]{2}\b",
        "source_code" | "medical" => r"(?s).+",
        "ssn_us" | "us_ssn" => r"\b[0-9]{3}-[0-9]{2}-[0-9]{4}\b",
        "ip" => r"\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b",
        _ => return Err("Unknown built-in detector".into()),
    };
    regex(pattern, true)
}

#[derive(Default)]
struct View { text: String, source: Vec<(usize, usize, usize)> }
fn view(text: &str, fold: bool, compact: bool) -> View {
    let mut out = View::default();
    for (at, c) in text.char_indices() {
        let end = at + c.len_utf8();
        let composed: String = c.to_string().nfkc().collect();
        let chars: Vec<char> = if fold { unicode_security::skeleton(&composed).flat_map(char::to_lowercase).collect() } else { composed.chars().collect() };
        for c in chars {
            if invisible(c) || unicode_normalization::char::is_combining_mark(c) || (compact && !c.is_alphanumeric()) { continue; }
            out.source.push((out.text.len(), at, end)); out.text.push(c);
        }
    }
    out
}
fn invisible(c: char) -> bool {
    matches!(c, '\u{ad}' | '\u{34f}' | '\u{600}'..='\u{605}' | '\u{61c}' | '\u{6dd}' | '\u{70f}' | '\u{8e2}' | '\u{115f}' | '\u{1160}' | '\u{17b4}'..='\u{17b5}' | '\u{180b}'..='\u{180f}' | '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{2060}'..='\u{206f}' | '\u{2800}' | '\u{3164}' | '\u{fe00}'..='\u{fe0f}' | '\u{feff}' | '\u{ffa0}' | '\u{fff9}'..='\u{fffb}' | '\u{110bd}' | '\u{110cd}' | '\u{1bca0}'..='\u{1bca3}' | '\u{1d173}'..='\u{1d17a}' | '\u{890}' | '\u{891}' | '\u{fff0}'..='\u{fff8}' | '\u{13430}'..='\u{1343f}' | '\u{e0000}'..='\u{e0fff}')
}
impl View {
    fn range(&self, start: usize, end: usize) -> Option<(usize, usize)> {
        let first = self.source.partition_point(|s| s.0 < start); let last = self.source.partition_point(|s| s.0 < end);
        (first < last).then(|| (self.source[first].1, self.source[last - 1].2))
    }
}
// Legacy exclusions removed an entire normalized entry, never just a context.
// Compact mutable policies to a positive list without changing that behavior.
pub fn normalize_dictionaries(policy: &mut Policy) -> Result<(), String> {
    validate(policy)?;
    for detector in &mut policy.detectors {
        if let DetectorKind::Dictionary { values, exceptions } = &mut detector.definition {
            if exceptions.is_empty() { continue; }
            let excluded: BTreeSet<String> = exceptions.iter().map(|value| view(value,true,false).text).collect();
            values.retain(|value| !excluded.contains(&view(value,true,false).text));
            exceptions.clear();
        }
    }
    Ok(())
}

fn distance_one(a: &str, b: &str) -> bool {
    let a: Vec<char> = a.chars().collect(); let b: Vec<char> = b.chars().collect();
    if a.len() < 4 || a.len() > 64 || b.len() > 64 || a.len().abs_diff(b.len()) > 1 { return false; }
    let (mut i, mut j, mut errors) = (0, 0, 0);
    while i < a.len() && j < b.len() {
        if a[i] == b[j] { i += 1; j += 1; continue; }
        errors += 1; if errors > 1 { return false; }
        if a.len() >= b.len() { i += 1; } if b.len() >= a.len() { j += 1; }
    }
    errors + a.len() - i + b.len() - j <= 1
}
fn plausible(category: &str, text: &str) -> bool {
    let compact: String = text.chars().filter(|c| !matches!(c, ' ' | '-' | '.' | '\t' | '\n' | '\r')).collect();
    match category {
        "ip" => text.parse::<std::net::Ipv4Addr>().is_ok(),
        "ssn_us" | "us_ssn" => { let p: Vec<_> = text.split('-').collect(); p.len() == 3 && p[0] != "000" && p[0] != "666" && !p[0].starts_with('9') && p[1] != "00" && p[2] != "0000" }
        "source_code" => {
            let indicators=["function ","import ","fn ","def ","class ","return ","const ","public ","#include","=>","->","()","{}","};"];
            let hits=indicators.iter().filter(|term|text.contains(**term)).count();
            let nested=text.chars().scan(0i32,|depth,c|{*depth+=match c{'{'|'('| '['=>1,'}'|')'|']'=>-1,_=>0};Some(*depth)}).any(|depth|depth>=2);
            hits>=3||(hits>=2&&nested)
        }
        "medical" => {let lower=text.to_lowercase();["diagnostic","ordonnance","prescription","medical record","dossier médical"].iter().filter(|term|lower.contains(**term)).take(2).count()>=2}
        "ch_avs" => {
            let d:Vec<u32>=compact.chars().filter_map(|c|c.to_digit(10)).collect();
            d.len()==13&&compact.starts_with("756")&&d.iter().enumerate().map(|(i,v)|if i%2==1{v*3}else{*v}).sum::<u32>()%10==0
        }
        "ca_sin" => {
            let d:Vec<u32>=compact.chars().filter_map(|c|c.to_digit(10)).collect();
            d.len()==9&&d[0]!=0&&d[0]!=8&&d.iter().rev().enumerate().map(|(i,v)|{let n=if i%2==1{v*2}else{*v};if n>9{n-9}else{n}}).sum::<u32>()%10==0
        }
        "card" => {
            let d: Vec<u32> = compact.chars().filter_map(|c| c.to_digit(10)).collect();
            (13..=19).contains(&d.len()) && !d.iter().all(|v| *v == d[0]) && d.iter().rev().enumerate().map(|(i,v)| { let n = if i % 2 == 1 { v * 2 } else { *v }; if n > 9 { n - 9 } else { n } }).sum::<u32>() % 10 == 0
        }
        "iban" => {
            let value = compact.to_ascii_uppercase(); if !(15..=34).contains(&value.len()) || !value.is_ascii() { return false; }
            let mut remainder = 0; for b in value.bytes().skip(4).chain(value.bytes().take(4)) {
                if b.is_ascii_digit() { remainder = (remainder * 10 + u32::from(b - b'0')) % 97; }
                else if b.is_ascii_uppercase() { remainder = (remainder * 100 + u32::from(b - b'A' + 10)) % 97; } else { return false; }
            } remainder == 1
        }
        _ => true,
    }
}

fn ranges(detector: &Detector, text: &str) -> Result<Vec<(usize, usize)>, String> {
    if let DetectorKind::Builtin{category}=&detector.definition {
        if matches!(category.as_str(),"source_code"|"medical") {
            return Ok(if plausible(category,text){vec![(0,text.len())]}else{vec![]});
        }
    }
    let mut output = Vec::new();
    let normalized;
    let (source, re, map) = match &detector.definition {
        DetectorKind::Literal { value, ignore_case, whole_word, unicode } => {
            if *unicode { normalized = view(text, false, false); (normalized.text.as_str(), literal(value, *ignore_case, *whole_word)?, Some(&normalized)) }
            else { (text, literal(value, *ignore_case, *whole_word)?, None) }
        }
        DetectorKind::Regex { pattern, ignore_case } => { normalized = view(text, false, false); (normalized.text.as_str(), regex(pattern, *ignore_case)?, Some(&normalized)) }
        DetectorKind::Builtin { category } => { normalized = view(text, false, false); (normalized.text.as_str(), builtin(category)?, Some(&normalized)) }
        DetectorKind::Keyword { value, tier, exceptions } => {
            let key = view(value, true, false).text;
            if exceptions.iter().any(|e| view(e, true, false).text == key) { return Ok(output); }
            let lower=text.to_lowercase();let keyword=value.to_lowercase();
            if *tier == "exact" {
                return Ok(lower.match_indices(&keyword).take(MAX_MATCHES+1).map(|(at,_)|{
                    if text.get(at..at+keyword.len()).is_some_and(|value|value.to_lowercase()==keyword){(at,at+keyword.len())}else{(0,text.len())}
                }).collect());
            }
            if lower.contains(&keyword) { return Ok(output); }
            let folded = view(text, true, false); let compact = view(text, true, true); let short = view(value, true, true).text;
            let mapped = if folded.text.contains(&key) { Some((&folded, key.as_str())) } else if short.chars().count() >= 4 && compact.text.contains(&short) { Some((&compact, short.as_str())) } else { None };
            if *tier == "unicode" {
                if let Some((v, k)) = mapped { for (at, _) in v.text.match_indices(k) { if let Some(r) = v.range(at, at + k.len()) { output.push(r); } if output.len() > MAX_MATCHES { break; } } }
            } else if mapped.is_none() {
                for word in folded.text.split(|c: char| !c.is_alphanumeric()) { if distance_one(&key, word) { output.push((0, text.len())); break; } }
            }
            return Ok(output);
        }
        DetectorKind::Dictionary { .. } | DetectorKind::KeywordTier { .. } | DetectorKind::DictionaryContext { .. } => return Err("Dictionary requires policy context".into()),
    };
    // Built-in candidates can greedily absorb following words; retry bounded prefixes.
    if let DetectorKind::Builtin { category } = &detector.definition {
        let whole = regex(&format!("^(?:{})$", re.as_str()), true)?;
        let mut at = 0;
        while at < source.len() {
            let Some(m) = re.find_at(source, at) else { break; };
            let mut ends: Vec<usize> = std::iter::once(m.end()).chain(source[m.start()..m.end()].char_indices().filter(|(i,c)| *i > 0 && !c.is_alphanumeric()).map(|(i,_)| m.start()+i).filter(|end| source[..*end].chars().next_back().is_some_and(char::is_alphanumeric))).collect();
            if matches!(category.as_str(),"source_code"|"medical") {ends.truncate(1);} else {ends[1..].reverse();}
            let candidate = ends.into_iter().find(|end| {
                let boundary = !matches!(category.as_str(), "card" | "iban") || (!source[..m.start()].chars().next_back().is_some_and(|c| c.is_ascii_alphanumeric()) && !source[*end..].chars().next().is_some_and(|c| c.is_ascii_alphanumeric()));
                boundary && whole.is_match(&source[m.start()..*end]) && plausible(category, &source[m.start()..*end])
            });
            if let Some(end) = candidate { if let Some(range) = map.and_then(|v| v.range(m.start(), end)) { output.push(range); } at = end; }
            else { at = m.start() + source[m.start()..].chars().next().map_or(1, char::len_utf8); }
            if output.len() > MAX_MATCHES { break; }
        }
    } else {
        for m in re.find_iter(source).take(MAX_MATCHES + 1) { if let Some(range) = map.map_or(Some((m.start(),m.end())), |v| v.range(m.start(),m.end())) { output.push(range); } }
    }
    Ok(output)
}

#[derive(Clone)]
struct Marker { field: String, index: usize, start: usize, end: usize, detector: String }
#[derive(Clone, Copy)]
struct WorkBudget {
    bytes: usize,
    #[cfg(not(target_arch="wasm32"))]
    deadline: std::time::Instant,
}
impl WorkBudget {
    fn new() -> Self { Self { bytes:64*1024*1024,
        #[cfg(not(target_arch="wasm32"))]
        deadline:std::time::Instant::now()+std::time::Duration::from_secs(2),
    } }
    fn charge(&mut self,bytes:usize)->Result<(),String> {
        #[cfg(not(target_arch="wasm32"))]
        if std::time::Instant::now()>=self.deadline{return Err("Inspection work deadline exceeded".into());}
        self.bytes=self.bytes.checked_sub(bytes.max(4096)).ok_or("Inspection work budget exceeded")?;
        Ok(())
    }
}
struct Env<'a> { input: &'a Input, markers: &'a [Marker], budget: usize, work: Option<WorkBudget>, context_work: WorkBudget }
impl Env<'_> {
    fn matches(&mut self, field: &str, detector: &Detector) -> Result<Option<Vec<(usize,usize,usize)>>, String> {
        let Some(texts) = self.input.texts.get(field) else { return Ok(None); };
        let mut found = Vec::new();
        for (index, text) in texts.iter().enumerate() {
            let detected = if let DetectorKind::DictionaryContext { dictionary,minimum } = &detector.definition {
                let Some(Detector { definition:DetectorKind::Dictionary { values,exceptions }, .. }) = self.input.policy.detectors.iter().find(|d| d.id == *dictionary) else { return Err("Dictionary unavailable".into()); };
                // Count distinct expressions within this one text value, never
                // repetitions or expressions spread across independent values.
                let lower=text.to_lowercase();
                let excluded:BTreeSet<_>=exceptions.iter().map(|v|view(v,true,false).text).collect();
                let terms:BTreeSet<_>=values.iter().filter(|v|!excluded.contains(&view(v,true,false).text)).map(|v|v.to_lowercase()).collect();
                let mut hits=0;
                for term in terms {
                    self.context_work.charge(lower.len())?;
                    if let Some(work)=&mut self.work {work.charge(lower.len())?;}
                    if lower.contains(&term) { hits+=1; if hits>=*minimum {break;} }
                }
                if hits>=*minimum {vec![(0,text.len())]} else {vec![]}
            } else if let DetectorKind::KeywordTier { dictionary,tier } = &detector.definition {
                let Some(Detector { definition:DetectorKind::Dictionary { values,exceptions }, .. }) = self.input.policy.detectors.iter().find(|d| d.id == *dictionary) else { return Err("Dictionary unavailable".into()); };
                let mut found=Vec::new();
                for value in values {
                    if let Some(work)=&mut self.work {work.charge(text.len())?;}
                    let definition=Detector { id:detector.id.clone(),name:detector.name.clone(),definition:DetectorKind::Keyword { value:value.clone(),tier:tier.clone(),exceptions:exceptions.clone() } };
                    found.extend(ranges(&definition,text)?); if found.len()>MAX_MATCHES{return Err("Detection budget exceeded".into());}
                }
                found
            } else if let DetectorKind::Dictionary { values,exceptions } = &detector.definition {
                let mut found=Vec::new();
                for value in values {
                    if let Some(work)=&mut self.work {work.charge(text.len())?;}
                    let definition=Detector { id:detector.id.clone(),name:detector.name.clone(),definition:DetectorKind::Keyword { value:value.clone(),tier:"exact".into(),exceptions:exceptions.clone() } };
                    found.extend(ranges(&definition,text)?); if found.len()>MAX_MATCHES{return Err("Detection budget exceeded".into());}
                }
                found
            } else {
                if let Some(work)=&mut self.work {work.charge(text.len())?;}
                ranges(detector,text)?
            };
            for (start,end) in detected {
                if self.budget == 0 { return Err("Detection budget exceeded".into()); } self.budget -= 1;
                if self.markers.iter().any(|m| m.field == field && m.index == index && m.detector == detector.id && start >= m.start && end <= m.end) { continue; }
                found.push((index,start,end));
            }
        }
        Ok(Some(found))
    }
    fn expr(&mut self, value: &Expr) -> Result<Truth, String> {
        use Truth::*;
        Ok(match value {
            Expr::True => True,
            Expr::Upload => match self.input.upload { Some(true) => True, Some(false) => False, None => Unknown },
            Expr::Not { child } => match self.expr(child)? { True => False, False => True, Unknown => Unknown },
            Expr::All { children } | Expr::Any { children } | Expr::One { children } => {
                let values: Vec<Truth> = children.iter().map(|v| self.expr(v)).collect::<Result<_,_>>()?;
                let yes = values.iter().filter(|v| **v == True).count(); let unknown = values.contains(&Unknown);
                match value {
                    Expr::All { .. } => if values.contains(&False) { False } else if unknown { Unknown } else { True },
                    Expr::Any { .. } => if yes > 0 { True } else if unknown { Unknown } else { False },
                    _ => if yes > 1 { False } else if unknown { Unknown } else if yes == 1 { True } else { False },
                }
            }
            Expr::Eq { field, value } => self.input.facts.get(field).map_or(Unknown, |actual| if actual == value { True } else { False }),
            Expr::In { field, values } => self.input.facts.get(field).map_or(Unknown, |actual| if values.contains(actual) { True } else { False }),
            Expr::Contains { field, value, ignore_case, whole_word } => {
                let d = Detector { id: "literal".into(), name: "literal".into(), definition: DetectorKind::Literal { value:value.clone(), ignore_case:*ignore_case, whole_word:*whole_word, unicode:false } };
                match self.matches(field, &d)? { None => Unknown, Some(v) if v.is_empty() => False, _ => True }
            }
            Expr::Matches { field, detector, minimum } => {
                let d = self.input.policy.detectors.iter().find(|d| &d.id == detector).ok_or("Detector is unavailable")?.clone();
                match self.matches(field, &d)? { None => Unknown, Some(v) if v.len() >= *minimum => True, _ => False }
            }
        })
    }
}

#[derive(Clone)]
struct Patch { field: String, index: usize, start: usize, end: usize, replacement: String, sources: Vec<(usize,String)>, mask: bool, priority: u16, id: String }
fn effect_name(effect: &Effect) -> &'static str { match effect { Effect::Observe => "observe", Effect::Warn => "warn", Effect::Block => "block", Effect::Mask { .. } => "mask", Effect::Replace { .. } => "replace" } }
fn patches(env: &mut Env<'_>, rule: &Rule, decision: usize) -> Result<Vec<Patch>,String> {
    let (detector, label, replacement, mask) = match &rule.consequence {
        Effect::Mask { detector, label } => (env.input.policy.detectors.iter().find(|d| &d.id == detector).ok_or("Detector is unavailable")?.clone(), label.as_str(), "", true),
        Effect::Replace { value, replacement, ignore_case, whole_word } => (Detector { id: format!("replace-{}",rule.id), name: "replacement".into(), definition: DetectorKind::Literal { value:value.clone(), ignore_case:*ignore_case, whole_word:*whole_word, unicode:false } }, "", replacement.as_str(), false),
        _ => return Ok(vec![]),
    };
    let mut found = Vec::new(); let mut numbers: BTreeMap<String,usize> = BTreeMap::new();
    for field in TEXT_FIELDS {
        if let Some(matches) = env.matches(field, &detector)? {
            for (index,start,end) in matches { found.push((field.to_string(),index,start,end)); }
        }
    }
    if mask { for (field,index,start,end) in &found { let value = &env.input.texts[field][*index][*start..*end]; if !numbers.contains_key(value) { numbers.insert(value.to_string(),numbers.len()+1); } } }
    Ok(found.into_iter().map(|(field,index,start,end)| {
        let value = &env.input.texts[&field][index][start..end];
        let replacement = if mask { if numbers.len() > 1 { format!("[{label}{}]", numbers[value]) } else { format!("[{label}]") } } else { replacement.to_string() };
        Patch { field,index,start,end,replacement,sources:vec![(decision,detector.id.clone())],mask,priority:rule.priority,id:rule.id.clone() }
    }).collect())
}

fn application_truth(application:&Option<Application>,facts:&BTreeMap<String,String>)->Truth {
    let (field,ids):(&str,Vec<&str>)=match application {
        None|Some(Application::Organization)=>return Truth::True,
        Some(Application::Group{id})=>("group_id",vec![id.as_str()]),
        Some(Application::Device{id})=>("device_id",vec![id.as_str()]),
        Some(Application::Groups{ids})=>("group_id",ids.iter().map(String::as_str).collect()),
        Some(Application::Devices{ids})=>("device_id",ids.iter().map(String::as_str).collect()),
    };
    facts.get(field).map_or(Truth::Unknown,|actual|if ids.iter().any(|id|actual.eq_ignore_ascii_case(id)){Truth::True}else{Truth::False})
}

pub fn evaluate(input: &Input) -> Result<Output, String> {
    evaluate_bounded(input,MAX_TEXT,256,Some(WorkBudget::new()))
}

/// Inspect one complete larger structured unit, never independent fragments.
/// This entry point is deliberately absent from dispatch: JSON/WASM callers
/// cannot select a different capacity through facts or request fields.
pub fn evaluate_large_unit(input:&Input)->Result<Output,String> {
    evaluate_bounded(input,MAX_LARGE_UNIT_TEXT,MAX_LARGE_UNIT_VALUES,Some(WorkBudget::new()))
}

fn evaluate_bounded(input:&Input,max_text:usize,max_values:usize,work:Option<WorkBudget>)->Result<Output,String> {
    validate(&input.policy)?;
    if input.texts.len() > 2 || input.texts.keys().any(|k| !TEXT_FIELDS.contains(&k.as_str())) || input.texts.values().map(Vec::len).sum::<usize>() > max_values || input.texts.values().flatten().map(String::len).sum::<usize>() > max_text || input.facts.len() > FIELDS.len() || input.facts.iter().any(|(k,v)| !FIELDS.contains(&k.as_str()) || !bounded(v,256)) { return Err("Inspection input exceeds its limits or has unknown fields".into()); }
    let mut output = Output { action: "observe".into(), texts: input.texts.clone(), decisions: vec![], reason: String::new(), transformed: false, confirmation:false };
    if !input.policy.inspection || (input.policy.domain == Domain::Endpoint && input.facts.get("channel").is_some_and(|value| value == "native") && !input.policy.native_inspection) { return Ok(output); }
    let mut env = Env { input, markers: &[], budget:8192, work, context_work:WorkBudget::new() };
    let mut all = Vec::new(); let mut review = false;let mut notices:Vec<String>=vec![];
    let mut ordered: Vec<&Rule> = input.policy.rules.iter().collect(); ordered.sort_by(|a,b| (a.priority,&a.id).cmp(&(b.priority,&b.id)));
    for rule in &ordered {
        if rule.mode == Mode::Disabled { continue; }
        let mut scope = env.expr(&rule.scope)?;
        let target=application_truth(&rule.application,&input.facts);
        scope=if scope==Truth::False||target==Truth::False{Truth::False}else if scope==Truth::Unknown||target==Truth::Unknown{Truth::Unknown}else{Truth::True};
        if scope == Truth::False { continue; }
        let condition = env.expr(&rule.condition)?;
        if condition == Truth::False { continue; }
        let unknown = scope == Truth::Unknown || condition == Truth::Unknown;
        let active = rule.mode == Mode::Active;
        let unavailable=unknown || matches!(rule.consequence,Effect::Warn) && input.facts.get("channel").is_none_or(|channel|channel!="browser");
        let outcome = if unknown { "unavailable" } else if !active { "simulated" } else { "matched" };
        let index = output.decisions.len();
        output.decisions.push(Decision { rule_id:rule.id.clone(), rule_revision:rule.revision, rule_name:rule.name.clone(), mode:rule.mode.clone(), consequence:effect_name(&rule.consequence).into(), condition, scope, outcome:outcome.into(), occurrences:0 });
        if active && ((unavailable && !matches!(rule.consequence,Effect::Observe)) || matches!(rule.consequence, Effect::Block)) {
            output.action = "block".into(); output.reason = if unavailable { "control_unavailable".into() } else { rule.message.clone() }; output.decisions[index].outcome = if unavailable { "unavailable" } else { "blocked" }.into();
        } else if !unknown {
            if active && matches!(rule.consequence,Effect::Warn) {output.confirmation=true;review=true;if !notices.contains(&rule.message){notices.push(rule.message.clone());}output.decisions[index].outcome="prepared".into();}
            let changes = patches(&mut env,rule,index)?; output.decisions[index].occurrences = changes.len();
            if active { if !changes.is_empty() { review |= rule.review; } all.extend(changes); }
            else { output.decisions[index].outcome = "simulated".into(); }
        }
    }
    if output.action == "block" {
        output.confirmation=false;
        for d in &mut output.decisions { if d.outcome == "matched" || d.consequence=="warn"&&d.outcome=="prepared" { d.outcome = "overridden".into(); } }
        return Ok(output);
    }
    all.sort_by(|a,b| (!a.mask,a.priority,&a.id,&a.field,a.index,a.start).cmp(&(!b.mask,b.priority,&b.id,&b.field,b.index,b.start)));
    let mut chosen: Vec<Patch> = Vec::new();
    for mut change in all {
        let overlaps: Vec<usize> = chosen.iter().enumerate().filter(|(_,p)| p.field == change.field && p.index == change.index && p.start < change.end && change.start < p.end).map(|(i,_)| i).collect();
        if overlaps.is_empty() { chosen.push(change); }
        else if change.mask {
            // A mask must cover the union: discarding an overlap could expose its tail.
            for index in overlaps.into_iter().rev() {
                let old = chosen.remove(index);
                change.start = change.start.min(old.start); change.end = change.end.max(old.end);
                change.sources.extend(old.sources);
                if (old.priority,&old.id) < (change.priority,&change.id) {
                    change.replacement=old.replacement;change.priority=old.priority;change.id=old.id;
                }
            }
            chosen.push(change);
        }
    }
    chosen.sort_by(|a,b| (&a.field,a.index,a.start).cmp(&(&b.field,b.index,b.start)));
    let mut markers = Vec::new();
    for (field,texts) in &input.texts {
        for (index,text) in texts.iter().enumerate() {
            let mut result = String::new(); let mut cursor = 0;
            for patch in chosen.iter().filter(|p| p.field == *field && p.index == index) {
                result.push_str(&text[cursor..patch.start]); let start = result.len(); result.push_str(&patch.replacement); cursor = patch.end;
                for (decision,detector) in &patch.sources {
                    output.decisions[*decision].outcome = "prepared".into();
                    if patch.mask { markers.push(Marker { field:field.clone(),index,start,end:result.len(),detector:detector.clone() }); }
                }
                if result.len() > max_text { return Err("Transformed content exceeds the limit".into()); }
            }
            result.push_str(&text[cursor..]); output.texts.get_mut(field).ok_or("Output field unavailable")?[index] = result;
        }
    }
    output.transformed = output.texts != input.texts;
    if output.texts.values().flatten().map(String::len).sum::<usize>() > max_text { return Err("Transformed content exceeds the limit".into()); }
    if output.transformed {
        let final_input = Input { policy:input.policy.clone(),texts:output.texts.clone(),facts:input.facts.clone(),upload:input.upload };
        let mut final_env = Env { input:&final_input,markers:&markers,budget:8192,work:env.work,context_work:env.context_work };
        for rule in &ordered {
            if rule.mode != Mode::Active {continue;}
            let target=application_truth(&rule.application,&input.facts);
            let scope=final_env.expr(&rule.scope)?;
            let condition=final_env.expr(&rule.condition)?;
            if target==Truth::False||scope==Truth::False||condition==Truth::False{continue;}
            if matches!(rule.consequence,Effect::Warn) && (target==Truth::Unknown||scope==Truth::Unknown||condition==Truth::Unknown){
                output.action="block".into();output.reason="control_unavailable".into();output.texts=input.texts.clone();output.transformed=false;output.confirmation=false;
                output.decisions.push(Decision{rule_id:rule.id.clone(),rule_revision:rule.revision,rule_name:rule.name.clone(),mode:Mode::Active,consequence:"warn".into(),condition,scope:if target==Truth::Unknown{Truth::Unknown}else{scope},outcome:"unavailable".into(),occurrences:0});
                return Ok(output);
            }
            if matches!(rule.consequence,Effect::Warn) {
                if input.facts.get("channel").is_none_or(|channel|channel!="browser"){return Err("Confirmation is unavailable in this context".into());}
                output.confirmation=true;
                if !notices.contains(&rule.message){notices.push(rule.message.clone());}
                if !output.decisions.iter().any(|d|d.rule_id==rule.id){output.decisions.push(Decision{rule_id:rule.id.clone(),rule_revision:rule.revision,rule_name:rule.name.clone(),mode:Mode::Active,consequence:"warn".into(),condition:Truth::True,scope:Truth::True,outcome:"prepared".into(),occurrences:0});}
            }
            if matches!(rule.consequence,Effect::Block) || !patches(&mut final_env,rule,0)?.is_empty() {
                output.action = "block".into(); output.reason = "transformation_unsatisfied".into(); output.texts = input.texts.clone(); output.transformed = false;output.confirmation=false;
                if let Some(d) = output.decisions.iter_mut().find(|d| d.rule_id == rule.id) { d.outcome = "final_blocked".into(); }
                else { output.decisions.push(Decision { rule_id:rule.id.clone(),rule_revision:rule.revision,rule_name:rule.name.clone(),mode:Mode::Active,consequence:effect_name(&rule.consequence).into(),condition:Truth::True,scope:Truth::True,outcome:"final_blocked".into(),occurrences:0 }); }
                return Ok(output);
            }
        }
        output.action = if review { "review" } else { "transform" }.into();
    }
    if output.confirmation {output.action="review".into();output.reason=notices.join("\n\n");if output.reason.len()>MAX_TEXT{return Err("Confirmation messages exceed the limit".into());}}
    for decision in &mut output.decisions { if decision.outcome == "matched" { decision.outcome = if decision.consequence == "observe" { "observed" } else { "overridden" }.into(); } }
    Ok(output)
}

pub(crate) fn scope_allows_channel(policy:&Policy,scope:&Expr,channel:&str)->Result<bool,String>{
 let input=Input{policy:policy.clone(),texts:BTreeMap::new(),facts:BTreeMap::from([("channel".into(),channel.into())]),upload:None};
 let mut env=Env{input:&input,markers:&[],budget:8192,work:None,context_work:WorkBudget::new()};Ok(env.expr(scope)?!=Truth::False)
}
pub(crate) fn mask_label_matches(policy:&Policy,detector:&str,label:&str)->Result<bool,String>{
 let input=Input{policy:policy.clone(),texts:BTreeMap::from([("prompt".into(),vec![format!("[{label}]")])]),facts:BTreeMap::new(),upload:None};
 let mut env=Env{input:&input,markers:&[],budget:8192,work:None,context_work:WorkBudget::new()};let target=policy.detectors.iter().find(|item|item.id==detector).ok_or("Detector unavailable")?;
 Ok(env.matches("prompt",target)?.is_some_and(|matches|!matches.is_empty()))
}
