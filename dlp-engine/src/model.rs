use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const MAX_TEXT: usize = 32768;
/// Opt-in Rust API for a complete structured unit; the JSON/WASM API keeps MAX_TEXT.
pub const MAX_LARGE_UNIT_TEXT: usize = 262144;
pub const MAX_LARGE_UNIT_VALUES: usize = 2048;
pub const MAX_POLICY: usize = 131072;
pub const MAX_RULES: usize = 128;
pub const MAX_DETECTORS: usize = 256;
pub const MAX_NODES: usize = 256;
pub const MAX_DEPTH: usize = 16;
pub const MAX_MATCHES: usize = 2048;

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Domain { Endpoint }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Mode { Disabled, Simulation, Active }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Truth { True, False, Unknown }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expr {
    All { children: Vec<Expr> },
    Any { children: Vec<Expr> },
    One { children: Vec<Expr> },
    Not { child: Box<Expr> },
    True,
    Contains { field: String, value: String, ignore_case: bool, whole_word: bool },
    Matches { field: String, detector: String, minimum: usize },
    Upload,
    Eq { field: String, value: String },
    In { field: String, values: Vec<String> },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "kind", rename_all = "snake_case", deny_unknown_fields)]
pub enum DetectorKind {
    Literal { value: String, ignore_case: bool, whole_word: bool, unicode: bool },
    Regex { pattern: String, ignore_case: bool },
    Builtin { category: String },
    Keyword { value: String, tier: String, exceptions: Vec<String> },
    Dictionary { values: Vec<String>, exceptions: Vec<String> },
    KeywordTier { dictionary: String, tier: String },
    DictionaryContext { dictionary: String, minimum: usize },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Detector {
    pub id: String,
    pub name: String,
    pub definition: DetectorKind,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag = "action", rename_all = "snake_case", deny_unknown_fields)]
pub enum Effect {
    Observe,
    Warn,
    Block,
    Mask { detector: String, label: String },
    Replace { value: String, replacement: String, ignore_case: bool, whole_word: bool },
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(tag="kind",rename_all="snake_case",deny_unknown_fields)]
pub enum Application { Organization, Group { id:String }, Device { id:String }, Groups { ids:Vec<String> }, Devices { ids:Vec<String> } }

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Rule {
    #[serde(default, skip_serializing_if="Option::is_none")]
    pub application: Option<Application>,
    pub id: String,
    pub revision: u64,
    pub name: String,
    pub mode: Mode,
    pub priority: u16,
    pub condition: Expr,
    pub scope: Expr,
    pub consequence: Effect,
    pub review: bool,
    pub message: String,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Policy {
    pub schema_version: u32,
    pub domain: Domain,
    pub inspection: bool,
    #[serde(default)]
    pub native_inspection: bool,
    pub journal: bool,
    pub detectors: Vec<Detector>,
    pub rules: Vec<Rule>,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Input {
    pub policy: Policy,
    pub texts: BTreeMap<String, Vec<String>>,
    pub facts: BTreeMap<String, String>,
    pub upload: Option<bool>,
}

#[derive(Clone, Debug, Serialize, Deserialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Decision {
    pub rule_id: String,
    pub rule_revision: u64,
    pub rule_name: String,
    pub mode: Mode,
    pub consequence: String,
    pub condition: Truth,
    pub scope: Truth,
    pub outcome: String,
    pub occurrences: usize,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Output {
    pub action: String,
    pub texts: BTreeMap<String, Vec<String>>,
    pub decisions: Vec<Decision>,
    pub reason: String,
    pub transformed: bool,
    pub confirmation: bool,
}
