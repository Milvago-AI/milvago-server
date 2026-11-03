use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;

pub const VERSION: u32 = 1;
pub const MAX_INPUT: usize = 2 * 1024 * 1024;
pub const MAX_OUTPUT: usize = 2 * 1024 * 1024;
pub const MAX_FACTS: usize = 16_384;
pub const MAX_ENTITIES: usize = 16_384;
pub const MAX_SIGNATURES: usize = 1_024;
// Keep room for custom routes alongside the factory without expanding the request budget.
pub const MAX_HTTP_PATHS: usize = 32;

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum EntityKind {
    Host,
    Vm,
    Wsl,
    Runtime,
    Container,
    Process,
    Endpoint,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Entity {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub display: Option<EntityDisplay>,
    pub id: String,
    pub kind: EntityKind,
}

#[derive(Clone, Debug, Deserialize, Serialize, Default)]
#[serde(deny_unknown_fields)]
pub struct EntityDisplay {
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub name: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub address: Option<std::net::SocketAddr>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub image: Option<String>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Source {
    Installation,
    HostProcess,
    GuestProcess,
    ContainerProcess,
    ContainerMetadata,
    Http,
    HostFlow,
    HostDnsQuery,
    VmFlow,
    RuntimeFlow,
    ContainerFlow,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum Field {
    Package,
    Executable,
    ArgumentToken,
    ImageRepository,
    ImageDigest,
    ContainerName,
    Label,
    ContainerState,
    HttpStatus,
    HttpBody,
    HttpPath,
    HttpContentType,
    RemoteHost,
    RemotePort,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Fact {
    pub id: String,
    pub entity_id: String,
    pub source: Source,
    pub observed_at: i64,
    pub fields: BTreeMap<Field, Vec<String>>,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum RelationKind {
    Contains,
    OwnsEndpoint,
    PublishedEndpoint,
    ObservedOrigin,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Relation {
    pub from: String,
    pub to: String,
    pub kind: RelationKind,
    pub source: String,
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum CoverageStatus {
    Disabled,
    Available,
    Partial,
    Denied,
    Unavailable,
    Timeout,
    Saturated,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Coverage {
    pub scope: String,
    pub adapter: String,
    pub status: CoverageStatus,
    pub checked_at: i64,
    pub complete: bool,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Snapshot {
    pub version: u32,
    pub scope: String,
    pub sequence: u64,
    pub observed_at: i64,
    pub complete: bool,
    pub entities: Vec<Entity>,
    pub facts: Vec<Fact>,
    pub relations: Vec<Relation>,
    pub coverage: Vec<Coverage>,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
pub enum Expression {
    Eq { field: Field, value: String },
    In { field: Field, values: Vec<String> },
    Token { field: Field, value: String },
    Contains { field: Field, value: String },
    Regex { field: Field, value: String },
    All { args: Vec<Expression> },
    AllHttpResponses { args: Vec<Expression> },
    Any { args: Vec<Expression> },
    Not { arg: Box<Expression> },
}

#[derive(Clone, Copy, Debug, Deserialize, Serialize, PartialEq, Eq, PartialOrd, Ord)]
#[serde(rename_all = "snake_case")]
pub enum State {
    Indication,
    Installed,
    Executed,
    InterfaceRecognized,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Signature {
    pub id: String,
    pub application_id: String,
    pub name: String,
    pub revision: u32,
    pub sources: Vec<Source>,
    pub state: State,
    pub condition: Expression,
    pub provenance: String,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Catalog {
    #[serde(default = "default_http_paths")]
    pub http_paths: Vec<String>,
    #[serde(default = "default_http_ports")]
    pub http_ports: Vec<u16>,
    pub version: u32,
    pub revision: u64,
    pub signatures: Vec<Signature>,
    #[serde(default = "default_providers")]
    pub providers: Vec<Provider>,
}
pub fn default_http_paths() -> Vec<String> {
    vec!["/".into()]
}

pub fn valid_http_path(path: &str) -> bool {
    path.starts_with('/')
        && path.len() <= 256
        && !path.contains("//")
        && path
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"/._-~".contains(&byte))
        && !path.split('/').any(|segment| matches!(segment, "." | ".."))
}
pub fn default_http_ports() -> Vec<u16> {
    vec![11434, 18789]
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Provider {
    pub id: String,
    pub hosts: Vec<String>,
}
pub fn default_providers() -> Vec<Provider> {
    [
        ("openai", "api.openai.com"),
        ("anthropic", "api.anthropic.com"),
        ("google", "generativelanguage.googleapis.com"),
        ("mistral", "api.mistral.ai"),
    ]
    .into_iter()
    .map(|(id, host)| Provider {
        id: id.into(),
        hosts: vec![host.into()],
    })
    .collect()
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Evidence {
    pub fact_id: String,
    pub source: Source,
    pub observed_at: i64,
    pub fields: Vec<Field>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Identification {
    pub application_id: String,
    pub signature_id: String,
    pub entity_id: String,
    pub signature_revision: u32,
    pub state: State,
    pub evidence: Vec<Evidence>,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct Communication {
    pub entity_id: String,
    pub provider: String,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Deserialize, Serialize, PartialEq, Eq)]
#[serde(deny_unknown_fields)]
pub struct DomainQuery {
    pub entity_id: String,
    pub provider: String,
    pub evidence: Evidence,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Evaluation {
    #[serde(default, skip_serializing_if = "is_false")]
    pub saturated: bool,
    pub identifications: Vec<Identification>,
    pub communications: Vec<Communication>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub queries: Vec<DomainQuery>,
    pub evaluated_facts: usize,
    pub unknown_conditions: usize,
}

#[derive(Clone, Debug, Deserialize, Serialize)]
#[serde(deny_unknown_fields)]
pub struct Report {
    pub version: u32,
    pub catalog_revision: u64,
    pub settings_revision: u64,
    pub run_id: Option<String>,
    pub scope: String,
    pub sequence: u64,
    pub page: u16,
    pub pages: u16,
    pub observed_at: i64,
    pub complete: bool,
    pub entities: Vec<Entity>,
    pub relations: Vec<Relation>,
    pub coverage: Vec<Coverage>,
    pub result: Evaluation,
}

pub fn identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 160
        && value
            .bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"-_.:/".contains(&b))
}

fn is_false(value: &bool) -> bool {
    !*value
}
