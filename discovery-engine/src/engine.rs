use crate::model::*;
use regex::{Regex, RegexBuilder};
use std::collections::{BTreeMap, BTreeSet};

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Truth {
    False,
    Unknown,
    True,
}

impl Truth {
    pub fn negate(self) -> Self {
        match self {
            Self::True => Self::False,
            Self::False => Self::True,
            Self::Unknown => self,
        }
    }
    pub fn all(values: impl Iterator<Item = Self>) -> Self {
        let mut result = Self::True;
        for value in values {
            if value == Self::False {
                return value;
            }
            if value == Self::Unknown {
                result = value;
            }
        }
        result
    }
    pub fn any(values: impl Iterator<Item = Self>) -> Self {
        let mut result = Self::False;
        for value in values {
            if value == Self::True {
                return value;
            }
            if value == Self::Unknown {
                result = value;
            }
        }
        result
    }
}

struct HttpRequirement {
    path: String,
    condition: CompiledExpression,
    fields: Vec<Field>,
}

enum CompiledExpression {
    Eq(Field, String),
    In(Field, Vec<String>),
    Token(Field, String),
    Contains(Field, String),
    Regex(Field, Regex),
    All(Vec<Self>),
    HttpAll(Vec<HttpRequirement>),
    Any(Vec<Self>),
    Not(Box<Self>),
}

fn literal(value: &str) -> Result<(), String> {
    if value.is_empty() || value.len() > 512 || value.chars().any(char::is_control) {
        return Err("Invalid signature literal".into());
    }
    Ok(())
}

impl CompiledExpression {
    fn compile(expression: &Expression, depth: usize, nodes: &mut usize) -> Result<Self, String> {
        *nodes += 1;
        if depth > 12 || *nodes > 128 {
            return Err("Signature condition exceeds its limits".into());
        }
        Ok(match expression {
            Expression::Eq { field, value } => {
                literal(value)?;
                Self::Eq(*field, value.clone())
            }
            Expression::In { field, values } => {
                if values.is_empty() || values.len() > 64 {
                    return Err("Invalid membership values".into());
                }
                for value in values {
                    literal(value)?;
                }
                Self::In(*field, values.clone())
            }
            Expression::Token { field, value } => {
                literal(value)?;
                if value
                    .chars()
                    .any(|c| !c.is_alphanumeric() && c != '_' && c != '-')
                {
                    return Err("Invalid token".into());
                }
                Self::Token(*field, value.clone())
            }
            Expression::Contains { field, value } => {
                literal(value)?;
                Self::Contains(*field, value.clone())
            }
            Expression::Regex { field, value } => {
                literal(value)?;
                let regex = RegexBuilder::new(value)
                    .size_limit(64 * 1024)
                    .dfa_size_limit(64 * 1024)
                    .nest_limit(16)
                    .build()
                    .map_err(|_| "Invalid or excessive regular expression")?;
                Self::Regex(*field, regex)
            }
            Expression::All { args } | Expression::Any { args } => {
                if args.is_empty() || args.len() > 32 {
                    return Err("Invalid condition group".into());
                }
                let compiled = args
                    .iter()
                    .map(|arg| Self::compile(arg, depth + 1, nodes))
                    .collect::<Result<Vec<_>, _>>()?;
                if matches!(expression, Expression::All { .. }) {
                    Self::All(compiled)
                } else {
                    Self::Any(compiled)
                }
            }
            Expression::AllHttpResponses { args } => {
                if depth != 0 || !(2..=8).contains(&args.len()) {
                    return Err(
                        "HTTP response groups must be a root condition with 2 to 8 responses"
                            .into(),
                    );
                }
                let mut paths = BTreeSet::new();
                let mut requirements = vec![];
                for expression in args {
                    let Expression::All { args: predicates } = expression else {
                        return Err("Each HTTP response must be an all condition".into());
                    };
                    let selected: Vec<_> = predicates
                        .iter()
                        .filter_map(|predicate| {
                            if let Expression::Eq {
                                field: Field::HttpPath,
                                value,
                            } = predicate
                            {
                                Some(value)
                            } else {
                                None
                            }
                        })
                        .collect();
                    if selected.len() != 1
                        || !valid_http_path(selected[0])
                        || !paths.insert(selected[0].clone())
                    {
                        return Err("Each HTTP response needs a distinct literal path".into());
                    }
                    let condition = Self::compile(expression, depth + 1, nodes)?;
                    let mut fields = BTreeSet::new();
                    condition.fields(&mut fields);
                    requirements.push(HttpRequirement {
                        path: selected[0].clone(),
                        condition,
                        fields: fields.into_iter().collect(),
                    });
                }
                Self::HttpAll(requirements)
            }
            Expression::Not { arg } => Self::Not(Box::new(Self::compile(arg, depth + 1, nodes)?)),
        })
    }

    fn evaluate(&self, fact: &Fact) -> Truth {
        let check = |field: &Field, predicate: &dyn Fn(&str) -> bool| match fact.fields.get(field) {
            None => Truth::Unknown,
            Some(values) => {
                if values.iter().any(|v| predicate(v)) {
                    Truth::True
                } else {
                    Truth::False
                }
            }
        };
        match self {
            Self::Eq(field, expected) => check(field, &|v| v == expected),
            Self::In(field, expected) => check(field, &|v| expected.iter().any(|e| e == v)),
            Self::Contains(field, expected) => check(field, &|v| v.contains(expected)),
            Self::Regex(field, regex) => check(field, &|v| regex.is_match(v)),
            Self::Token(field, expected) => check(field, &|v| {
                v.split(|c: char| !c.is_alphanumeric() && c != '_' && c != '-')
                    .any(|t| t == expected)
            }),
            Self::All(args) => Truth::all(args.iter().map(|arg| arg.evaluate(fact))),
            Self::Any(args) => Truth::any(args.iter().map(|arg| arg.evaluate(fact))),
            Self::Not(arg) => arg.evaluate(fact).negate(),
            Self::HttpAll(_) => Truth::Unknown,
        }
    }

    fn fields(&self, output: &mut BTreeSet<Field>) {
        match self {
            Self::Eq(f, _)
            | Self::In(f, _)
            | Self::Token(f, _)
            | Self::Contains(f, _)
            | Self::Regex(f, _) => {
                output.insert(*f);
            }
            Self::All(args) | Self::Any(args) => {
                for arg in args {
                    arg.fields(output);
                }
            }
            Self::Not(arg) => arg.fields(output),
            Self::HttpAll(args) => {
                for arg in args {
                    arg.condition.fields(output);
                }
            }
        }
    }
}

struct CompiledSignature {
    signature: Signature,
    condition: CompiledExpression,
    fields: Vec<Field>,
    cost: usize,
}

pub struct Engine {
    providers: BTreeMap<String, String>,
    provider_ids: BTreeSet<String>,
    signatures: Vec<CompiledSignature>,
    http_signatures: Vec<usize>,
    by_source: BTreeMap<Source, Vec<usize>>,
    by_value: BTreeMap<(Source, Field, String), Vec<usize>>,
    indexed_fields: BTreeSet<(Source, Field)>,
    by_missing: BTreeMap<(Source, Field), Vec<usize>>,
}

fn anchor(expression: &Expression) -> Option<(Field, Vec<String>)> {
    match expression {
        Expression::Eq { field, value } => Some((*field, vec![value.clone()])),
        Expression::In { field, values } => Some((*field, values.clone())),
        Expression::All { args } => args.iter().find_map(anchor),
        _ => None,
    }
}
fn literal_bytes(expression: &Expression) -> usize {
    match expression {
        Expression::Eq { value, .. }
        | Expression::Token { value, .. }
        | Expression::Contains { value, .. }
        | Expression::Regex { value, .. } => value.len(),
        Expression::In { values, .. } => values.iter().map(String::len).sum(),
        Expression::All { args }
        | Expression::Any { args }
        | Expression::AllHttpResponses { args } => args.iter().map(literal_bytes).sum(),
        Expression::Not { arg } => literal_bytes(arg),
    }
}

fn source_field(source: Source, field: Field) -> bool {
    match source {
        Source::Installation => matches!(field, Field::Package | Field::Executable),
        Source::HostDnsQuery => field == Field::RemoteHost,
        Source::HostProcess | Source::GuestProcess | Source::ContainerProcess => {
            matches!(field, Field::Executable | Field::ArgumentToken)
        }
        Source::ContainerMetadata => matches!(
            field,
            Field::ImageRepository
                | Field::ImageDigest
                | Field::ContainerName
                | Field::Label
                | Field::ContainerState
        ),
        Source::Http => matches!(
            field,
            Field::HttpStatus | Field::HttpBody | Field::HttpPath | Field::HttpContentType
        ),
        Source::HostFlow | Source::VmFlow | Source::RuntimeFlow | Source::ContainerFlow => {
            matches!(field, Field::RemoteHost | Field::RemotePort)
        }
    }
}

fn state_allowed(source: Source, state: State) -> bool {
    match source {
        Source::Installation => matches!(state, State::Indication | State::Installed),
        Source::HostProcess | Source::GuestProcess | Source::ContainerProcess => {
            matches!(state, State::Indication | State::Executed)
        }
        Source::ContainerMetadata => state == State::Indication,
        Source::Http => matches!(state, State::Indication | State::InterfaceRecognized),
        // A destination identifies a provider, never the application which
        // generated the connection. Provider definitions have their own model.
        _ => false,
    }
}

fn planned_http_routes(expression: &Expression, paths: &[String]) -> bool {
    match expression {
        Expression::Eq {
            field: Field::HttpPath,
            value,
        } => paths.contains(value),
        Expression::In {
            field: Field::HttpPath,
            values,
        } => values.iter().all(|value| paths.contains(value)),
        Expression::All { args }
        | Expression::Any { args }
        | Expression::AllHttpResponses { args } => {
            args.iter().all(|arg| planned_http_routes(arg, paths))
        }
        Expression::Not { arg } => planned_http_routes(arg, paths),
        _ => true,
    }
}

impl Engine {
    pub fn compile(catalog: &Catalog) -> Result<Self, String> {
        let mut paths = BTreeSet::new();
        if catalog.http_paths.is_empty()
            || catalog.http_paths.len() > MAX_HTTP_PATHS
            || catalog
                .http_paths
                .iter()
                .any(|path| !valid_http_path(path) || !paths.insert(path))
        {
            return Err("Invalid discovery HTTP probe paths".into());
        }
        let mut ports = BTreeSet::new();
        if catalog.http_ports.len() > 64
            || catalog
                .http_ports
                .iter()
                .any(|port| *port == 0 || !ports.insert(*port))
        {
            return Err("Invalid discovery HTTP candidate ports".into());
        }
        if catalog.version != VERSION
            || catalog.revision == 0
            || catalog.signatures.len() > MAX_SIGNATURES
        {
            return Err("Unsupported or excessive discovery catalog".into());
        }
        let mut signatures = Vec::new();
        let mut http_signatures = Vec::new();
        if catalog.providers.len() > 64 {
            return Err("Too many discovery providers".into());
        }
        let mut providers = BTreeMap::new();
        let mut provider_ids = BTreeSet::new();
        for provider in &catalog.providers {
            if provider.id.is_empty()
                || provider.id.len() > 64
                || !provider
                    .id
                    .bytes()
                    .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b"_-".contains(&b))
                || !provider_ids.insert(provider.id.clone())
                || provider.hosts.is_empty()
                || provider.hosts.len() > 32
            {
                return Err("Invalid discovery provider".into());
            }
            for host in &provider.hosts {
                if host.len() > 253
                    || !host.contains('.')
                    || host.parse::<std::net::IpAddr>().is_ok()
                    || host.split('.').any(|part| {
                        part.is_empty()
                            || part.len() > 63
                            || part.starts_with('-')
                            || part.ends_with('-')
                            || !part
                                .bytes()
                                .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
                    })
                    || providers
                        .insert(host.clone(), provider.id.clone())
                        .is_some()
                    || providers.len() > 1024
                {
                    return Err("Invalid or ambiguous discovery provider hostname".into());
                }
            }
        }
        let mut ids = BTreeSet::new();
        let mut by_source: BTreeMap<Source, Vec<usize>> = BTreeMap::new();
        let mut by_value: BTreeMap<(Source, Field, String), Vec<usize>> = BTreeMap::new();
        let mut indexed_fields = BTreeSet::new();
        let mut by_missing: BTreeMap<(Source, Field), Vec<usize>> = BTreeMap::new();
        let mut total_nodes = 0;
        let mut regexes = 0;
        let mut bytes = 0;
        for signature in &catalog.signatures {
            if !identifier(&signature.id)
                || !identifier(&signature.application_id)
                || !ids.insert(signature.id.clone())
                || signature.revision == 0
                || signature.name.is_empty()
                || signature.name.len() > 120
                || signature.name.chars().any(char::is_control)
                || signature.provenance.is_empty()
                || signature.provenance.len() > 256
                || signature.sources.is_empty()
                || signature.sources.len() > 4
            {
                return Err("Invalid discovery signature metadata".into());
            }
            let mut nodes = 0;
            let condition = CompiledExpression::compile(&signature.condition, 0, &mut nodes)?;
            if !planned_http_routes(&signature.condition, &catalog.http_paths) {
                return Err("Signature HTTP path is missing from http_paths".into());
            }
            bytes += literal_bytes(&signature.condition);
            if bytes > 512 * 1024 {
                return Err("Discovery literal budget exceeded".into());
            }
            fn count_regex(expression: &Expression) -> usize {
                match expression {
                    Expression::Regex { .. } => 1,
                    Expression::All { args }
                    | Expression::Any { args }
                    | Expression::AllHttpResponses { args } => args.iter().map(count_regex).sum(),
                    Expression::Not { arg } => count_regex(arg),
                    _ => 0,
                }
            }
            regexes += count_regex(&signature.condition);
            if regexes > 64 {
                return Err("Discovery regex budget exceeded".into());
            }
            total_nodes += nodes;
            if total_nodes > 8_192 {
                return Err("Discovery catalog complexity exceeds its limit".into());
            }
            let mut fields = BTreeSet::new();
            condition.fields(&mut fields);
            let unique: BTreeSet<_> = signature.sources.iter().copied().collect();
            if unique.len() != signature.sources.len() {
                return Err("Duplicate signature source".into());
            }
            let correlated = matches!(&condition, CompiledExpression::HttpAll(_));
            if correlated {
                if signature.sources != vec![Source::Http] {
                    return Err("HTTP response groups require only the HTTP source".into());
                }
                http_signatures.push(signatures.len());
            }
            for source in &signature.sources {
                if !state_allowed(*source, signature.state)
                    || fields.iter().any(|f| !source_field(*source, *f))
                {
                    return Err("Signature exceeds source capabilities".into());
                }
                if correlated {
                    continue;
                }
                if let Some((field, values)) = anchor(&signature.condition) {
                    indexed_fields.insert((*source, field));
                    by_missing
                        .entry((*source, field))
                        .or_default()
                        .push(signatures.len());
                    for value in values {
                        by_value
                            .entry((*source, field, value))
                            .or_default()
                            .push(signatures.len());
                    }
                } else {
                    by_source.entry(*source).or_default().push(signatures.len());
                }
            }
            signatures.push(CompiledSignature {
                signature: signature.clone(),
                condition,
                fields: fields.into_iter().collect(),
                cost: nodes,
            });
        }
        Ok(Self {
            providers,
            provider_ids,
            signatures,
            http_signatures,
            by_source,
            by_value,
            indexed_fields,
            by_missing,
        })
    }

    pub fn evaluate(&self, snapshot: &Snapshot) -> Result<Evaluation, String> {
        self.evaluate_with_cancel(snapshot, || false)
    }

    pub fn evaluate_with_cancel(
        &self,
        snapshot: &Snapshot,
        cancelled: impl Fn() -> bool,
    ) -> Result<Evaluation, String> {
        validate_snapshot(snapshot)?;
        let mut output = Evaluation {
            identifications: Vec::new(),
            communications: Vec::new(),
            queries: Vec::new(),
            evaluated_facts: 0,
            unknown_conditions: 0,
            saturated: false,
        };
        let mut work = 0usize;
        let mut identified: BTreeMap<(&str, usize), usize> = BTreeMap::new();
        let mut contacted = BTreeSet::new();
        let mut queried = BTreeSet::new();
        for fact in &snapshot.facts {
            if cancelled() {
                return Err("Discovery evaluation cancelled".into());
            }
            output.evaluated_facts += 1;
            let mut candidates: BTreeSet<usize> = self
                .by_source
                .get(&fact.source)
                .into_iter()
                .flatten()
                .copied()
                .collect();
            for ((source, field), indexes) in &self.by_missing {
                if *source == fact.source && !fact.fields.contains_key(field) {
                    candidates.extend(indexes);
                }
            }
            for (field, values) in &fact.fields {
                if !self.indexed_fields.contains(&(fact.source, *field)) {
                    continue;
                }
                for value in values {
                    if let Some(indexes) = self.by_value.get(&(fact.source, *field, value.clone()))
                    {
                        candidates.extend(indexes);
                    }
                }
            }
            {
                for index in candidates {
                    let signature = &self.signatures[index];
                    work += signature.cost;
                    if work > 1_000_000 {
                        return Err("Discovery evaluation exceeds its work budget".into());
                    }
                    match signature.condition.evaluate(fact) {
                        Truth::True => {
                            let evidence = Evidence {
                                fact_id: fact.id.clone(),
                                source: fact.source,
                                observed_at: fact.observed_at,
                                fields: signature
                                    .fields
                                    .iter()
                                    .filter(|f| fact.fields.contains_key(f))
                                    .copied()
                                    .collect(),
                            };
                            if let Some(position) =
                                identified.get(&(fact.entity_id.as_str(), index))
                            {
                                if output.identifications[*position].evidence.len() < 8 {
                                    output.identifications[*position].evidence.push(evidence);
                                }
                                continue;
                            }
                            if output.identifications.len() >= 4096 {
                                output.saturated = true;
                                return Ok(output);
                            }
                            identified.insert(
                                (fact.entity_id.as_str(), index),
                                output.identifications.len(),
                            );
                            output.identifications.push(Identification {
                                application_id: signature.signature.application_id.clone(),
                                signature_id: signature.signature.id.clone(),
                                entity_id: fact.entity_id.clone(),
                                signature_revision: signature.signature.revision,
                                state: signature.signature.state,
                                evidence: vec![evidence],
                            });
                        }
                        Truth::Unknown => output.unknown_conditions += 1,
                        Truth::False => (),
                    }
                }
            }
            if matches!(
                fact.source,
                Source::HostFlow
                    | Source::VmFlow
                    | Source::RuntimeFlow
                    | Source::ContainerFlow
                    | Source::HostDnsQuery
            ) {
                if let Some(hosts) = fact.fields.get(&Field::RemoteHost) {
                    for host in hosts {
                        let normalized =
                            host.strip_suffix('.').unwrap_or(host).to_ascii_lowercase();
                        if let Some(provider) = self.providers.get(&normalized).map(String::as_str)
                        {
                            if fact.source == Source::HostDnsQuery {
                                if !queried.insert((fact.entity_id.as_str(), provider)) {
                                    continue;
                                }
                                if output.queries.len() >= 4096 {
                                    output.saturated = true;
                                    return Ok(output);
                                }
                                output.queries.push(DomainQuery {
                                    entity_id: fact.entity_id.clone(),
                                    provider: provider.into(),
                                    evidence: Evidence {
                                        fact_id: fact.id.clone(),
                                        source: fact.source,
                                        observed_at: fact.observed_at,
                                        fields: vec![Field::RemoteHost],
                                    },
                                });
                                continue;
                            }
                            if !contacted.insert((fact.entity_id.as_str(), provider)) {
                                continue;
                            }
                            if output.communications.len() >= 4096 {
                                output.saturated = true;
                                return Ok(output);
                            }
                            output.communications.push(Communication {
                                entity_id: fact.entity_id.clone(),
                                provider: provider.into(),
                                evidence: Evidence {
                                    fact_id: fact.id.clone(),
                                    source: fact.source,
                                    observed_at: fact.observed_at,
                                    fields: vec![Field::RemoteHost],
                                },
                            });
                        }
                    }
                }
            }
        }
        if !self.http_signatures.is_empty() {
            let mut responses: BTreeMap<&str, BTreeMap<&str, Vec<&Fact>>> = BTreeMap::new();
            for fact in &snapshot.facts {
                if cancelled() {
                    return Err("Discovery evaluation cancelled".into());
                }
                if fact.source != Source::Http
                    || snapshot.observed_at.saturating_sub(fact.observed_at) > 60
                {
                    continue;
                }
                let Some(paths) = fact
                    .fields
                    .get(&Field::HttpPath)
                    .filter(|values| values.len() == 1)
                else {
                    continue;
                };
                let Some(status) = fact
                    .fields
                    .get(&Field::HttpStatus)
                    .filter(|values| values.len() == 1)
                else {
                    continue;
                };
                if !status[0]
                    .parse::<u16>()
                    .is_ok_and(|value| (100..=599).contains(&value))
                    || fact
                        .fields
                        .get(&Field::HttpBody)
                        .is_none_or(|values| values.len() != 1)
                    || fact
                        .fields
                        .get(&Field::HttpContentType)
                        .is_some_and(|values| values.len() != 1)
                {
                    continue;
                }
                responses
                    .entry(&fact.entity_id)
                    .or_default()
                    .entry(&paths[0])
                    .or_default()
                    .push(fact);
            }
            for (entity, paths) in responses {
                for index in &self.http_signatures {
                    if cancelled() {
                        return Err("Discovery evaluation cancelled".into());
                    }
                    work = work.saturating_add(1);
                    if work > 1_000_000 {
                        return Err("Discovery evaluation exceeds its work budget".into());
                    }
                    let signature = &self.signatures[*index];
                    let CompiledExpression::HttpAll(requirements) = &signature.condition else {
                        continue;
                    };
                    let mut evidence = vec![];
                    let mut truth = Truth::True;
                    for requirement in requirements {
                        let Some(facts) = paths.get(requirement.path.as_str()) else {
                            truth = Truth::Unknown;
                            break;
                        };
                        let mut found = None;
                        let mut unknown = false;
                        for fact in facts {
                            if cancelled() {
                                return Err("Discovery evaluation cancelled".into());
                            }
                            work = work.saturating_add(signature.cost);
                            if work > 1_000_000 {
                                return Err("Discovery evaluation exceeds its work budget".into());
                            }
                            match requirement.condition.evaluate(fact) {
                                Truth::True => {
                                    found = Some(*fact);
                                    break;
                                }
                                Truth::Unknown => unknown = true,
                                Truth::False => (),
                            }
                        }
                        let Some(fact) = found else {
                            truth = if unknown {
                                Truth::Unknown
                            } else {
                                Truth::False
                            };
                            break;
                        };
                        evidence.push(Evidence {
                            fact_id: fact.id.clone(),
                            source: Source::Http,
                            observed_at: fact.observed_at,
                            fields: requirement
                                .fields
                                .iter()
                                .filter(|field| fact.fields.contains_key(field))
                                .copied()
                                .collect(),
                        });
                    }
                    match truth {
                        Truth::Unknown => output.unknown_conditions += 1,
                        Truth::False => (),
                        Truth::True => {
                            if output.identifications.len() >= 4096 {
                                output.saturated = true;
                                return Ok(output);
                            }
                            output.identifications.push(Identification {
                                application_id: signature.signature.application_id.clone(),
                                signature_id: signature.signature.id.clone(),
                                signature_revision: signature.signature.revision,
                                entity_id: entity.into(),
                                state: signature.signature.state,
                                evidence,
                            });
                        }
                    }
                }
            }
        }
        Ok(output)
    }

    pub(crate) fn has_provider(&self, id: &str) -> bool {
        self.provider_ids.contains(id)
    }
}

pub fn provider(host: &str) -> Option<&'static str> {
    if host.len() > 253 || !host.is_ascii() {
        return None;
    }
    let host = host.strip_suffix('.').unwrap_or(host);
    if host.eq_ignore_ascii_case("api.openai.com") {
        Some("openai")
    } else if host.eq_ignore_ascii_case("api.anthropic.com") {
        Some("anthropic")
    } else if host.eq_ignore_ascii_case("generativelanguage.googleapis.com") {
        Some("google")
    } else if host.eq_ignore_ascii_case("api.mistral.ai") {
        Some("mistral")
    } else {
        None
    }
}

pub fn validate_snapshot(snapshot: &Snapshot) -> Result<(), String> {
    if snapshot.version != VERSION
        || !identifier(&snapshot.scope)
        || snapshot.sequence == 0
        || snapshot.observed_at < 0
        || snapshot.entities.len() > MAX_ENTITIES
        || snapshot.facts.len() > MAX_FACTS
        || snapshot.relations.len() > MAX_ENTITIES
        || snapshot.coverage.len() > 256
    {
        return Err("Invalid discovery snapshot limits".into());
    }
    let mut entities = BTreeMap::new();
    for entity in &snapshot.entities {
        if !identifier(&entity.id) || entities.insert(entity.id.as_str(), entity.kind).is_some() {
            return Err("Invalid or duplicate discovery entity".into());
        }
        if let Some(display) = &entity.display {
            let text = |value: &Option<String>, limit: usize| {
                value.as_ref().is_none_or(|s| {
                    !s.is_empty() && s.len() <= limit && !s.chars().any(char::is_control)
                })
            };
            if !text(&display.name, 160)
                || !text(&display.image, 512)
                || display.image.is_some() && entity.kind != EntityKind::Container
                || display.address.is_some_and(|address| {
                    entity.kind != EntityKind::Endpoint
                        || address.port() == 0
                        || address.ip().is_unspecified()
                        || address.ip().is_multicast()
                })
            {
                return Err("Invalid discovery display metadata".into());
            }
        }
    }
    let mut ids = BTreeSet::new();
    let mut bytes = 0usize;
    for fact in &snapshot.facts {
        let kind = entities
            .get(fact.entity_id.as_str())
            .ok_or("Unknown discovery entity")?;
        let valid_kind = match fact.source {
            Source::HostProcess | Source::GuestProcess | Source::ContainerProcess => {
                *kind == EntityKind::Process
            }
            Source::ContainerMetadata => *kind == EntityKind::Container,
            Source::Http => *kind == EntityKind::Endpoint,
            Source::VmFlow => matches!(kind, EntityKind::Vm | EntityKind::Wsl),
            Source::RuntimeFlow => *kind == EntityKind::Runtime,
            Source::ContainerFlow => *kind == EntityKind::Container,
            Source::HostFlow => matches!(kind, EntityKind::Host | EntityKind::Process),
            Source::Installation | Source::HostDnsQuery => *kind == EntityKind::Host,
        };
        if !valid_kind
            || !identifier(&fact.id)
            || !ids.insert(fact.id.as_str())
            || fact.observed_at < 0
            || fact.observed_at > snapshot.observed_at
            || fact.source == Source::HostDnsQuery
                && snapshot.observed_at.saturating_sub(fact.observed_at) > 3600
            || fact.fields.len() > 8
        {
            return Err("Invalid discovery fact".into());
        }
        for (field, values) in &fact.fields {
            if !source_field(fact.source, *field) || values.len() > 64 {
                return Err("Unsupported discovery field".into());
            }
            for value in values {
                let limit = if *field == Field::HttpBody {
                    65_536
                } else {
                    1024
                };
                bytes = bytes.saturating_add(value.len());
                if value.len() > limit || bytes > MAX_INPUT {
                    return Err("Discovery fields exceed their limits".into());
                }
            }
        }
    }
    let mut relations = BTreeSet::new();
    for relation in &snapshot.relations {
        if relation.from == relation.to
            || !entities.contains_key(relation.from.as_str())
            || !entities.contains_key(relation.to.as_str())
            || !identifier(&relation.source)
            || !relations.insert((
                relation.from.as_str(),
                relation.to.as_str(),
                format!("{:?}", relation.kind),
            ))
        {
            return Err("Invalid discovery relationship".into());
        }
        let from = entities[relation.from.as_str()];
        let to = entities[relation.to.as_str()];
        let valid = match relation.kind {
            RelationKind::Contains => match from {
                EntityKind::Host => matches!(
                    to,
                    EntityKind::Vm | EntityKind::Wsl | EntityKind::Runtime | EntityKind::Process
                ),
                EntityKind::Vm | EntityKind::Wsl => matches!(
                    to,
                    EntityKind::Vm | EntityKind::Runtime | EntityKind::Process
                ),
                EntityKind::Runtime => to == EntityKind::Container,
                EntityKind::Container => matches!(
                    to,
                    EntityKind::Process | EntityKind::Runtime | EntityKind::Vm
                ),
                EntityKind::Process => to == EntityKind::Process,
                EntityKind::Endpoint => false,
            },
            RelationKind::OwnsEndpoint
            | RelationKind::PublishedEndpoint
            | RelationKind::ObservedOrigin => {
                from != EntityKind::Endpoint && to == EntityKind::Endpoint
            }
        };
        if !valid {
            return Err("Invalid discovery relationship kinds".into());
        }
    }
    // Cycles in containment would make the UI and attribution graph ambiguous.
    let mut parents: BTreeMap<&str, &str> = BTreeMap::new();
    for relation in snapshot
        .relations
        .iter()
        .filter(|r| r.kind == RelationKind::Contains)
    {
        if parents.insert(&relation.to, &relation.from).is_some() {
            return Err("Multiple discovery containment parents".into());
        }
    }
    for child in parents.keys() {
        let mut current = *child;
        for depth in 0..=32 {
            match parents.get(current) {
                None => break,
                Some(parent) => {
                    if depth == 32 {
                        return Err("Cyclic or excessive discovery containment".into());
                    }
                    current = parent;
                }
            }
        }
    }
    let mut coverage_ids = BTreeSet::new();
    for coverage in &snapshot.coverage {
        if !identifier(&coverage.scope)
            || !coverage_ids.insert((&coverage.scope, &coverage.adapter))
            || !identifier(&coverage.adapter)
            || coverage.checked_at < 0
            || coverage.checked_at > snapshot.observed_at
            || (coverage.complete && coverage.status != CoverageStatus::Available)
        {
            return Err("Invalid discovery coverage".into());
        }
    }
    if snapshot.complete
        && snapshot
            .coverage
            .iter()
            .any(|c| c.status != CoverageStatus::Disabled && !c.complete)
    {
        return Err("Partial discovery coverage cannot finalize a complete snapshot".into());
    }
    Ok(())
}
