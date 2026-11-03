use crate::*;
use std::collections::{BTreeMap, BTreeSet};

pub fn validate(report: &Report, catalog: &Catalog) -> Result<(), String> {
    let engine = Engine::compile(catalog)?;
    if report.version != VERSION
        || report.catalog_revision != catalog.revision
        || report.page >= report.pages
        || report.pages == 0
        || report.pages > 256
        || report.entities.len() > 256
        || report.relations.len() > 512
        || report.coverage.len() > 16
        || report.result.identifications.len() > 100
        || report.result.communications.len() > 100
        || report.result.queries.len() > 100
    {
        return Err("Invalid discovery report limits".into());
    }
    let snapshot = Snapshot {
        version: report.version,
        scope: report.scope.clone(),
        sequence: report.sequence,
        observed_at: report.observed_at,
        complete: report.complete,
        entities: report.entities.clone(),
        relations: report.relations.clone(),
        coverage: report.coverage.clone(),
        facts: vec![],
    };
    validate_snapshot(&snapshot)?;
    let kinds: BTreeMap<_, _> = report
        .entities
        .iter()
        .map(|e| (e.id.as_str(), e.kind))
        .collect();
    let signatures: BTreeMap<_, _> = catalog
        .signatures
        .iter()
        .map(|s| (s.id.as_str(), s))
        .collect();
    let evidence = |evidence: &Evidence, entity: &str| -> Result<(), String> {
        if evidence.fields.is_empty() || evidence.fields.len() > 8 || !identifier(&evidence.fact_id)
        {
            return Err("Invalid discovery evidence".into());
        }
        let fields = evidence.fields.iter().map(|f| (*f, vec![])).collect();
        let fact = Fact {
            id: evidence.fact_id.clone(),
            entity_id: entity.into(),
            source: evidence.source,
            observed_at: evidence.observed_at,
            fields,
        };
        let kind = *kinds
            .get(entity)
            .ok_or("Unknown discovery evidence entity")?;
        let check = Snapshot {
            version: snapshot.version,
            scope: snapshot.scope.clone(),
            sequence: snapshot.sequence,
            observed_at: snapshot.observed_at,
            complete: false,
            entities: vec![Entity {
                display: None,
                id: entity.into(),
                kind,
            }],
            facts: vec![fact],
            relations: vec![],
            coverage: vec![],
        };
        validate_snapshot(&check)
    };
    let mut ids = BTreeSet::new();
    for matched in &report.result.identifications {
        let signature = signatures
            .get(matched.signature_id.as_str())
            .ok_or("Unknown discovery signature")?;
        if matched.application_id != signature.application_id
            || matched.signature_revision != signature.revision
            || matched.state != signature.state
            || matched.evidence.is_empty()
            || matched.evidence.len() > 8
            || !kinds.contains_key(matched.entity_id.as_str())
            || !ids.insert((&matched.entity_id, &matched.signature_id))
        {
            return Err("Invalid discovery identification".into());
        }
        if let Expression::AllHttpResponses { args } = &signature.condition {
            let unique: BTreeSet<_> = matched
                .evidence
                .iter()
                .map(|proof| &proof.fact_id)
                .collect();
            if matched.evidence.len() != args.len()
                || unique.len() != args.len()
                || matched.evidence.iter().any(|proof| {
                    !proof.fields.contains(&Field::HttpPath)
                        || report.observed_at.saturating_sub(proof.observed_at) > 60
                })
            {
                return Err("Invalid correlated HTTP evidence".into());
            }
        }
        for proof in &matched.evidence {
            if !signature.sources.contains(&proof.source) {
                return Err("Invalid discovery evidence source".into());
            }
            evidence(proof, &matched.entity_id)?;
        }
    }
    let mut communications = BTreeSet::new();
    for communication in &report.result.communications {
        if !engine.has_provider(&communication.provider)
            || !matches!(
                communication.evidence.source,
                Source::HostFlow | Source::VmFlow | Source::RuntimeFlow | Source::ContainerFlow
            )
            || communication.evidence.fields != vec![Field::RemoteHost]
            || !communications.insert((&communication.entity_id, &communication.provider))
        {
            return Err("Invalid discovery communication".into());
        }
        evidence(&communication.evidence, &communication.entity_id)?;
    }
    let mut queries = BTreeSet::new();
    for query in &report.result.queries {
        if !engine.has_provider(&query.provider)
            || query.evidence.source != Source::HostDnsQuery
            || query.evidence.fields != vec![Field::RemoteHost]
            || !queries.insert((&query.entity_id, &query.provider))
        {
            return Err("Invalid discovery domain query".into());
        }
        evidence(&query.evidence, &query.entity_id)?;
    }
    Ok(())
}

fn ancestors<'a>(
    parents: &BTreeMap<&'a str, Vec<&'a str>>,
    ids: &mut BTreeSet<&'a str>,
    limit: usize,
) -> bool {
    let mut pending: Vec<_> = ids.iter().copied().collect();
    while let Some(id) = pending.pop() {
        if let Some(rows) = parents.get(id) {
            for parent in rows {
                if ids.insert(*parent) {
                    if ids.len() > limit {
                        return false;
                    }
                    pending.push(*parent);
                }
            }
        }
    }
    true
}

// Raw fields (HTTP bodies and argument projections) never leave the endpoint.
pub fn pages<'a>(
    snapshot: &'a Snapshot,
    result: &'a Evaluation,
    catalog_revision: u64,
    settings_revision: u64,
) -> Result<Vec<Report>, String> {
    let limited = result.saturated.then(|| {
        let mut coverage = snapshot.coverage.clone();
        for source in &mut coverage {
            source.complete = false;
            if source.status == CoverageStatus::Available {
                source.status = CoverageStatus::Partial;
            }
        }
        if coverage.len() < 256 {
            coverage.push(Coverage {
                scope: snapshot.scope.clone(),
                adapter: "detection-engine".into(),
                status: CoverageStatus::Saturated,
                checked_at: snapshot.observed_at,
                complete: false,
            });
        }
        Snapshot {
            version: snapshot.version,
            scope: snapshot.scope.clone(),
            sequence: snapshot.sequence,
            observed_at: snapshot.observed_at,
            complete: false,
            entities: snapshot.entities.clone(),
            relations: snapshot.relations.clone(),
            coverage,
            facts: vec![],
        }
    });
    let snapshot = limited.as_ref().unwrap_or(snapshot);

    validate_snapshot(snapshot)?;
    let entities: BTreeMap<_, _> = snapshot
        .entities
        .iter()
        .map(|entity| (entity.id.as_str(), entity))
        .collect();
    let mut parents: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for relation in &snapshot.relations {
        parents
            .entry(&relation.to)
            .or_default()
            .push(&relation.from);
    }
    // Entity identities carried with an identification/communication need no
    // second inventory-only page. This keeps a normal 100-observation batch in
    // one request while preserving independently valid ancestry on every page.
    let mut carried: BTreeSet<&str> = result
        .identifications
        .iter()
        .map(|row| row.entity_id.as_str())
        .chain(
            result
                .communications
                .iter()
                .map(|row| row.entity_id.as_str()),
        )
        .chain(result.queries.iter().map(|row| row.entity_id.as_str()))
        .collect();
    ancestors(&parents, &mut carried, MAX_ENTITIES);
    let visible: Vec<_> = snapshot
        .entities
        .iter()
        .filter(|entity| {
            entity.kind != EntityKind::Process && !carried.contains(entity.id.as_str())
        })
        .collect();
    let length = visible
        .len()
        .max(result.identifications.len())
        .max(result.communications.len())
        .max(result.queries.len());
    let count = length
        .div_ceil(100)
        .max(snapshot.coverage.len().div_ceil(16))
        .max(1);
    if count > 256 {
        return Err("Discovery report exceeds its page budget".into());
    }
    let mut pending = std::collections::VecDeque::new();
    for page in 0..count {
        let coverage = snapshot
            .coverage
            .get(page * 16..((page + 1) * 16).min(snapshot.coverage.len()))
            .unwrap_or(&[])
            .to_vec();
        pending.push_back((
            (page * 100).min(length),
            ((page + 1) * 100).min(length),
            coverage,
        ));
    }
    let mut reports = vec![];
    while let Some((start, end, coverage)) = pending.pop_front() {
        let selected = |length: usize| start.min(length)..end.min(length);
        let identifications =
            result.identifications[selected(result.identifications.len())].to_vec();
        let communications = result.communications[selected(result.communications.len())].to_vec();
        let queries = result.queries[selected(result.queries.len())].to_vec();
        let mut ids: BTreeSet<&str> = visible[selected(visible.len())]
            .iter()
            .map(|entity| entity.id.as_str())
            .chain(identifications.iter().map(|row| row.entity_id.as_str()))
            .chain(communications.iter().map(|row| row.entity_id.as_str()))
            .chain(queries.iter().map(|row| row.entity_id.as_str()))
            .collect();
        let fits = ids.len() <= 256 && ancestors(&parents, &mut ids, 256);
        let relations: Vec<_> = if fits {
            snapshot
                .relations
                .iter()
                .filter(|row| ids.contains(row.from.as_str()) && ids.contains(row.to.as_str()))
                .take(513)
                .cloned()
                .collect()
        } else {
            vec![]
        };
        let mut report = Report {
            version: VERSION,
            catalog_revision,
            settings_revision,
            run_id: None,
            scope: snapshot.scope.clone(),
            sequence: snapshot.sequence,
            page: 255,
            pages: 256,
            observed_at: snapshot.observed_at,
            complete: snapshot.complete,
            entities: if fits {
                ids.iter()
                    .filter_map(|id| entities.get(id).map(|entity| (*entity).clone()))
                    .collect()
            } else {
                vec![]
            },
            relations,
            coverage,
            result: Evaluation {
                identifications,
                communications,
                queries,
                evaluated_facts: 0,
                unknown_conditions: 0,
                saturated: false,
            },
        };
        let fits = fits
            && report.relations.len() <= 512
            && serde_json::to_vec(&report)
                .map_err(|_| "Cannot encode discovery report")?
                .len()
                <= 120 * 1024;
        if !fits {
            if end - start <= 1 {
                return Err("A discovery observation exceeds its page budget".into());
            }
            let coverage = std::mem::take(&mut report.coverage);
            let middle = start + (end - start) / 2;
            pending.push_front((middle, end, vec![]));
            pending.push_front((start, middle, coverage));
        } else {
            reports.push(report);
        }
        if reports.len() + pending.len() > 256 {
            return Err("Discovery report exceeds its page budget".into());
        }
    }
    let count = reports.len() as u16;
    for (index, report) in reports.iter_mut().enumerate() {
        report.page = index as u16;
        report.pages = count;
    }
    Ok(reports)
}
