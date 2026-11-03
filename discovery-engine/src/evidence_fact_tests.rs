use super::*;

// Reproduce the former per-evidence path through a complete one-fact snapshot.
fn legacy_evidence(evidence: &Evidence, kind: EntityKind, observed_at: i64) -> Result<(), String> {
    if evidence.fields.is_empty() || evidence.fields.len() > 8 || !identifier(&evidence.fact_id) {
        return Err("Invalid discovery evidence".into());
    }
    validate_snapshot(&Snapshot {
        version: VERSION, scope: "endpoint".into(), sequence: 1, observed_at, complete: false,
        entities: vec![Entity { display: None, id: "entity/one".into(), kind }],
        facts: vec![Fact { id:evidence.fact_id.clone(), entity_id:"entity/one".into(), source:evidence.source,
            observed_at:evidence.observed_at, fields:evidence.fields.iter().map(|field| (*field,vec![])).collect() }],
        relations:vec![], coverage:vec![],
    })
}

fn borrowed_evidence(evidence: &Evidence, kind: EntityKind, observed_at: i64) -> Result<(), String> {
    if evidence.fields.is_empty() || evidence.fields.len() > 8 || !identifier(&evidence.fact_id) {
        return Err("Invalid discovery evidence".into());
    }
    validate_evidence_fact(evidence,kind,observed_at)
}

#[test]
fn borrowed_report_evidence_matches_full_fact_source_kind_and_field_matrix() {
    let kinds = [EntityKind::Host,EntityKind::Vm,EntityKind::Wsl,EntityKind::Runtime,
        EntityKind::Container,EntityKind::Process,EntityKind::Endpoint];
    let fields = [Field::Package,Field::Executable,Field::ArgumentToken,Field::ImageRepository,
        Field::ImageDigest,Field::ContainerName,Field::Label,Field::ContainerState,Field::HttpStatus,
        Field::HttpBody,Field::HttpPath,Field::HttpContentType,Field::RemoteHost,Field::RemotePort];
    // Explicit contract table also checks the oracle rather than merely comparing
    // two paths that share the extracted scalar helper.
    let cases = [
        (Source::Installation,vec![EntityKind::Host],vec![Field::Package,Field::Executable]),
        (Source::HostProcess,vec![EntityKind::Process],vec![Field::Executable,Field::ArgumentToken]),
        (Source::GuestProcess,vec![EntityKind::Process],vec![Field::Executable,Field::ArgumentToken]),
        (Source::ContainerProcess,vec![EntityKind::Process],vec![Field::Executable,Field::ArgumentToken]),
        (Source::ContainerMetadata,vec![EntityKind::Container],vec![Field::ImageRepository,Field::ImageDigest,Field::ContainerName,Field::Label,Field::ContainerState]),
        (Source::Http,vec![EntityKind::Endpoint],vec![Field::HttpStatus,Field::HttpBody,Field::HttpPath,Field::HttpContentType]),
        (Source::HostFlow,vec![EntityKind::Host,EntityKind::Process],vec![Field::RemoteHost,Field::RemotePort]),
        (Source::HostDnsQuery,vec![EntityKind::Host],vec![Field::RemoteHost]),
        (Source::VmFlow,vec![EntityKind::Vm,EntityKind::Wsl],vec![Field::RemoteHost,Field::RemotePort]),
        (Source::RuntimeFlow,vec![EntityKind::Runtime],vec![Field::RemoteHost,Field::RemotePort]),
        (Source::ContainerFlow,vec![EntityKind::Container],vec![Field::RemoteHost,Field::RemotePort]),
    ];
    for (source,allowed_kinds,allowed_fields) in cases {
        for kind in kinds {
            for field in fields {
                let evidence=Evidence { fact_id:"fact/one".into(), source,observed_at:7200,fields:vec![field] };
                let legacy=legacy_evidence(&evidence,kind,7200);
                assert_eq!(borrowed_evidence(&evidence,kind,7200),legacy,"{source:?}/{kind:?}/{field:?}");
                assert_eq!(legacy.is_ok(),allowed_kinds.contains(&kind)&&allowed_fields.contains(&field));
            }
        }
    }
}

#[test]
fn borrowed_report_evidence_preserves_ids_time_dns_and_duplicate_field_semantics() {
    for source in [Source::HostProcess,Source::HostDnsQuery] {
        let (kind,field)=if source==Source::HostProcess {(EntityKind::Process,Field::Executable)} else {(EntityKind::Host,Field::RemoteHost)};
        for fact_id in ["fact/one".to_owned(),String::new(),"bad space".to_owned(),"x".repeat(161)] {
            for timestamp in [-1,0,3599,3600,3601,7199,7200,7201] {
                for count in [0,1,2,8,9] {
                    let evidence=Evidence { fact_id:fact_id.clone(),source,observed_at:timestamp,fields:vec![field;count] };
                    let legacy=legacy_evidence(&evidence,kind,7200);
                    assert_eq!(borrowed_evidence(&evidence,kind,7200),legacy);
                    let allowed=identifier(&fact_id)&&(1..=8).contains(&count)&&timestamp>=0&&timestamp<=7200
                        &&(source!=Source::HostDnsQuery||7200-timestamp<=3600);
                    assert_eq!(legacy.is_ok(),allowed);
                }
            }
        }
    }
}

fn report_fixture() -> (Catalog,Report) {
    let signatures = ["one","two"].into_iter().map(|id| Signature {
        id:format!("signature/{id}"),application_id:format!("application/{id}"),name:"Synthetic signature".into(),revision:1,
        sources:vec![Source::HostProcess],state:State::Executed,
        condition:Expression::Eq {field:Field::Executable,value:"synthetic".into()},provenance:"Synthetic fixture".into(),
    }).collect::<Vec<_>>();
    let identifications=signatures.iter().map(|signature| Identification {
        application_id:signature.application_id.clone(),signature_id:signature.id.clone(),signature_revision:1,
        entity_id:"entity/one".into(),state:State::Executed,
        evidence:vec![Evidence {fact_id:"fact/shared".into(),source:Source::HostProcess,observed_at:7200,
            fields:vec![Field::Executable,Field::Executable]}],
    }).collect();
    let catalog=Catalog {http_paths:vec!["/".into()],http_ports:vec![],version:VERSION,revision:1,signatures,providers:vec![]};
    let report=Report {version:VERSION,catalog_revision:1,settings_revision:1,run_id:None,scope:"endpoint".into(),
        sequence:1,page:0,pages:1,observed_at:7200,complete:false,
        entities:vec![Entity {display:None,id:"entity/one".into(),kind:EntityKind::Process}],relations:vec![],coverage:vec![],
        result:Evaluation {saturated:false,identifications,communications:vec![],queries:vec![],evaluated_facts:1,unknown_conditions:0}};
    (catalog,report)
}

#[test]
fn borrowed_report_evidence_keeps_fact_reuse_across_matches_and_match_identity_checks() {
    let (catalog,mut report)=report_fixture();
    assert!(crate::report::validate(&report,&catalog).is_ok());
    assert!(crate::report::validate_prevalidated(&report,&catalog).is_ok());
    report.result.identifications[1]=report.result.identifications[0].clone();
    assert_eq!(crate::report::validate(&report,&catalog).unwrap_err(),"Invalid discovery identification");
    assert_eq!(crate::report::validate_prevalidated(&report,&catalog).unwrap_err(),"Invalid discovery identification");
}

#[test]
fn borrowed_report_evidence_does_not_skip_initial_snapshot_structure() {
    let (catalog,report)=report_fixture();
    for case in 0..4 {
        let mut malformed=report.clone();
        match case {
            0 => malformed.scope="bad scope".into(),
            1 => malformed.entities.push(malformed.entities[0].clone()),
            2 => malformed.entities[0].display=Some(EntityDisplay {name:Some(String::new()),..Default::default()}),
            _ => {
                malformed.complete=true;
                malformed.coverage.push(Coverage {scope:"endpoint".into(),adapter:"host".into(),status:CoverageStatus::Partial,
                    complete:false,checked_at:7200});
            }
        }
        let normal=crate::report::validate(&malformed,&catalog);
        assert!(normal.is_err());
        assert_eq!(crate::report::validate_prevalidated(&malformed,&catalog),normal);
    }
}
