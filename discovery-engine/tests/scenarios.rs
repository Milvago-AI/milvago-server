use milvago_discovery_engine::*;
use std::collections::BTreeMap;

#[test]
fn native_openclaw_gateway_titles_are_process_evidence_only_and_exact() {
    let catalog: Catalog = serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    assert!(catalog.revision >= 2);
    let engine = Engine::compile(&catalog).unwrap();
    for source in [Source::HostProcess, Source::GuestProcess, Source::ContainerProcess] {
        for executable in ["openclaw-gateway", "openclaw-gateway.exe"] {
            let input = snapshot(source, EntityKind::Process, &[(Field::Executable, &[executable])]);
            let result = engine.evaluate(&input).unwrap();
            assert!(result.identifications.iter().any(|row| row.application_id == "openclaw"
                && row.signature_id == "openclaw.gateway" && row.state == State::Executed));
            assert!(result.communications.is_empty());
            assert!(result.queries.is_empty());
        }
        for executable in ["node", "openclaw-gateway-other", "openclaw-gatewa", "data:image/png", "OpenClaw-Gateway"] {
            let input = snapshot(source, EntityKind::Process, &[(Field::Executable, &[executable])]);
            assert!(!engine.evaluate(&input).unwrap().identifications.iter()
                .any(|row| row.signature_id == "openclaw.gateway"));
        }
    }
    let input = snapshot(Source::ContainerMetadata, EntityKind::Container,
        &[(Field::ImageRepository, &["openclaw-gateway"])]);
    assert!(engine.evaluate(&input).unwrap().identifications.iter().all(|row| row.state != State::Executed));
}

#[test]
fn reviewed_julius_fingerprints_require_their_own_responses_and_reject_error_pages() {
    let catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let cases: serde_json::Value =
        serde_json::from_slice(include_bytes!("fixtures/julius-http.json")).unwrap();
    assert_eq!(cases.as_array().unwrap().len(), 14);
    for case in cases.as_array().unwrap() {
        let expected = case["signature_id"].as_str().unwrap();
        let mut input = snapshot(Source::Http, EntityKind::Endpoint, &[]);
        input.facts.clear();
        for (index, response) in case["responses"].as_array().unwrap().iter().enumerate() {
            assert!(
                catalog
                    .http_paths
                    .contains(&response["path"].as_str().unwrap().to_string())
            );
            input.facts.push(Fact {
                id: format!("response/{index}"),
                entity_id: input.entities[0].id.clone(),
                source: Source::Http,
                observed_at: input.observed_at,
                fields: BTreeMap::from([
                    (
                        Field::HttpPath,
                        vec![response["path"].as_str().unwrap().into()],
                    ),
                    (
                        Field::HttpStatus,
                        vec![response["status"].as_str().unwrap().into()],
                    ),
                    (
                        Field::HttpBody,
                        vec![response["body"].as_str().unwrap().into()],
                    ),
                    (
                        Field::HttpContentType,
                        vec![response["content_type"].as_str().unwrap().into()],
                    ),
                ]),
            });
        }
        let matched = |snapshot: &Snapshot| {
            engine
                .evaluate(snapshot)
                .unwrap()
                .identifications
                .into_iter()
                .filter(|row| row.signature_id == expected)
                .collect::<Vec<_>>()
        };
        let found = matched(&input);
        assert_eq!(found.len(), 1, "positive {expected}");
        assert_eq!(found[0].evidence.len(), input.facts.len(), "{expected}");
        for page in report::pages(&input, &engine.evaluate(&input).unwrap(), catalog.revision, 1).unwrap() {
            report::validate(&page, &catalog).unwrap();
        }
        for index in 0..input.facts.len() {
            for (field, value) in [
                (Field::HttpBody, "<html>Service unavailable</html>"),
                (Field::HttpStatus, "503"),
                (Field::HttpPath, "/unrelated"),
            ] {
                let mut broken = input.clone();
                broken.facts[index].fields.insert(field, vec![value.into()]);
                assert!(
                    matched(&broken).is_empty(),
                    "negative {expected} response {index} {field:?}"
                );
            }
            if input.facts.len() > 1 {
                let mut missing = input.clone();
                missing.facts.remove(index);
                assert!(matched(&missing).is_empty(), "missing {expected}/{index}");
                let mut foreign = input.clone();
                let mut entity = input.entities[0].clone();
                entity.id = "other/endpoint".into();
                foreign.entities.push(entity);
                foreign.facts[index].entity_id = "other/endpoint".into();
                assert!(
                    matched(&foreign).is_empty(),
                    "cross endpoint {expected}/{index}"
                );
            }
        }
        if expected == "lm-studio.http_greeting" {
            input.facts[0].fields.insert(
                Field::HttpBody,
                vec!["{\"lmstudio\":false,\"other\":true}".into()],
            );
            assert!(matched(&input).is_empty());
        }
    }
}

fn correlated_http_catalog() -> Catalog {
    serde_json::from_value(serde_json::json!({
        "version":1,"revision":1,"http_paths":["/","/health"],"signatures":[{
            "id":"fixture.http-bundle","application_id":"fixture","name":"Fixture",
            "revision":1,"sources":["http"],"state":"interface_recognized","provenance":"fixture",
            "condition":{"op":"all_http_responses","args":[
                {"op":"all","args":[{"op":"eq","field":"http_path","value":"/"},{"op":"contains","field":"http_body","value":"alpha"}]},
                {"op":"all","args":[{"op":"eq","field":"http_path","value":"/health"},{"op":"contains","field":"http_body","value":"beta"}]}
            ]}
        }]
    })).unwrap()
}

#[test]
fn correlated_http_requires_each_response_on_one_endpoint_and_recent_atomic_facts() {
    let catalog = correlated_http_catalog();
    let engine = Engine::compile(&catalog).unwrap();
    let mut input = snapshot(
        Source::Http,
        EntityKind::Endpoint,
        &[
            (Field::HttpStatus, &["200"]),
            (Field::HttpPath, &["/"]),
            (Field::HttpBody, &["alpha"]),
        ],
    );
    assert!(engine.evaluate(&input).unwrap().identifications.is_empty());
    let mut second = input.facts[0].clone();
    second.id = "response/2".into();
    second
        .fields
        .insert(Field::HttpPath, vec!["/health".into()]);
    second.fields.insert(Field::HttpBody, vec!["beta".into()]);
    input.facts.push(second);
    let result = engine.evaluate(&input).unwrap();
    assert_eq!(result.identifications.len(), 1);
    assert_eq!(result.identifications[0].evidence.len(), 2);
    let pages = report::pages(&input, &result, catalog.revision, 1).unwrap();
    report::validate(&pages[0], &catalog).unwrap();
    assert!(!serde_json::to_string(&pages).unwrap().contains("alpha"));
    for mutation in 0..5 {
        let mut broken = input.clone();
        match mutation {
            0 => {
                let mut entity = broken.entities[0].clone();
                entity.id = "other/endpoint".into();
                broken.entities.push(entity);
                broken.facts[1].entity_id = "other/endpoint".into();
            }
            1 => {
                broken.facts[1]
                    .fields
                    .insert(Field::HttpPath, vec!["/other".into()]);
            }
            2 => broken.facts[1].observed_at = 0,
            3 => {
                broken.facts[1]
                    .fields
                    .insert(Field::HttpBody, vec!["beta".into(), "alpha".into()]);
            }
            _ => {
                broken.facts[1]
                    .fields
                    .insert(Field::HttpPath, vec!["/health".into(), "/".into()]);
            }
        }
        assert!(
            engine.evaluate(&broken).unwrap().identifications.is_empty(),
            "{mutation}"
        );
    }
    let mut duplicate = pages[0].clone();
    duplicate.result.identifications[0].evidence[1] =
        duplicate.result.identifications[0].evidence[0].clone();
    assert!(report::validate(&duplicate, &catalog).is_err());
    let mut partial = pages[0].clone();
    partial.result.identifications[0].evidence.pop();
    assert!(report::validate(&partial, &catalog).is_err());
}

#[test]
fn correlated_http_groups_reject_ambiguous_paths_nesting_and_non_http_sources() {
    let good = serde_json::to_value(correlated_http_catalog()).unwrap();
    let rule = good["signatures"][0].clone();
    for mutation in 0..8 {
        let mut catalog = good.clone();
        let condition = &mut catalog["signatures"][0]["condition"];
        match mutation {
            0 => condition["args"] = serde_json::json!([]),
            1 => condition["args"] = serde_json::json!([rule["condition"]["args"][0].clone()]),
            2 => {
                condition["args"] = serde_json::json!(vec![rule["condition"]["args"][0].clone(); 9])
            }
            3 => condition["args"][1]["args"][0]["value"] = "/".into(),
            4 => condition["args"][1]["args"][0]["value"] = "/health?token=private".into(),
            5 => {
                condition["args"][1] =
                    serde_json::json!({"op":"contains","field":"http_body","value":"beta"})
            }
            6 => *condition = serde_json::json!({"op":"not","arg":rule["condition"].clone()}),
            _ => catalog["signatures"][0]["sources"] = serde_json::json!(["http", "host_process"]),
        }
        let catalog: Catalog = serde_json::from_value(catalog).unwrap();
        assert!(Engine::compile(&catalog).is_err(), "{mutation}");
    }
}

#[test]
fn correlated_http_cancellation_and_work_limits_bound_dense_response_groups() {
    let mut catalog = correlated_http_catalog();
    catalog.signatures = (0..1024)
        .map(|index| {
            let mut rule = catalog.signatures[0].clone();
            rule.id = format!("fixture.{index}");
            rule
        })
        .collect();
    let engine = Engine::compile(&catalog).unwrap();
    let mut input = snapshot(
        Source::Http,
        EntityKind::Endpoint,
        &[
            (Field::HttpStatus, &["200"]),
            (Field::HttpPath, &["/"]),
            (Field::HttpBody, &["alpha"]),
        ],
    );
    for index in 0..1000 {
        let mut fact = input.facts[0].clone();
        fact.id = format!("response/{index}");
        fact.fields.insert(Field::HttpPath, vec!["/health".into()]);
        fact.fields.insert(Field::HttpBody, vec!["other".into()]);
        input.facts.push(fact);
    }
    assert!(engine.evaluate(&input).unwrap_err().contains("work budget"));
    let checks = std::cell::Cell::new(0);
    assert!(
        engine
            .evaluate_with_cancel(&input, || {
                checks.set(checks.get() + 1);
                checks.get() > 64
            })
            .unwrap_err()
            .contains("cancelled")
    );
    assert!(checks.get() < 100);
}

#[test]
fn dns_query_is_neither_a_connection_nor_an_application_nor_a_guest_origin() {
    let catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let mut input = snapshot(
        Source::HostDnsQuery,
        EntityKind::Host,
        &[(
            Field::RemoteHost,
            &[
                "API.OPENAI.COM.",
                "api.openai.com",
                "api.openai.com.evil.test",
            ],
        )],
    );
    let result = engine.evaluate(&input).unwrap();
    assert_eq!(result.queries.len(), 1);
    assert_eq!(result.queries[0].provider, "openai");
    assert!(result.communications.is_empty());
    assert!(result.identifications.is_empty());
    let mut report = report::pages(&input, &result, catalog.revision, 1).unwrap().remove(0);
    report::validate(&report, &catalog).unwrap();
    assert!(
        !serde_json::to_string(&report)
            .unwrap()
            .contains("API.OPENAI.COM")
    );
    report.result.communications.push(Communication {
        entity_id: result.queries[0].entity_id.clone(),
        provider: "openai".into(),
        evidence: result.queries[0].evidence.clone(),
    });
    assert!(report::validate(&report, &catalog).is_err());
    for kind in [
        EntityKind::Vm,
        EntityKind::Wsl,
        EntityKind::Process,
        EntityKind::Runtime,
        EntityKind::Container,
        EntityKind::Endpoint,
    ] {
        input.entities[0].kind = kind;
        assert!(engine.evaluate(&input).is_err(), "{kind:?}");
    }
    input.entities[0].kind = EntityKind::Host;
    input.facts[0]
        .fields
        .insert(Field::RemotePort, vec!["443".into()]);
    assert!(engine.evaluate(&input).is_err());
    input.facts[0].fields.remove(&Field::RemotePort);
    input.observed_at += 3601;
    assert!(engine.evaluate(&input).is_err());
    for state in [
        State::Indication,
        State::Installed,
        State::Executed,
        State::InterfaceRecognized,
    ] {
        assert!(Engine::compile(&catalog_with_dns_signature(state)).is_err());
    }
}

fn catalog_with_dns_signature(state: State) -> Catalog {
    catalog(
        Source::HostDnsQuery,
        state,
        Expression::Eq {
            field: Field::RemoteHost,
            value: "api.openai.com".into(),
        },
    )
}

#[test]
fn dns_query_pages_preserve_separate_contact_and_reject_forged_proofs() {
    let catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let mut input = snapshot(
        Source::HostDnsQuery,
        EntityKind::Host,
        &[(Field::RemoteHost, &["api.openai.com"])],
    );
    for n in 1..251 {
        let mut entity = input.entities[0].clone();
        entity.id = format!("host/{n}");
        let mut fact = input.facts[0].clone();
        fact.id = format!("query/{n}");
        fact.entity_id = entity.id.clone();
        input.entities.push(entity);
        input.facts.push(fact);
    }
    let mut flow = input.facts[0].clone();
    flow.id = "flow/1".into();
    flow.source = Source::HostFlow;
    input.facts.push(flow);
    let result = engine.evaluate(&input).unwrap();
    assert_eq!(result.communications.len(), 1);
    assert_eq!(result.queries.len(), 251);
    let pages = report::pages(&input, &result, catalog.revision, 1).unwrap();
    assert_eq!(pages.len(), 3);
    assert_eq!(
        pages.iter().map(|p| p.result.queries.len()).sum::<usize>(),
        251
    );
    for page in &pages {
        report::validate(page, &catalog).unwrap();
    }
    for mutation in 0..5 {
        let mut page = pages[0].clone();
        match mutation {
            0 => page.result.queries[0].provider = "unknown".into(),
            1 => page.result.queries[0].evidence.source = Source::HostFlow,
            2 => page.result.queries[0]
                .evidence
                .fields
                .push(Field::RemotePort),
            3 => page.result.queries.push(page.result.queries[0].clone()),
            _ => page.result.queries[0].evidence.observed_at = page.observed_at + 1,
        }
        assert!(report::validate(&page, &catalog).is_err(), "{mutation}");
    }
    let mut empty = serde_json::to_value(&result).unwrap();
    empty.as_object_mut().unwrap().remove("queries");
    let legacy: Evaluation = serde_json::from_value(empty).unwrap();
    assert!(legacy.queries.is_empty());
    assert!(
        serde_json::to_value(legacy)
            .unwrap()
            .get("queries")
            .is_none()
    );
}

fn catalog(source: Source, state: State, condition: Expression) -> Catalog {
    Catalog {
        http_paths: default_http_paths(),
        http_ports: default_http_ports(),
        providers: default_providers(),
        version: VERSION,
        revision: 1,
        signatures: vec![Signature {
            id: "openclaw.process".into(),
            application_id: "openclaw".into(),
            name: "OpenClaw".into(),
            revision: 1,
            sources: vec![source],
            state,
            condition,
            provenance: "fixture".into(),
        }],
    }
}
fn process_catalog(source: Source) -> Catalog {
    catalog(
        source,
        State::Executed,
        Expression::Eq {
            field: Field::Executable,
            value: "openclaw".into(),
        },
    )
}

#[test]
fn catalogue_http_paths_are_literal_bounded_routes_with_legacy_root_default() {
    let mut value: serde_json::Value =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    value.as_object_mut().unwrap().remove("http_paths");
    let mut catalog: Catalog = serde_json::from_value(value).unwrap();
    assert_eq!(catalog.http_paths, vec!["/"]);
    // Route syntax is independent from a factory signature's required routes.
    catalog
        .signatures
        .retain(|signature| !signature.sources.contains(&Source::Http));
    for path in ["/", "/health", "/v1/health", "/.well-known/ai"] {
        catalog.http_paths = vec![path.into()];
        assert!(Engine::compile(&catalog).is_ok());
    }
    for paths in [
        vec![],
        vec!["/health".into(); 2],
        vec!["/health".into(); 17],
    ] {
        catalog.http_paths = paths;
        assert!(Engine::compile(&catalog).is_err());
    }
    for path in [
        "https://example.test/",
        "//example.test/",
        "/../secret",
        "/v1/./health",
        "/%2e%2e/secret",
        "/health?token=secret",
        "/health#part",
        "/health\\other",
        "/health\n",
        "data:image/png",
    ] {
        catalog.http_paths = vec![path.into()];
        assert!(Engine::compile(&catalog).is_err(), "{path:?}");
    }
}

#[test]
fn hermes_health_is_recognized_only_on_a_matching_json_health_interface() {
    let catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    let valid = r#"{"status":"ok","platform":"hermes-agent","version":"fixture"}"#;
    for path in ["/health", "/v1/health"] {
        let input = snapshot(
            Source::Http,
            EntityKind::Endpoint,
            &[
                (Field::HttpStatus, &["200"]),
                (Field::HttpPath, &[path]),
                (Field::HttpContentType, &["application/json"]),
                (Field::HttpBody, &[valid]),
            ],
        );
        assert!(
            engine
                .evaluate(&input)
                .unwrap()
                .identifications
                .iter()
                .any(|item| item.application_id == "hermes"
                    && item.state == State::InterfaceRecognized)
        );
    }
    for (status, path, mime, body) in [
        ("401", "/health", "application/json", valid),
        ("200", "/", "application/json", valid),
        ("200", "/health", "text/html", valid),
        (
            "200",
            "/health",
            "application/json",
            r#"{"status":"ok","version":"fixture"}"#,
        ),
        (
            "200",
            "/health",
            "application/json",
            r#"{"status":"ok","platform":"not-hermes","version":"fixture"}"#,
        ),
        (
            "200",
            "/health",
            "application/json",
            r#"{"status":"ok","platform":"hermes-agent"}"#,
        ),
        ("200", "/health", "application/json", "data:image/png"),
    ] {
        let input = snapshot(
            Source::Http,
            EntityKind::Endpoint,
            &[
                (Field::HttpStatus, &[status]),
                (Field::HttpPath, &[path]),
                (Field::HttpContentType, &[mime]),
                (Field::HttpBody, &[body]),
            ],
        );
        assert!(
            engine.evaluate(&input).unwrap().identifications.is_empty(),
            "{status}/{path}/{mime}/{body}"
        );
    }
}

#[test]
fn official_script_launchers_are_recognized_without_treating_images_as_execution() {
    let catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    for source in [
        Source::HostProcess,
        Source::GuestProcess,
        Source::ContainerProcess,
    ] {
        for (executable, token, application) in [
            ("node", "openclaw.mjs", "openclaw"),
            ("nodejs", "openclaw", "openclaw"),
            ("python3.11", "hermes", "hermes"),
            ("python3.12", "hermes-agent", "hermes"),
            ("python3", "hermes-acp", "hermes"),
            ("python", "hermes.exe", "hermes"),
        ] {
            let input = snapshot(
                source,
                EntityKind::Process,
                &[
                    (Field::Executable, &[executable]),
                    (Field::ArgumentToken, &[token]),
                ],
            );
            assert!(engine.evaluate(&input).unwrap().identifications.iter().any(|item| item.application_id == application && item.state == State::Executed), "{source:?}/{executable}/{token}");
        }
        for (executable, token) in [
            ("node", "hermes-agent"),
            ("python3.11", "openclaw.mjs"),
            ("python3.11evil", "hermes"),
            ("python3.11", "hermes-agent-copy"),
            ("node", "openclaw.mjs.evil"),
        ] {
            let input = snapshot(
                source,
                EntityKind::Process,
                &[
                    (Field::Executable, &[executable]),
                    (Field::ArgumentToken, &[token]),
                ],
            );
            assert!(
                engine.evaluate(&input).unwrap().identifications.is_empty(),
                "{source:?}/{executable}/{token}"
            );
        }
    }
    let input = snapshot(
        Source::ContainerMetadata,
        EntityKind::Container,
        &[(Field::ImageRepository, &["hermes-agent"])],
    );
    let result = engine.evaluate(&input).unwrap();
    assert!(
        result
            .identifications
            .iter()
            .any(|item| item.application_id == "hermes" && item.state == State::Indication)
    );
    assert!(
        result
            .identifications
            .iter()
            .all(|item| item.state != State::Executed)
    );
}

#[test]
fn factory_recognizes_hermes_on_versioned_python_without_prefix_spoofing() {
    let catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    let engine = Engine::compile(&catalog).unwrap();
    for source in [
        Source::HostProcess,
        Source::GuestProcess,
        Source::ContainerProcess,
    ] {
        for executable in [
            "python",
            "python3",
            "python3.9",
            "python3.10",
            "python3.11",
            "python3.15",
        ] {
            let input = snapshot(
                source,
                EntityKind::Process,
                &[
                    (Field::Executable, &[executable]),
                    (Field::ArgumentToken, &["hermes_cli.main"]),
                ],
            );
            assert!(
                engine
                    .evaluate(&input)
                    .unwrap()
                    .identifications
                    .iter()
                    .any(|item| item.application_id == "hermes" && item.state == State::Executed),
                "{source:?}/{executable}"
            );
        }
        for executable in ["python2", "python3.11evil", "python3.111", "python3.１"] {
            let input = snapshot(
                source,
                EntityKind::Process,
                &[
                    (Field::Executable, &[executable]),
                    (Field::ArgumentToken, &["hermes_cli.main"]),
                ],
            );
            assert!(engine.evaluate(&input).unwrap().identifications.is_empty());
        }
    }
}

#[test]
fn custom_provider_catalogue_uses_exact_hosts_without_identifying_a_guest_application() {
    let mut catalog = process_catalog(Source::GuestProcess);
    catalog.providers = vec![Provider {
        id: "internal_ai".into(),
        hosts: vec![
            "inference.example.test".into(),
            "inference-backup.example.test".into(),
        ],
    }];
    let mut input = snapshot(
        Source::VmFlow,
        EntityKind::Vm,
        &[(Field::RemoteHost, &["INFERENCE.EXAMPLE.TEST."])],
    );
    let engine = Engine::compile(&catalog).unwrap();
    let result = engine.evaluate(&input).unwrap();
    assert!(result.identifications.is_empty());
    assert_eq!(result.communications.len(), 1);
    assert_eq!(result.communications[0].provider, "internal_ai");
    for page in report::pages(&input, &result, catalog.revision, 1).unwrap() {
        report::validate(&page, &catalog).unwrap();
        let other = process_catalog(Source::GuestProcess);
        assert!(report::validate(&page, &other).is_err());
    }
    for host in [
        "inference.example.test.evil.test",
        "prefix-inference.example.test",
        "api.openai.com",
        "inference.example.test..",
    ] {
        input.facts[0]
            .fields
            .insert(Field::RemoteHost, vec![host.into()]);
        assert!(engine.evaluate(&input).unwrap().communications.is_empty());
    }
}

#[test]
fn provider_definitions_reject_ambiguity_wildcards_urls_and_unbounded_input() {
    let misleading = catalog(
        Source::VmFlow,
        State::Indication,
        Expression::Eq {
            field: Field::RemoteHost,
            value: "api.openai.com".into(),
        },
    );
    assert!(Engine::compile(&misleading).is_err());
    for host in [
        "*.example.test",
        "https://example.test",
        "api.example.test:443",
        "api.example.test/",
        "api.example.test.",
        "API.example.test",
        "127.0.0.1",
        "api..example.test",
        "-api.example.test",
        "api.éxample.test",
    ] {
        let mut catalog = process_catalog(Source::HostProcess);
        catalog.providers = vec![Provider {
            id: "custom".into(),
            hosts: vec![host.into()],
        }];
        assert!(Engine::compile(&catalog).is_err(), "accepted {host}");
    }
    let mut catalog = process_catalog(Source::HostProcess);
    catalog.providers.push(Provider {
        id: "other".into(),
        hosts: vec!["api.openai.com".into()],
    });
    assert!(Engine::compile(&catalog).is_err());
    catalog.providers = vec![Provider {
        id: "data:image/png".into(),
        hosts: vec!["example.test".into()],
    }];
    assert!(Engine::compile(&catalog).is_err());
    catalog.providers = vec![Provider {
        id: "custom".into(),
        hosts: vec![],
    }];
    assert!(Engine::compile(&catalog).is_err());
}
fn snapshot(source: Source, kind: EntityKind, fields: &[(Field, &[&str])]) -> Snapshot {
    Snapshot {
        version: VERSION,
        scope: "host/boot-1".into(),
        sequence: 1,
        observed_at: 100,
        complete: true,
        entities: vec![Entity {
            display: None,
            id: "object/1".into(),
            kind,
        }],
        facts: vec![Fact {
            id: "fact/1".into(),
            entity_id: "object/1".into(),
            source,
            observed_at: 100,
            fields: fields
                .iter()
                .map(|(f, v)| (*f, v.iter().map(|s| s.to_string()).collect()))
                .collect(),
        }],
        relations: vec![],
        coverage: vec![],
    }
}

#[test]
fn host_guest_and_container_process_scenarios() {
    for source in [
        Source::HostProcess,
        Source::GuestProcess,
        Source::ContainerProcess,
    ] {
        let engine = Engine::compile(&process_catalog(source)).unwrap();
        for (executable, expected) in [
            ("openclaw", 1),
            ("node", 0),
            ("python", 0),
            ("not-openclaw", 0),
            ("openclaw-helper", 0),
        ] {
            let result = engine
                .evaluate(&snapshot(
                    source,
                    EntityKind::Process,
                    &[(Field::Executable, &[executable])],
                ))
                .unwrap();
            assert_eq!(
                result.identifications.len(),
                expected,
                "{source:?} {executable}"
            );
        }
    }
}

#[test]
fn vmtools_absent_denied_or_unknown_is_not_evidence_of_absence() {
    let engine = Engine::compile(&process_catalog(Source::GuestProcess)).unwrap();
    for status in [
        CoverageStatus::Disabled,
        CoverageStatus::Denied,
        CoverageStatus::Unavailable,
        CoverageStatus::Timeout,
        CoverageStatus::Partial,
    ] {
        let mut input = snapshot(Source::GuestProcess, EntityKind::Process, &[]);
        input.complete = false;
        input.coverage.push(Coverage {
            scope: "vm/1".into(),
            adapter: "vmware-tools".into(),
            status,
            checked_at: 100,
            complete: false,
        });
        let result = engine.evaluate(&input).unwrap();
        assert!(result.identifications.is_empty());
        assert_eq!(result.unknown_conditions, 1);
        assert!(!input.complete);
    }
}

#[test]
fn exposed_vm_endpoint_does_not_require_default_port() {
    let signature = catalog(
        Source::Http,
        State::InterfaceRecognized,
        Expression::All {
            args: vec![
                Expression::Eq {
                    field: Field::HttpStatus,
                    value: "200".into(),
                },
                Expression::Contains {
                    field: Field::HttpBody,
                    value: "<title>OpenClaw Control</title>".into(),
                },
                Expression::Contains {
                    field: Field::HttpBody,
                    value: "<openclaw-app>".into(),
                },
            ],
        },
    );
    let engine = Engine::compile(&signature).unwrap();
    let body = "<title>OpenClaw Control</title><openclaw-app></openclaw-app>";
    for port in [18789, 32145, 65535] {
        let mut input = snapshot(
            Source::Http,
            EntityKind::Endpoint,
            &[(Field::HttpStatus, &["200"]), (Field::HttpBody, &[body])],
        );
        input.entities[0].id = format!("endpoint/vm1/{port}");
        input.facts[0].entity_id = input.entities[0].id.clone();
        input.entities.push(Entity {
            display: None,
            id: "vm/1".into(),
            kind: EntityKind::Vm,
        });
        input.relations.push(Relation {
            from: "vm/1".into(),
            to: input.entities[0].id.clone(),
            kind: RelationKind::OwnsEndpoint,
            source: "nat-map".into(),
        });
        let result = engine.evaluate(&input).unwrap();
        assert_eq!(result.identifications.len(), 1);
        assert_eq!(result.identifications[0].state, State::InterfaceRecognized);
    }
    let false_response = snapshot(
        Source::Http,
        EntityKind::Endpoint,
        &[
            (Field::HttpStatus, &["200"]),
            (Field::HttpBody, &["OpenClaw documentation"]),
        ],
    );
    assert!(
        engine
            .evaluate(&false_response)
            .unwrap()
            .identifications
            .is_empty()
    );
}

#[test]
fn hidden_vm_contacting_openai_is_not_an_openclaw_identification() {
    let engine = Engine::compile(&process_catalog(Source::GuestProcess)).unwrap();
    for (source, kind) in [
        (Source::VmFlow, EntityKind::Vm),
        (Source::RuntimeFlow, EntityKind::Runtime),
        (Source::ContainerFlow, EntityKind::Container),
        (Source::HostFlow, EntityKind::Host),
    ] {
        let result = engine
            .evaluate(&snapshot(
                source,
                kind,
                &[
                    (Field::RemoteHost, &["api.openai.com"]),
                    (Field::RemotePort, &["443"]),
                ],
            ))
            .unwrap();
        assert!(result.identifications.is_empty());
        assert_eq!(result.communications.len(), 1);
        assert_eq!(result.communications[0].entity_id, "object/1");
        assert_eq!(result.communications[0].provider, "openai");
    }
}

#[test]
fn provider_exact_names_avoid_suffix_and_unicode_spoofing() {
    for host in ["api.openai.com", "API.OPENAI.COM", "api.openai.com."] {
        assert_eq!(provider(host), Some("openai"));
    }
    for host in [
        "api.openai.com.evil.invalid",
        "evilapi.openai.com",
        "api.openаi.com",
        "api.openai.com:443",
        "https://api.openai.com",
        "104.18.0.1",
    ] {
        assert_eq!(provider(host), None, "{host}");
    }
}

#[test]
fn container_names_images_labels_are_indications_not_execution() {
    for field in [
        Field::ContainerName,
        Field::ImageRepository,
        Field::ImageDigest,
        Field::Label,
    ] {
        let condition = Expression::Eq {
            field,
            value: "openclaw".into(),
        };
        assert!(
            Engine::compile(&catalog(
                Source::ContainerMetadata,
                State::Executed,
                condition.clone()
            ))
            .is_err()
        );
        let engine = Engine::compile(&catalog(
            Source::ContainerMetadata,
            State::Indication,
            condition,
        ))
        .unwrap();
        for state in ["running", "exited", "created"] {
            let result = engine
                .evaluate(&snapshot(
                    Source::ContainerMetadata,
                    EntityKind::Container,
                    &[(field, &["openclaw"]), (Field::ContainerState, &[state])],
                ))
                .unwrap();
            assert_eq!(result.identifications[0].state, State::Indication);
        }
    }
}

#[test]
fn conjunctions_do_not_mix_different_processes_or_facts() {
    let engine = Engine::compile(&catalog(
        Source::HostProcess,
        State::Executed,
        Expression::All {
            args: vec![
                Expression::Eq {
                    field: Field::Executable,
                    value: "node".into(),
                },
                Expression::Eq {
                    field: Field::ArgumentToken,
                    value: "openclaw".into(),
                },
            ],
        },
    ))
    .unwrap();
    let mut input = snapshot(
        Source::HostProcess,
        EntityKind::Process,
        &[(Field::Executable, &["node"])],
    );
    let mut other = input.facts[0].clone();
    other.id = "fact/2".into();
    other.fields = BTreeMap::from([(Field::ArgumentToken, vec!["openclaw".into()])]);
    input.facts.push(other);
    assert!(engine.evaluate(&input).unwrap().identifications.is_empty());
    input.facts[0]
        .fields
        .insert(Field::ArgumentToken, vec!["openclaw".into()]);
    assert_eq!(engine.evaluate(&input).unwrap().identifications.len(), 1);
}

#[test]
fn full_three_valued_logic_truth_tables() {
    let values = [Truth::False, Truth::Unknown, Truth::True];
    for a in values {
        assert_eq!(a.negate().negate(), a);
        for b in values {
            let and = if a == Truth::False || b == Truth::False {
                Truth::False
            } else if a == Truth::Unknown || b == Truth::Unknown {
                Truth::Unknown
            } else {
                Truth::True
            };
            let or = if a == Truth::True || b == Truth::True {
                Truth::True
            } else if a == Truth::Unknown || b == Truth::Unknown {
                Truth::Unknown
            } else {
                Truth::False
            };
            assert_eq!(Truth::all([a, b].into_iter()), and);
            assert_eq!(Truth::any([a, b].into_iter()), or);
            assert_eq!(
                Truth::all([a, b].into_iter()).negate(),
                Truth::any([a.negate(), b.negate()].into_iter())
            );
        }
    }
}

#[test]
fn each_operator_and_unknown_fields() {
    for expression in [
        Expression::Eq {
            field: Field::Executable,
            value: "openclaw".into(),
        },
        Expression::In {
            field: Field::Executable,
            values: vec!["hermes".into(), "openclaw".into()],
        },
        Expression::Token {
            field: Field::Executable,
            value: "openclaw".into(),
        },
        Expression::Contains {
            field: Field::Executable,
            value: "claw".into(),
        },
        Expression::Regex {
            field: Field::Executable,
            value: "^openclaw$".into(),
        },
        Expression::Any {
            args: vec![Expression::Eq {
                field: Field::Executable,
                value: "openclaw".into(),
            }],
        },
        Expression::Not {
            arg: Box::new(Expression::Eq {
                field: Field::Executable,
                value: "hermes".into(),
            }),
        },
    ] {
        let engine =
            Engine::compile(&catalog(Source::HostProcess, State::Executed, expression)).unwrap();
        assert_eq!(
            engine
                .evaluate(&snapshot(
                    Source::HostProcess,
                    EntityKind::Process,
                    &[(Field::Executable, &["openclaw"])]
                ))
                .unwrap()
                .identifications
                .len(),
            1
        );
        let unknown = engine
            .evaluate(&snapshot(Source::HostProcess, EntityKind::Process, &[]))
            .unwrap();
        assert!(unknown.identifications.is_empty());
        assert_eq!(unknown.unknown_conditions, 1);
    }
}

#[test]
fn malformed_types_images_and_unknown_fields_are_rejected() {
    for input in [
        r#"{"op":"evaluate","catalog":"data:image/png;base64,AA"}"#,
        r#"{"op":"compile","catalog":null}"#,
        r#"{"op":"run"}"#,
        r#"{"op":"compile","catalog":{"version":1,"revision":1,"signatures":[],"exec":"echo"}}"#,
        r#"{"op":[],"catalog":{}}"#,
    ] {
        let output: serde_json::Value =
            serde_json::from_slice(&dispatch(input.as_bytes())).unwrap();
        assert_eq!(output["ok"], false, "{input}");
    }
    assert!(dispatch(&vec![b'a'; MAX_INPUT + 1]).len() < 200);
    for input in [
        r#"{"op":"compile","catalog":{"version":1,"version":2,"revision":1,"signatures":[]}}"#,
        r#"{"op":"compile","op":"evaluate","catalog":{}}"#,
    ] {
        let output: serde_json::Value =
            serde_json::from_slice(&dispatch(input.as_bytes())).unwrap();
        assert_eq!(output["ok"], false);
    }
}

#[test]
fn identities_relations_cycles_and_source_spoofing_are_rejected() {
    let engine = Engine::compile(&process_catalog(Source::HostProcess)).unwrap();
    let valid = snapshot(
        Source::HostProcess,
        EntityKind::Process,
        &[(Field::Executable, &["openclaw"])],
    );
    let mut bad = valid.clone();
    bad.entities.push(bad.entities[0].clone());
    assert!(engine.evaluate(&bad).is_err());
    let mut bad = valid.clone();
    bad.facts.push(bad.facts[0].clone());
    assert!(engine.evaluate(&bad).is_err());
    let mut bad = valid.clone();
    bad.facts[0].entity_id = "other".into();
    assert!(engine.evaluate(&bad).is_err());
    let mut bad = valid.clone();
    bad.facts[0].source = Source::VmFlow;
    assert!(engine.evaluate(&bad).is_err());
    let mut bad = valid.clone();
    bad.facts[0]
        .fields
        .insert(Field::RemoteHost, vec!["api.openai.com".into()]);
    assert!(engine.evaluate(&bad).is_err());
    let mut bad = valid.clone();
    bad.entities.push(Entity {
        display: None,
        id: "other".into(),
        kind: EntityKind::Process,
    });
    bad.relations = vec![
        Relation {
            from: "object/1".into(),
            to: "other".into(),
            kind: RelationKind::Contains,
            source: "fixture".into(),
        },
        Relation {
            from: "other".into(),
            to: "object/1".into(),
            kind: RelationKind::Contains,
            source: "fixture".into(),
        },
    ];
    assert!(engine.evaluate(&bad).is_err());
    let mut next = valid.clone();
    next.entities[0].id = "process/42/start-2".into();
    next.facts[0].entity_id = next.entities[0].id.clone();
    assert_ne!(
        engine.evaluate(&valid).unwrap().identifications[0].entity_id,
        engine.evaluate(&next).unwrap().identifications[0].entity_id
    );
}

#[test]
fn no_raw_response_or_command_values_in_evidence() {
    let engine = Engine::compile(&process_catalog(Source::HostProcess)).unwrap();
    let result = engine
        .evaluate(&snapshot(
            Source::HostProcess,
            EntityKind::Process,
            &[
                (Field::Executable, &["openclaw"]),
                (Field::ArgumentToken, &["fixture-private-token"]),
            ],
        ))
        .unwrap();
    let output = serde_json::to_string(&result).unwrap();
    assert!(!output.contains("fixture-private-token"));
    assert!(output.contains("executable"));
}

#[test]
fn bounded_catalog_regex_and_input_sizes() {
    let mut input = process_catalog(Source::HostProcess);
    input.signatures[0].condition = Expression::Regex {
        field: Field::Executable,
        value: "(a{100000}){100000}".into(),
    };
    assert!(Engine::compile(&input).is_err());
    input.signatures[0].condition = Expression::All { args: vec![] };
    assert!(Engine::compile(&input).is_err());
    input.signatures[0].condition = Expression::Eq {
        field: Field::Package,
        value: "openclaw".into(),
    };
    assert!(Engine::compile(&input).is_err());
    let engine = Engine::compile(&process_catalog(Source::HostProcess)).unwrap();
    let mut input = snapshot(Source::HostProcess, EntityKind::Process, &[]);
    input.facts[0]
        .fields
        .insert(Field::Executable, vec!["x".repeat(1025)]);
    assert!(engine.evaluate(&input).is_err());
    input.facts[0].fields.clear();
    input.facts[0].observed_at = 101;
    assert!(engine.evaluate(&input).is_err());
}

#[test]
fn thousands_of_repeated_evaluations_retain_no_results() {
    let engine = Engine::compile(&process_catalog(Source::HostProcess)).unwrap();
    let input = snapshot(
        Source::HostProcess,
        EntityKind::Process,
        &[(Field::Executable, &["openclaw"])],
    );
    for _ in 0..10_000 {
        let output = engine.evaluate(&input).unwrap();
        assert_eq!(output.identifications.len(), 1);
        assert_eq!(output.evaluated_facts, 1);
    }
}

#[test]
fn indexed_thousand_signatures_evaluate_ten_thousand_processes() {
    let mut catalog = process_catalog(Source::HostProcess);
    let template = catalog.signatures.remove(0);
    for number in 0..1000 {
        let mut signature = template.clone();
        signature.id = format!("fixture/{number}");
        signature.application_id = signature.id.clone();
        signature.condition = Expression::Eq {
            field: Field::Executable,
            value: format!("app-{number}"),
        };
        catalog.signatures.push(signature);
    }
    let engine = Engine::compile(&catalog).unwrap();
    let mut input = snapshot(
        Source::HostProcess,
        EntityKind::Process,
        &[(Field::Executable, &["unrelated"])],
    );
    let template = input.facts.remove(0);
    input.entities.clear();
    for number in 0..10000 {
        let id = format!("process/{number}/start-1");
        input.entities.push(Entity {
            display: None,
            id: id.clone(),
            kind: EntityKind::Process,
        });
        let mut fact = template.clone();
        fact.id = format!("fact/{number}");
        fact.entity_id = id;
        input.facts.push(fact);
    }
    let result = engine.evaluate(&input).unwrap();
    assert_eq!(result.evaluated_facts, 10000);
    assert!(result.identifications.is_empty());
    assert!(engine.evaluate_with_cancel(&input, || true).is_err());
}

#[test]
fn repeated_proofs_and_provider_aliases_do_not_create_duplicate_instances() {
    let engine = Engine::compile(&process_catalog(Source::HostProcess)).unwrap();
    let mut input = snapshot(
        Source::HostProcess,
        EntityKind::Process,
        &[(Field::Executable, &["openclaw"])],
    );
    let mut other = input.facts[0].clone();
    other.id = "fact/2".into();
    input.facts.push(other);
    let result = engine.evaluate(&input).unwrap();
    assert_eq!(result.identifications.len(), 1);
    assert_eq!(result.identifications[0].evidence.len(), 2);
    let input = snapshot(
        Source::VmFlow,
        EntityKind::Vm,
        &[(
            Field::RemoteHost,
            &["api.openai.com", "API.OPENAI.COM", "api.openai.com."],
        )],
    );
    assert_eq!(engine.evaluate(&input).unwrap().communications.len(), 1);
}

#[test]
fn report_pages_minimize_process_inventory_and_keep_verified_ancestors() {
    let catalog = process_catalog(Source::HostProcess);
    let engine = Engine::compile(&catalog).unwrap();
    let mut input = snapshot(
        Source::HostProcess,
        EntityKind::Process,
        &[(Field::Executable, &["openclaw"])],
    );
    input.entities.push(Entity {
        display: None,
        id: "host/1".into(),
        kind: EntityKind::Host,
    });
    input.relations.push(Relation {
        from: "host/1".into(),
        to: "object/1".into(),
        kind: RelationKind::Contains,
        source: "procfs".into(),
    });
    for number in 0..1000 {
        input.entities.push(Entity {
            display: None,
            id: format!("unrelated/{number}"),
            kind: EntityKind::Process,
        });
    }
    let result = engine.evaluate(&input).unwrap();
    let pages = report::pages(&input, &result, catalog.revision, 5).unwrap();
    assert_eq!(pages.len(), 1);
    assert_eq!(pages[0].entities.len(), 2);
    assert_eq!(pages[0].relations.len(), 1);
    report::validate(&pages[0], &catalog).unwrap();
    assert!(
        !serde_json::to_string(&pages)
            .unwrap()
            .contains("unrelated/")
    );
    let mut forged = pages[0].clone();
    forged.result.identifications[0].state = State::InterfaceRecognized;
    assert!(report::validate(&forged, &catalog).is_err());
}

#[test]
fn multi_page_environment_inventory_is_independently_valid() {
    let catalog = Catalog {
        http_paths: default_http_paths(),
        http_ports: default_http_ports(),
        providers: default_providers(),
        version: 1,
        revision: 1,
        signatures: vec![],
    };
    let mut input = snapshot(Source::HostProcess, EntityKind::Process, &[]);
    input.entities.clear();
    input.facts.clear();
    input.entities.push(Entity {
        display: None,
        id: "runtime/1".into(),
        kind: EntityKind::Runtime,
    });
    for number in 0..1000 {
        let id = format!("container/{number}");
        input.entities.push(Entity {
            display: None,
            id: id.clone(),
            kind: EntityKind::Container,
        });
        input.relations.push(Relation {
            from: "runtime/1".into(),
            to: id,
            kind: RelationKind::Contains,
            source: "container-api".into(),
        });
    }
    for number in 0..40 {
        input.coverage.push(Coverage {
            scope: format!("scope/{number}"),
            adapter: "fixture".into(),
            status: CoverageStatus::Available,
            checked_at: 100,
            complete: true,
        });
    }
    let result = Engine::compile(&catalog).unwrap().evaluate(&input).unwrap();
    let pages = report::pages(&input, &result, catalog.revision, 5).unwrap();
    assert!(pages.len() > 1);
    assert_eq!(pages.iter().map(|p| p.coverage.len()).sum::<usize>(), 40);
    for (number, page) in pages.iter().enumerate() {
        assert_eq!(page.page as usize, number);
        assert_eq!(page.pages as usize, pages.len());
        report::validate(page, &catalog).unwrap();
    }
}

#[test]
fn a_hundred_observations_fit_one_request_and_large_proofs_split_by_wire_size() {
    for long in [false, true] {
        let catalog = process_catalog(Source::HostProcess);
        let mut input = snapshot(Source::HostProcess, EntityKind::Process, &[]);
        input.entities.clear();
        input.facts.clear();
        input.entities.push(Entity {
            display: None,
            id: "host/fixture".into(),
            kind: EntityKind::Host,
        });
        for number in 0..100 {
            let id = if long {
                format!("process/{number:0145}")
            } else {
                format!("process/{number}")
            };
            input.entities.push(Entity {
                display: None,
                id: id.clone(),
                kind: EntityKind::Process,
            });
            input.relations.push(Relation {
                from: "host/fixture".into(),
                to: id.clone(),
                kind: RelationKind::Contains,
                source: "procfs".into(),
            });
            for proof in 0..if long { 8 } else { 1 } {
                input.facts.push(Fact {
                    id: if long {
                        format!("fact/{number:0145}/{proof}")
                    } else {
                        format!("fact/{number}/{proof}")
                    },
                    entity_id: id.clone(),
                    source: Source::HostProcess,
                    observed_at: input.observed_at,
                    fields: BTreeMap::from([(Field::Executable, vec!["openclaw".into()])]),
                });
            }
        }
        let result = Engine::compile(&catalog).unwrap().evaluate(&input).unwrap();
        let reports = report::pages(&input, &result, catalog.revision, 1).unwrap();
        if long {
            assert!(reports.len() > 1);
        } else {
            assert_eq!(reports.len(), 1);
        }
        assert_eq!(
            reports
                .iter()
                .map(|report| report.result.identifications.len())
                .sum::<usize>(),
            100
        );
        for page in reports {
            assert!(serde_json::to_vec(&page).unwrap().len() <= 120 * 1024);
            report::validate(&page, &catalog).unwrap();
        }
    }
}

#[test]
fn partial_coverage_cannot_assert_complete_inventory() {
    let mut input = snapshot(Source::HostProcess, EntityKind::Process, &[]);
    input.coverage.push(Coverage {
        scope: "host/1".into(),
        adapter: "fixture".into(),
        status: CoverageStatus::Denied,
        checked_at: 100,
        complete: false,
    });
    assert!(validate_snapshot(&input).is_err());
    input.complete = false;
    validate_snapshot(&input).unwrap();
}

#[test]
fn display_metadata_keeps_real_addresses_and_rejects_wrong_types_and_unbounded_labels() {
    let catalog = catalog(
        Source::Http,
        State::InterfaceRecognized,
        Expression::Contains {
            field: Field::HttpBody,
            value: "Ollama is running".into(),
        },
    );
    let mut input = snapshot(
        Source::Http,
        EntityKind::Endpoint,
        &[(Field::HttpBody, &["Ollama is running"])],
    );
    input.entities[0].display = Some(EntityDisplay {
        name: Some("Local inference".into()),
        address: Some("[::1]:32145".parse().unwrap()),
        image: None,
    });
    let result = Engine::compile(&catalog).unwrap().evaluate(&input).unwrap();
    let pages = report::pages(&input, &result, catalog.revision, 1).unwrap();
    report::validate(&pages[0], &catalog).unwrap();
    assert_eq!(
        pages[0].entities[0]
            .display
            .as_ref()
            .unwrap()
            .address
            .unwrap()
            .port(),
        32145
    );
    for name in ["x".repeat(161), "a\nb".into(), String::new()] {
        input.entities[0].display.as_mut().unwrap().name = Some(name);
        assert!(validate_snapshot(&input).is_err());
    }
    input.entities[0].display.as_mut().unwrap().name = None;
    input.entities[0].display.as_mut().unwrap().image = Some("fixture/image".into());
    assert!(validate_snapshot(&input).is_err());
    input.entities[0].display.as_mut().unwrap().image = None;
    input.entities[0].kind = EntityKind::Host;
    assert!(validate_snapshot(&input).is_err());
    for display in [
        serde_json::json!({"name":{"image":"data:image/png"}}),
        serde_json::json!({"address":"http://127.0.0.1:80/path"}),
        serde_json::json!({"name":"fixture","command":"arbitrary"}),
    ] {
        assert!(serde_json::from_value::<EntityDisplay>(display).is_err());
    }
}

#[test]
fn yaml_candidate_ports_are_bounded_and_do_not_limit_http_recognition_to_default_ports() {
    let mut catalog = catalog(
        Source::Http,
        State::InterfaceRecognized,
        Expression::Eq {
            field: Field::HttpBody,
            value: "Ollama is running".into(),
        },
    );
    catalog.http_ports = vec![32145];
    let input = snapshot(
        Source::Http,
        EntityKind::Endpoint,
        &[(Field::HttpBody, &["Ollama is running"])],
    );
    assert_eq!(
        Engine::compile(&catalog)
            .unwrap()
            .evaluate(&input)
            .unwrap()
            .identifications
            .len(),
        1
    );
    for ports in [vec![0], vec![32145, 32145], (1..=65).collect()] {
        catalog.http_ports = ports;
        assert!(Engine::compile(&catalog).is_err());
    }
    for ports in [
        serde_json::json!([65536]),
        serde_json::json!([-1]),
        serde_json::json!(["32145"]),
        serde_json::json!({"image":"data:image/png"}),
    ] {
        let mut value = serde_json::to_value(&catalog).unwrap();
        value["http_ports"] = ports;
        assert!(serde_json::from_value::<Catalog>(value).is_err());
    }
}

#[test]
fn duplicate_coverage_cannot_overwrite_an_adapter_result() {
    let mut input = snapshot(Source::HostProcess, EntityKind::Process, &[]);
    input.complete = false;
    let coverage = Coverage {
        scope: "host/1".into(),
        adapter: "fixture".into(),
        status: CoverageStatus::Denied,
        checked_at: 100,
        complete: false,
    };
    input.coverage.push(coverage.clone());
    validate_snapshot(&input).unwrap();
    let mut conflicting = coverage;
    conflicting.status = CoverageStatus::Available;
    conflicting.complete = true;
    input.coverage.push(conflicting);
    assert!(validate_snapshot(&input).is_err());
    input.coverage[1].adapter = "independent-adapter".into();
    validate_snapshot(&input).unwrap();
}

#[test]
fn literal_signature_routes_must_be_in_the_http_probe_plan() {
    let mut catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    let original = catalog.http_paths.clone();
    for path in original {
        catalog.http_paths.retain(|candidate| candidate != &path);
        assert!(
            Engine::compile(&catalog).is_err(),
            "catalogue still references the omitted route {path}"
        );
        catalog.http_paths.push(path);
    }
}

#[test]
fn match_saturation_keeps_positive_results_instead_of_failing_the_whole_evaluation() {
    let mut catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    catalog
        .signatures
        .retain(|signature| signature.id == "openclaw.process");
    assert_eq!(catalog.signatures.len(), 1);
    let mut input = snapshot(
        Source::HostProcess,
        EntityKind::Process,
        &[(Field::Executable, &["openclaw"])],
    );
    input.entities.clear();
    input.facts.clear();
    for index in 0..4100 {
        let id = format!("process/{index}");
        input.entities.push(Entity {
            id: id.clone(),
            kind: EntityKind::Process,
            display: None,
        });
        input.facts.push(Fact {
            id: format!("fact/{index}"),
            entity_id: id,
            source: Source::HostProcess,
            observed_at: input.observed_at,
            fields: BTreeMap::from([(Field::Executable, vec!["openclaw".into()])]),
        });
    }
    let output = Engine::compile(&catalog)
        .unwrap()
        .evaluate(&input)
        .expect("output saturation must retain bounded positive evidence");
    assert_eq!(output.identifications.len(), 4096);
    assert_eq!(serde_json::to_value(&output).unwrap()["saturated"], true);
    assert!(serde_json::to_vec(&output).unwrap().len() < MAX_OUTPUT);
    input.complete = true;
    input.coverage.push(Coverage {
        scope: input.scope.clone(),
        adapter: "host".into(),
        status: CoverageStatus::Available,
        checked_at: input.observed_at,
        complete: true,
    });
    let pages = report::pages(&input, &output, catalog.revision, 1).unwrap();
    assert_eq!(
        pages
            .iter()
            .map(|page| page.result.identifications.len())
            .sum::<usize>(),
        4096
    );
    assert!(
        pages
            .iter()
            .all(|page| !page.complete && page.coverage.iter().all(|source| !source.complete))
    );
    assert!(pages.iter().any(|page| {
        page.coverage.iter().any(|source| {
            source.adapter == "detection-engine" && source.status == CoverageStatus::Saturated
        })
    }));
    for page in pages {
        report::validate(&page, &catalog).unwrap();
        assert!(
            !serde_json::to_value(page).unwrap()["result"]
                .as_object()
                .unwrap()
                .contains_key("saturated")
        );
    }
}

#[test]
fn full_factory_keeps_its_routes_when_a_custom_http_application_is_added() {
    let mut catalog: Catalog =
        serde_json::from_slice(include_bytes!("../catalog/factory.json")).unwrap();
    assert_eq!(catalog.http_paths.len(), 16);
    let original = catalog.http_paths.clone();
    let path = "/custom/agent/status";
    let mut signature = catalog
        .signatures
        .iter()
        .find(|row| row.sources.contains(&Source::Http))
        .unwrap()
        .clone();
    signature.id = "fixture-custom-http".into();
    signature.application_id = "fixture-http-agent".into();
    signature.name = "Fixture HTTP agent".into();
    signature.state = State::InterfaceRecognized;
    signature.condition = Expression::All {
        args: vec![
            Expression::Eq {
                field: Field::HttpPath,
                value: path.into(),
            },
            Expression::Contains {
                field: Field::HttpBody,
                value: "fixture-agent-signature".into(),
            },
        ],
    };
    catalog.signatures.push(signature);
    catalog.http_paths.push(path.into());
    let engine = Engine::compile(&catalog)
        .expect("custom routes must not require dropping factory recognition");
    let sample = snapshot(
        Source::Http,
        EntityKind::Endpoint,
        &[
            (Field::HttpPath, &[path]),
            (Field::HttpStatus, &["200"]),
            (Field::HttpBody, &["fixture-agent-signature"]),
            (Field::HttpContentType, &["application/json"]),
        ],
    );
    assert!(
        engine
            .evaluate(&sample)
            .unwrap()
            .identifications
            .iter()
            .any(|row| row.application_id == "fixture-http-agent")
    );
    assert!(
        original
            .iter()
            .all(|path| catalog.http_paths.contains(path))
    );
    while catalog.http_paths.len() < 32 {
        catalog
            .http_paths
            .push(format!("/custom/extra-{}", catalog.http_paths.len()));
    }
    assert!(Engine::compile(&catalog).is_ok());
    catalog.http_paths.push("/custom/excess".into());
    assert!(Engine::compile(&catalog).is_err());
}
