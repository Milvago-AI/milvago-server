//! Bounded evidence evaluation. Collection, network access and policy activation live outside this crate.
pub mod engine;
mod json;
pub mod model;
pub mod report;
pub use engine::{Engine, Truth, provider, validate_snapshot};
pub use model::*;

pub fn dispatch(input: &[u8]) -> Vec<u8> {
    fn operation(input: &[u8]) -> Result<serde_json::Value, String> {
        #[derive(serde::Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
        enum Request {
            Compile {
                catalog: Catalog,
            },
            Evaluate {
                catalog: Catalog,
                snapshot: Snapshot,
            },
            ValidateReport {
                catalog: Catalog,
                report: Report,
            },
        }
        if input.len() > MAX_INPUT {
            return Err("Discovery input exceeds its limit".into());
        }
        json::check(input)?;
        let request: Request =
            serde_json::from_slice(input).map_err(|_| "Invalid discovery input")?;
        match request {
            Request::Compile { catalog } => {
                Engine::compile(&catalog)?;
                Ok(serde_json::json!({"catalog":catalog}))
            }
            Request::Evaluate { catalog, snapshot } => {
                let result = Engine::compile(&catalog)?.evaluate(&snapshot)?;
                Ok(serde_json::json!({"result":result}))
            }
            Request::ValidateReport { catalog, report } => {
                report::validate(&report, &catalog)?;
                Ok(serde_json::json!({"report":report}))
            }
        }
    }
    encode_result(operation(input))
}

// Kept out of the public dispatch operation enum: reports cannot select this path.
// The host must bind a successful full compilation to these exact catalog bytes.
#[cfg(any(target_arch = "wasm32", test))]
fn prevalidated_report(input: &[u8]) -> Vec<u8> {
    fn operation(input: &[u8]) -> Result<serde_json::Value, String> {
        #[derive(serde::Deserialize)]
        #[serde(deny_unknown_fields)]
        struct Request {
            catalog: Catalog,
            report: Report,
        }
        if input.len() > MAX_INPUT {
            return Err("Discovery input exceeds its limit".into());
        }
        json::check(input)?;
        let request: Request = serde_json::from_slice(input).map_err(|_| "Invalid discovery input")?;
        report::validate_prevalidated(&request.report, &request.catalog)?;
        // A status is sufficient for admission; do not copy the report back out.
        Ok(serde_json::json!({}))
    }
    encode_result(operation(input))
}

fn encode_result(result: Result<serde_json::Value, String>) -> Vec<u8> {
    let result = match result {
        Ok(mut output) => {
            output["ok"] = true.into();
            output
        }
        Err(error) => serde_json::json!({"ok":false,"error":error}),
    };
    match serde_json::to_vec(&result) {
        Ok(output) if output.len() <= MAX_OUTPUT => output,
        _ => br#"{"ok":false,"error":"Discovery output exceeds its limit"}"#.to_vec(),
    }
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    #[unsafe(no_mangle)]
    pub extern "C" fn discovery_alloc(length: usize) -> *mut u8 {
        if length == 0 || length > super::MAX_INPUT {
            return std::ptr::null_mut();
        }
        let bytes = vec![0u8; length].into_boxed_slice();
        Box::into_raw(bytes) as *mut u8
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn discovery_call(pointer: *mut u8, length: usize) -> u64 {
        unsafe { call(pointer, length, super::dispatch) }
    }
    /// Trusted-host entry point: the exact catalog must already have passed compile.
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn discovery_call_prevalidated_report(pointer: *mut u8, length: usize) -> u64 {
        unsafe { call(pointer, length, super::prevalidated_report) }
    }
    // Both entry points consume the allocator-owned input exactly once, clear it,
    // and return an output with the same bounded ownership/freeing convention.
    unsafe fn call(pointer: *mut u8, length: usize, dispatch: fn(&[u8]) -> Vec<u8>) -> u64 {
        if pointer.is_null() || length == 0 || length > super::MAX_INPUT {
            return 0;
        }
        let mut input =
            unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length)) };
        let output = dispatch(&input).into_boxed_slice();
        input.fill(0);
        let length = output.len();
        let pointer = Box::into_raw(output) as *mut u8;
        ((length as u64) << 32) | pointer as u64
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn discovery_free(pointer: *mut u8, length: usize) {
        if !pointer.is_null() && length > 0 && length <= super::MAX_OUTPUT {
            let mut bytes =
                unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length)) };
            bytes.fill(0);
        }
    }
}

#[cfg(test)]
mod prevalidated_tests {
    use super::*;
    use serde_json::{Value, json};

    fn fixture() -> (Catalog, Report) {
        // Omitted providers deliberately exercise Catalog's serde defaults.
        let catalog: Catalog = serde_json::from_value(json!({"version":1,"revision":7,
            "http_paths":["/","/health"],"signatures":[
            {"id":"fixture.process","application_id":"fixture","name":"Fixture process","revision":2,
             "sources":["host_process"],"state":"executed","provenance":"synthetic fixture",
             "condition":{"op":"eq","field":"executable","value":"synthetic"}},
            {"id":"fixture.http","application_id":"fixture","name":"Fixture HTTP","revision":3,
             "sources":["http"],"state":"interface_recognized","provenance":"synthetic fixture",
             "condition":{"op":"all_http_responses","args":[
                {"op":"all","args":[{"op":"eq","field":"http_path","value":"/"},{"op":"contains","field":"http_body","value":"alpha"}]},
                {"op":"all","args":[{"op":"eq","field":"http_path","value":"/health"},{"op":"contains","field":"http_body","value":"beta"}]}]}}
        ]})).unwrap();
        let snapshot: Snapshot = serde_json::from_value(json!({"version":1,"scope":"host","sequence":1,
            "observed_at":1000,"complete":true,"relations":[],"coverage":[],
            "entities":[{"id":"host/1","kind":"host"},{"id":"process/1","kind":"process"},{"id":"endpoint/1","kind":"endpoint"}],
            "facts":[
              {"id":"process/fact","entity_id":"process/1","source":"host_process","observed_at":1000,"fields":{"executable":["synthetic"]}},
              {"id":"flow/fact","entity_id":"host/1","source":"host_flow","observed_at":1000,"fields":{"remote_host":["api.openai.com"]}},
              {"id":"dns/fact","entity_id":"host/1","source":"host_dns_query","observed_at":1000,"fields":{"remote_host":["api.openai.com"]}},
              {"id":"http/root","entity_id":"endpoint/1","source":"http","observed_at":1000,"fields":{"http_path":["/"],"http_status":["200"],"http_body":["alpha"]}},
              {"id":"http/health","entity_id":"endpoint/1","source":"http","observed_at":1000,"fields":{"http_path":["/health"],"http_status":["200"],"http_body":["beta"]}}
            ]})).unwrap();
        let engine = Engine::compile(&catalog).unwrap();
        let evaluated = engine.evaluate(&snapshot).unwrap();
        let mut pages = report::pages(&snapshot, &evaluated, catalog.revision, 1).unwrap();
        assert_eq!(pages.len(), 1);
        let page = pages.remove(0);
        assert_eq!(page.result.identifications.len(), 2);
        assert_eq!(page.result.communications.len(), 1);
        assert_eq!(page.result.queries.len(), 1);
        (catalog, page)
    }

    fn agree(catalog: &Catalog, report: &Report, expected: bool) {
        let full = report::validate(report, catalog);
        let prevalidated = report::validate_prevalidated(report, catalog);
        assert_eq!(full, prevalidated);
        assert_eq!(full.is_ok(), expected);
        let input = serde_json::to_vec(&json!({"catalog":catalog,"report":report})).unwrap();
        let reply: Value = serde_json::from_slice(&prevalidated_report(&input)).unwrap();
        assert_eq!(reply["ok"], expected);
        if expected { assert_eq!(reply, json!({"ok":true})); }
    }

    #[test]
    fn prevalidated_reports_keep_every_report_dependent_check() {
        let (catalog, page) = fixture();
        agree(&catalog, &page, true);
        let mut custom = catalog.clone();
        custom.providers = vec![Provider { id:"synthetic_provider".into(), hosts:vec!["synthetic.example".into()] }];
        Engine::compile(&custom).unwrap();
        let mut custom_page=page.clone();
        custom_page.result.communications[0].provider="synthetic_provider".into();
        custom_page.result.queries[0].provider="synthetic_provider".into();
        agree(&custom,&custom_page,true);
        agree(&custom,&page,false);
        for case in 0..22 {
            let mut broken=page.clone();
            match case {
                0=>broken.catalog_revision+=1,
                1=>broken.pages=0,
                2=>broken.page=broken.pages,
                3=>broken.sequence=0,
                4=>broken.entities.push(broken.entities[0].clone()),
                5=>broken.result.identifications[0].signature_id="unknown".into(),
                6=>broken.result.identifications[0].application_id="unknown".into(),
                7=>broken.result.identifications[0].signature_revision+=1,
                8=>broken.result.identifications[0].state=State::Installed,
                9=>broken.result.identifications[0].entity_id="unknown".into(),
                10=>broken.result.identifications[0].evidence.clear(),
                11=>broken.result.identifications.push(broken.result.identifications[0].clone()),
                12=>broken.result.identifications[0].evidence[0].source=Source::Installation,
                13=>broken.result.identifications[0].evidence[0].fields=vec![Field::RemoteHost],
                14=>broken.result.communications[0].provider="unknown".into(),
                15=>broken.result.communications[0].evidence.source=Source::Installation,
                16=>broken.result.communications[0].evidence.fields=vec![Field::Executable],
                17=>broken.result.communications.push(broken.result.communications[0].clone()),
                18=>broken.result.queries[0].provider="unknown".into(),
                19=>broken.result.queries[0].evidence.source=Source::HostFlow,
                20=>broken.result.queries.push(broken.result.queries[0].clone()),
                _=>broken.result.queries[0].entity_id="process/1".into(),
            }
            agree(&catalog,&broken,false);
        }
        for case in 0..4 {
            let mut broken=page.clone();
            let row=broken.result.identifications.iter_mut().find(|row|row.signature_id=="fixture.http").unwrap();
            match case {
                0=>{row.evidence.pop();},
                1=>row.evidence[1].fact_id=row.evidence[0].fact_id.clone(),
                2=>row.evidence[0].fields.retain(|field|*field!=Field::HttpPath),
                _=>row.evidence[0].observed_at=939,
            }
            agree(&catalog,&broken,false);
        }
    }

    #[test]
    fn public_report_validation_still_compiles_catalog_and_rejects_fast_operation_names() {
        let (mut catalog, page)=fixture();
        catalog.signatures[0].condition=Expression::Regex {field:Field::Executable,value:"[".into()};
        assert!(report::validate(&page,&catalog).is_err());
        let public=json!({"op":"validate_report","catalog":catalog,"report":page});
        let reply:Value=serde_json::from_slice(&dispatch(&serde_json::to_vec(&public).unwrap())).unwrap();
        assert_eq!(reply["ok"],false);
        for op in ["validate_report_prevalidated","prevalidated_report"] {
            let mut request=public.clone();request["op"]=json!(op);
            let reply:Value=serde_json::from_slice(&dispatch(&serde_json::to_vec(&request).unwrap())).unwrap();
            assert_eq!(reply["ok"],false);
        }
    }

    #[test]
    fn trusted_export_input_is_strict_and_bounded_before_report_validation() {
        let (catalog,page)=fixture();
        let input=json!({"catalog":catalog,"report":page});
        for case in 0..6 {
            let mut broken=input.clone();
            match case {
                0=>broken["op"]=json!("validate_report_prevalidated"),
                1=>broken["catalog"]=json!(["data:image/png"]),
                2=>broken["report"]=json!("data:image/png"),
                3=>broken["report"]["sequence"]=json!({"image":"png"}),
                4=>broken["report"]["unexpected"]=json!(true),
                _=>broken["catalog"]["unexpected"]=json!(true),
            }
            let reply:Value=serde_json::from_slice(&prevalidated_report(&serde_json::to_vec(&broken).unwrap())).unwrap();
            assert_eq!(reply["ok"],false);
        }
        for input in [b"{\"catalog\":{},\"catalog\":{},\"report\":{}}".to_vec(), vec![b' ';MAX_INPUT+1], b"null".to_vec()] {
            let reply:Value=serde_json::from_slice(&prevalidated_report(&input)).unwrap();
            assert_eq!(reply["ok"],false);
        }
    }
}
