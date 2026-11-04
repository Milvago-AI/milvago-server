use milvago_discovery_engine::*;
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicIsize, Ordering};

struct CountingAllocator;
static LIVE: AtomicIsize = AtomicIsize::new(0);
unsafe impl GlobalAlloc for CountingAllocator {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let pointer = unsafe { System.alloc(layout) };
        if !pointer.is_null() {
            LIVE.fetch_add(layout.size() as isize, Ordering::Relaxed);
        }
        pointer
    }
    unsafe fn dealloc(&self, pointer: *mut u8, layout: Layout) {
        LIVE.fetch_sub(layout.size() as isize, Ordering::Relaxed);
        unsafe { System.dealloc(pointer, layout) };
    }
    unsafe fn realloc(&self, pointer: *mut u8, old: Layout, size: usize) -> *mut u8 {
        let result = unsafe { System.realloc(pointer, old, size) };
        if !result.is_null() {
            LIVE.fetch_add(size as isize - old.size() as isize, Ordering::Relaxed);
        }
        result
    }
}
#[global_allocator]
static ALLOCATOR: CountingAllocator = CountingAllocator;

#[test]
fn live_allocations_return_to_baseline_on_success_and_error() {
    let good = br#"{"op":"evaluate","catalog":{"version":1,"revision":1,"signatures":[{"id":"fixture","application_id":"fixture","name":"Fixture","revision":1,"sources":["host_process"],"state":"executed","condition":{"op":"eq","field":"executable","value":"fixture"},"provenance":"fixture"}]},"snapshot":{"version":1,"scope":"host/boot","sequence":1,"observed_at":1,"complete":true,"entities":[{"id":"p/1/start-1","kind":"process"}],"facts":[{"id":"f/1","entity_id":"p/1/start-1","source":"host_process","observed_at":1,"fields":{"executable":["fixture"]}}],"relations":[],"coverage":[]}}"#;
    let cases: &[&[u8]] = &[
        good,
        b"{",
        br#"{"op":"compile","catalog":null}"#,
        br#"{"op":"compile","catalog":{"version":1,"revision":1,"signatures":[],"version":2}}"#,
    ];
    let request: serde_json::Value = serde_json::from_slice(good).unwrap();
    let catalog: Catalog = serde_json::from_value(request["catalog"].clone()).unwrap();
    let snapshot: Snapshot = serde_json::from_value(request["snapshot"].clone()).unwrap();
    let result = Engine::compile(&catalog)
        .unwrap()
        .evaluate(&snapshot)
        .unwrap();
    let page = report::pages(&snapshot, &result, 1, 1).unwrap().remove(0);
    let validation = serde_json::to_vec(
        &serde_json::json!({"op":"validate_report","catalog":catalog,"report":page}),
    )
    .unwrap();
    let mut invalid: serde_json::Value = serde_json::from_slice(&validation).unwrap();
    invalid["report"]["result"]["identifications"][0]["evidence"][0]["source"] =
        serde_json::json!("vm_flow");
    let invalid = serde_json::to_vec(&invalid).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&dispatch(&validation)).unwrap()["ok"],
        true
    );
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&dispatch(&invalid)).unwrap()["ok"],
        false
    );
    let mut dns_request = request.clone();
    dns_request["snapshot"]["entities"][0]["kind"] = "host".into();
    dns_request["snapshot"]["facts"][0]["source"] = "host_dns_query".into();
    dns_request["snapshot"]["facts"][0]["fields"] =
        serde_json::json!({"remote_host":["api.openai.com"]});
    let dns_request = serde_json::to_vec(&dns_request).unwrap();
    let dns_output: serde_json::Value = serde_json::from_slice(&dispatch(&dns_request)).unwrap();
    assert_eq!(dns_output["result"]["queries"].as_array().unwrap().len(), 1);
    assert!(
        dns_output["result"]["communications"]
            .as_array()
            .unwrap()
            .is_empty()
    );
    let cases = [
        cases,
        &[
            validation.as_slice(),
            invalid.as_slice(),
            dns_request.as_slice(),
        ],
    ]
    .concat();
    let mut http = request.clone();
    http["catalog"]["http_paths"] = serde_json::json!(["/", "/health"]);
    http["catalog"]["signatures"][0]["sources"] = serde_json::json!(["http"]);
    http["catalog"]["signatures"][0]["state"] = "interface_recognized".into();
    http["catalog"]["signatures"][0]["condition"] = serde_json::json!({"op":"all_http_responses","args":[
        {"op":"all","args":[{"op":"eq","field":"http_path","value":"/"},{"op":"contains","field":"http_body","value":"alpha"}]},
        {"op":"all","args":[{"op":"eq","field":"http_path","value":"/health"},{"op":"contains","field":"http_body","value":"beta"}]}]});
    http["snapshot"]["entities"][0]["kind"] = "endpoint".into();
    http["snapshot"]["facts"][0]["source"] = "http".into();
    http["snapshot"]["facts"][0]["fields"] =
        serde_json::json!({"http_path":["/"],"http_status":["200"],"http_body":["alpha"]});
    let mut second = http["snapshot"]["facts"][0].clone();
    second["id"] = "response/second".into();
    second["fields"] =
        serde_json::json!({"http_path":["/health"],"http_status":["200"],"http_body":["beta"]});
    http["snapshot"]["facts"]
        .as_array_mut()
        .unwrap()
        .push(second);
    let http_good = serde_json::to_vec(&http).unwrap();
    let result: serde_json::Value = serde_json::from_slice(&dispatch(&http_good)).unwrap();
    assert_eq!(
        result["result"]["identifications"]
            .as_array()
            .unwrap()
            .len(),
        1
    );
    http["catalog"]["signatures"][0]["condition"]["args"][1]["args"][0]["value"] = "/".into();
    let http_bad = serde_json::to_vec(&http).unwrap();
    assert_eq!(
        serde_json::from_slice::<serde_json::Value>(&dispatch(&http_bad)).unwrap()["ok"],
        false
    );
    let cases = [cases, vec![http_good.as_slice(), http_bad.as_slice()]].concat();
    for input in &cases {
        drop(dispatch(input));
    }
    let baseline = LIVE.load(Ordering::SeqCst);
    for _ in 0..10_000 {
        for input in &cases {
            let output = dispatch(input);
            assert!(!output.is_empty());
            drop(output);
        }
    }
    assert_eq!(
        LIVE.load(Ordering::SeqCst),
        baseline,
        "retained allocations after repeated success/error cycles"
    );
}
