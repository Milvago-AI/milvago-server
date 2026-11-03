//! Bounded policy compilation and evaluation, shared by endpoints and server egress.
pub mod language;
pub mod model;
pub mod evaluation;
pub mod consequences;

pub use evaluation::{evaluate, evaluate_large_unit, validate, normalize_dictionaries};
pub use language::{parse, print};
pub use model::*;

pub fn dispatch(bytes: &[u8]) -> Vec<u8> {
    fn operation(bytes: &[u8]) -> Result<serde_json::Value, String> {
        #[derive(serde::Deserialize)]
        #[serde(tag = "op", rename_all = "snake_case", deny_unknown_fields)]
        enum Request {
            Parse { source: String },
            Format { rule: Rule },
            Validate { policy: Policy },
            Normalize { policy: Policy },
            Consequences { policy: Policy, rule: Rule },
            Evaluate { input: Input },
        }
        if bytes.len() > 524288 { return Err("Engine request exceeds the limit".into()); }
        let request: Request = serde_json::from_slice(bytes).map_err(|_| "Invalid engine request")?;
        Ok(match request {
            Request::Parse { source } => { let rule = parse(&source)?; serde_json::json!({"rule":rule,"source":print(&rule)}) }
            Request::Format { rule } => serde_json::json!({"rule":rule,"source":print(&rule)}),
            Request::Validate { policy } => { validate(&policy)?; serde_json::json!({"policy":policy}) }
            Request::Normalize { mut policy } => { normalize_dictionaries(&mut policy)?; serde_json::json!({"policy":policy}) }
            Request::Consequences { policy, rule } => serde_json::json!({"options":consequences::options(&policy,&rule)?}),
            Request::Evaluate { input } => serde_json::json!({"result":evaluate(&input)?}),
        })
    }
    let response = match operation(bytes) {
        Ok(mut value) => { value["ok"] = serde_json::json!(true); value },
        Err(message) => serde_json::json!({"ok":false,"error":message}),
    };
    serde_json::to_vec(&response).unwrap_or_default()
}

#[cfg(target_arch = "wasm32")]
mod wasm {
    #[unsafe(no_mangle)]
    pub extern "C" fn dlp_alloc(length: usize) -> *mut u8 {
        if length > 524288 { return std::ptr::null_mut(); }
        let mut bytes = vec![0u8;length].into_boxed_slice(); let pointer = bytes.as_mut_ptr(); std::mem::forget(bytes); pointer
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn dlp_call(pointer: *mut u8, length: usize) -> u64 {
        if pointer.is_null() || length > 524288 { return 0; }
        let mut input = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer,length)) };
        let mut output = super::dispatch(&input).into_boxed_slice(); input.fill(0);
        let pointer = output.as_mut_ptr(); let length = output.len(); std::mem::forget(output);
        ((length as u64) << 32) | pointer as u64
    }
    #[unsafe(no_mangle)]
    pub unsafe extern "C" fn dlp_free(pointer: *mut u8, length: usize) {
        if !pointer.is_null() && length <= 1048576 {
            let mut bytes = unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer,length)) }; bytes.fill(0);
        }
    }
}
