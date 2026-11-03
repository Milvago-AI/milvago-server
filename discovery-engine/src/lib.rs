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
    let result = match operation(input) {
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
        if pointer.is_null() || length == 0 || length > super::MAX_INPUT {
            return 0;
        }
        let mut input =
            unsafe { Box::from_raw(std::ptr::slice_from_raw_parts_mut(pointer, length)) };
        let output = super::dispatch(&input).into_boxed_slice();
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
