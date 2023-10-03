use dfns_key_export_common::KeyExportRequest;
use wasm_bindgen::{JsError, JsValue};

use crate::Context;

/// Key-export request type to be returned on non-wasm32 arch.
pub type Request = JsValue;
/// Error type to be returned on non-wasm32 arch.
pub type Error = JsError;

/// Key-export request type on non-wasm32 arch is JsValue.
pub fn format_request(req: KeyExportRequest) -> Result<Request, Error> {
    serde_wasm_bindgen::to_value(&req).context("cannot serialize key-export request")
}