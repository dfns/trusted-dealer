use dfns_key_export_common::{KeyExportRequest, KeyExportResponse};
use wasm_bindgen::{JsError, JsValue};

use crate::Context;

/// Key-export request type (sent to Dfns API) to be used on wasm32 arch.
pub type Request = JsValue;
/// Key-export response type (returned from Dfns API)
/// to be used as input in `recover_secret_key()` on wasm32 arch.
pub type Response = JsValue;
/// Error type to be used on wasm32 arch.
pub type Error = JsError;

/// Format a `KeyExportRequest` as type `Request`
/// (which is `JsValue` on wasm32 arch).
pub fn format_request(req: KeyExportRequest) -> Result<Request, Error> {
    serde_wasm_bindgen::to_value(&req).context("cannot serialize key-export request")
}

/// Parse a type `Reponse` (which is `JsValue` on wasm32 arch)
/// as a `KeyExportResponse`.
pub fn parse_response(resp: Response) -> Result<KeyExportResponse, Error> {
    serde_wasm_bindgen::from_value(resp).context("cannot parse key-export response")
}
