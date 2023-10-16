use alloc::string::{String, ToString};
use dfns_key_export_common::{KeyExportRequest, KeyExportResponse};

/// Key-export request type (sent to Dfns API) to be used on non-wasm32 arch.
pub type Request = KeyExportRequest;
/// Key-export response type (returned from Dfns API)
/// to be used as input in `recover_secret_key()` on non-wasm32 arch.
pub type Response = KeyExportResponse;
/// Error type to be used on non-wasm32 arch.
pub type Error = KeyExportError;

/// Format a `KeyExportRequest` as type `Request`
/// (which is `KeyExportRequest` on non-wasm32 arch).
pub fn format_request(req: KeyExportRequest) -> Result<Request, Error> {
    Ok(req)
}

/// Parse a type `Reponse` (which is `KeyExportResponse` on non-wasm32 arch)
/// as a `KeyExportResponse`.
pub fn parse_response(resp: Response) -> Result<KeyExportResponse, Error> {
    Ok(resp)
}

/// Error type on non-wasm32 arch is KeyExportError.
#[derive(Debug)]
pub struct KeyExportError {
    desc: String,
}

impl KeyExportError {
    #[allow(dead_code)]
    pub fn new(s: &str) -> Self {
        KeyExportError {
            desc: s.to_string(),
        }
    }
}

impl core::fmt::Display for KeyExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.desc)
    }
}
