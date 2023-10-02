use alloc::string::{String, ToString};
use dfns_key_export_common::KeyExportRequest;

/// Key-export request type to be returned on non-wasm32 arch.
pub type RequestType = KeyExportRequest;
/// Error type to be returned on non-wasm32 arch.
pub type ErrorType = KeyExportError;

/// Key-export request type on non-wasm32 arch is KeyExportRequest.
pub fn format_request(req: KeyExportRequest) -> Result<RequestType, ErrorType> {
    Ok(req)
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
