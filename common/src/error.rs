//! Anyhow-like error type for JS code
//!
//! The error type can be casted to `wasm_bindgen::JsError` on wasm target,
//! which is convenient to use in wasm code

use core::fmt;

/// Error type
#[derive(Debug)]
pub struct Error {
    desc: alloc::string::String,
}

impl Error {
    /// Constructs an error
    pub fn new(desc: &str) -> Self {
        Self { desc: desc.into() }
    }
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.desc)
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(err: Error) -> Self {
        wasm_bindgen::JsError::new(&err.desc).into()
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

/// Adds context to an error
pub trait Context<T, E> {
    /// Adds context to an error
    fn context(self, ctx: &str) -> Result<T, Error>;
}

impl<T, E> Context<T, E> for Result<T, E>
where
    E: core::fmt::Display,
{
    fn context(self, ctx: &str) -> Result<T, Error> {
        self.map_err(|e| Error::new(&alloc::format!("{ctx}: {e}")))
    }
}

impl<T> Context<T, core::convert::Infallible> for Option<T> {
    fn context(self, ctx: &str) -> Result<T, Error> {
        self.ok_or_else(|| Error::new(ctx))
    }
}
