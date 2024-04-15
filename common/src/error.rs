//! Anyhow-like error type for JS code
//!
//! The error type can be casted to `wasm_bindgen::JsError` on wasm target,
//! which is convenient to use in wasm code

use core::fmt;

/// Error type
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct Error {
    desc: alloc::string::String,
}

#[cfg(not(target_arch = "wasm32"))]
impl Error {
    /// Constructs an error
    pub fn new(desc: &str) -> Self {
        Self { desc: desc.into() }
    }
}

#[cfg(not(target_arch = "wasm32"))]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.desc)
    }
}

/// Error type
#[cfg(target_arch = "wasm32")]
pub struct Error(wasm_bindgen::JsError);

#[cfg(target_arch = "wasm32")]
impl Error {
    /// Constructs an error
    pub fn new(desc: &str) -> Self {
        Self(wasm_bindgen::JsError::new(desc))
    }
}

#[cfg(target_arch = "wasm32")]
impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("JsError")
    }
}

#[cfg(target_arch = "wasm32")]
impl From<Error> for wasm_bindgen::JsValue {
    fn from(err: Error) -> Self {
        err.0.into()
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
