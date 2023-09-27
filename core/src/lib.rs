//! Common functionality for key import and export.

#![forbid(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod encryption;
pub mod version;

extern crate alloc;

/// Version number, ensures that server and client are compatible
const VERSION: u8 = 1;
