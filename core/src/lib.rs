//! Common functionality for key import and export.

#![forbid(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

pub mod encryption;

extern crate alloc;

/// Version number, ensures that server and client are compatible
///
/// Version is embedded into the serialized encryption and decryption keys.
/// Incrementing the version will force clients to update the library.
const VERSION: u8 = 1;
