//! Encryption scheme for key import and export.
//!
//! This library implements a public-key encryption scheme
//! used in the key-export and key-import functionallities.

#![forbid(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub mod encryption;

/// Version number, ensures that server and client are compatible
///
/// Version is embedded into the serialized encryption and decryption keys.
/// Incrementing the version will force clients to update the library.
const VERSION: u8 = 1;
