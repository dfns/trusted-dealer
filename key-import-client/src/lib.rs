//! Dfns Key Import SDK
//!
//! Provides a basic functionality to split the secret key to be imported into key shares
//! at customer side, encrypt them and build a key import request that needs to be sent
//! to Dfns API.

#![forbid(missing_docs)]
#![no_std]

extern crate alloc;

use alloc::vec::Vec;

use common::KeyImportRequest;
use dfns_trusted_dealer_core::types::{KeyCurve, KeyProtocol};
use wasm_bindgen::prelude::*;

use dfns_key_import_common::{
    self as common,
    generic_ec::{self, curves::Secp256k1},
    rand_core::{self, RngCore},
};

/// Signers info
///
/// Contains information necessary to establish a secure communication channel with
/// the signers who're going to host the imported key
#[wasm_bindgen]
pub struct SignersInfo(common::SignersInfo);

#[wasm_bindgen]
impl SignersInfo {
    /// Parses signers info from response obtained from Dfns API
    ///
    /// Throws `Error` if response is malformed
    pub fn from_response(resp: &[u8]) -> Result<SignersInfo, JsError> {
        let info = serde_json::from_slice(resp).context("couldn't parse the response")?;
        Ok(Self(info))
    }
}

/// Secret key to be imported
#[wasm_bindgen]
pub struct SecretKey(generic_ec::SecretScalar<Secp256k1>);

#[wasm_bindgen]
impl SecretKey {
    /// Parses the secret key in big-endian format (the most widely-used format)
    ///
    /// Throws `Error` if secret key is invalid
    pub fn from_bytes_be(bytes: &[u8]) -> Result<SecretKey, JsError> {
        let scalar = generic_ec::SecretScalar::from_be_bytes(bytes)
            .context("couldn't parse the secret key")?;
        Ok(Self(scalar))
    }
}

/// Builds a request body that needs to be sent to Dfns API in order to import given key
///
/// Takes a secret key to be imported, and signers info (needs to be retrieved from Dfns API). Returns
/// a body of the request that needs to be sent to Dfns API in order to import given key
///
/// Requires a global secure randomness generator to be available, that can be either [Web Crypto API]
/// or [Node JS crypto module]. If neither of them is available, throws `Error`.
///
/// [Web Crypto API]: https://www.w3.org/TR/WebCryptoAPI/
/// [Node JS crypto module]: https://nodejs.org/api/crypto.html
///
/// Throws `Error` in case of failure
#[wasm_bindgen]
pub fn build_key_import_request(
    signers_info: &SignersInfo,
    secret_key: &SecretKey,
) -> Result<Vec<u8>, JsError> {
    let mut rng = rand_core::OsRng;

    {
        // Sample random 10 bytes to see that CSPRNG is available
        let mut sample = [0u8; 10];
        rng.try_fill_bytes(&mut sample)
            .map_err(|_| JsError::new("cryptographic randomness generator is not available"))?;
    }

    // Split the secret key into the shares
    let key_shares = common::split_secret_key(&mut rng, 3, 5, &secret_key.0)
        .context("failed to split secret key into key shares")?;

    // Serialize each share
    let key_shares = key_shares
        .into_iter()
        .map(|k| serde_json::to_vec(&k))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| JsError::new("couldn't serialize a key share"))?;

    // Encrypt each share with corresponding signer encryption key
    let encrypted_key_shares = signers_info
        .0
        .signers()
        .iter()
        .zip(key_shares)
        .map(|(recipient, mut key_share)| {
            recipient
                .encryption_key
                .encrypt(&mut rng, &[], &mut key_share)?;
            Ok(common::KeyShareCiphertext {
                encrypted_key_share: key_share,
                signer_id: recipient.signer_id.clone(),
            })
        })
        .collect::<Result<Vec<_>, dfns_trusted_dealer_core::encryption::Error>>()
        .map_err(|_| JsError::new("couldn't encrypt a key share"))?;

    // Build a request and serialize it
    let req = KeyImportRequest {
        min_signers: 3,
        protocol: KeyProtocol::Cggmp21,
        curve: KeyCurve::Secp256k1,
        encrypted_key_shares,
    };
    serde_json::to_vec(&req).context("serialize a request")
}

trait Context<T, E> {
    fn context(self, ctx: &str) -> Result<T, JsError>;
}

impl<T, E> Context<T, E> for Result<T, E>
where
    E: core::fmt::Display,
{
    fn context(self, ctx: &str) -> Result<T, JsError> {
        self.map_err(|e| JsError::new(&alloc::format!("{ctx}: {e}")))
    }
}
