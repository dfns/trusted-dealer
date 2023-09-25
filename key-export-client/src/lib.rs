//! Client code for the key-export functionality.
//!
//! Customers can use the KeyExportContext struct and its methods
//! to build a key-export request, which then can be sent to
//! the Dfns API, and to parse the response and extract the secret
//! key of a specified wallet.

#![forbid(missing_docs)]
#![no_std]

extern crate alloc;

use alloc::{string::String, vec::Vec};

use dfns_key_import_common::encryption::DecryptionKey;
use generic_ec::curves::Secp256k1;

use dfns_key_export_common::{
    KeyCurve, KeyExportRequest, KeyExportResponse, KeyProtocol, SupportedScheme,
};
use rand_core::{self, RngCore};

const SUPPORTED_SCHEMES: [SupportedScheme; 1] = [SupportedScheme {
    protocol: KeyProtocol::Cggmp21,
    curve: KeyCurve::Secp256k1,
}];

// We are using KeyExportContext and the returned ErrorType in `tests/integration.rs` of the
// `dfns-signer-tests` package. As JsError::new() is not suported in non-wasm32 architectures,
// this code is compiled to return a KeyExportError in non-wasm32 architectures
// and a JsError in wasm32 architecture.

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;
#[cfg(target_arch = "wasm32")]
type ErrorType = JsError;

#[cfg(not(target_arch = "wasm32"))]
type ErrorType = KeyExportError;

/// This class can be used to generate an encryption/decryption key pair,
/// create a key-export request (which needs to be forwarded to the Dfns API),
/// and parse the response of the Dfns API to extract the key of a wallet.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct KeyExportContext {
    decryption_key: DecryptionKey,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl KeyExportContext {
    /// Generates a new encryption/decryption key pair.
    ///
    /// Requires a global secure randomness generator to be available, that can be either [Web Crypto API]
    /// or [Node JS crypto module]. If neither of them is available, throws `Error`.
    ///
    /// [Web Crypto API]: https://www.w3.org/TR/WebCryptoAPI/
    /// [Node JS crypto module]: https://nodejs.org/api/crypto.html
    ///
    /// Throws `Error` in case of failure.
    pub fn new() -> Result<KeyExportContext, ErrorType> {
        let mut rng = rand_core::OsRng;
        // Sample random 10 bytes to see that CSPRNG is available
        let mut sample = [0u8; 10];
        rng.try_fill_bytes(&mut sample)
            .context("cryptographic randomness generator is not available")?;

        Ok(KeyExportContext {
            decryption_key: DecryptionKey::generate(&mut rng),
        })
    }

    /// Returns a request body that needs to be sent to Dfns API in order to
    /// export the key of the wallet with the given `wallet_id`,
    pub fn build_key_export_request(&self, wallet_id: String) -> Result<String, ErrorType> {
        let req = KeyExportRequest {
            wallet_id,
            supported_schemes: Vec::from(SUPPORTED_SCHEMES),
            encryption_key: self.decryption_key.encryption_key().to_bytes().to_vec(),
        };
        serde_json::to_string(&req).context("cannot serialize key-export request")
    }

    /// Parse the response from Dfns API and recover the secret key.
    /// The functions returns the secret key in big-endian format.
    pub fn recover_secret_key(&self, response: String) -> Result<Vec<u8>, ErrorType> {
        // Parse response
        let response: KeyExportResponse =
            serde_json::from_str(&response).context("cannot parse key-export response")?;
        // Parse and validate fields
        let min_signers: u16 = response
            .min_signers
            .try_into()
            .context("min_signers overflows u16")?;
        let n: u16 = response
            .encrypted_shares
            .len()
            .try_into()
            .context("length of key_holders overflows u16")?;
        if !(2 <= min_signers && min_signers <= n) {
            return Err(new_error(
                "threshold doesn't meet requirements: 2 <= min_signers <= n",
            ));
        };

        // Decrypt key shares
        let decrypted_key_shares = response
            .encrypted_shares
            .iter()
            .map(|share| {
                let mut buffer = share.encrypted_key_share.clone();
                self.decryption_key
                    .decrypt(&[], &mut buffer)
                    .context("cannot decrypt a key share from key-export response")?;
                Ok(buffer)
            })
            .collect::<Result<Vec<_>, ErrorType>>()?;
        // decrypted_key_shares is a vector of decrypted but serialized KeySharePlaintext<E>

        // Depending on the protocol/curve combination, call the appropriate version of
        // interpolate_secret_key() and extract the secret key.
        let secret_key = match (response.protocol, response.curve) {
            (KeyProtocol::Cggmp21, KeyCurve::Secp256k1) => {
                dfns_key_export_common::interpolate_secret_key::<Secp256k1>(
                    &decrypted_key_shares,
                    &response.public_key,
                )
                .context("interpolation failed")?
            }
            (_, _) => {
                return Err(new_error("the combination of protocol and curve for this key is not supported for key export"));
            } // ed25519_dalek::PublicKey::from_bytes(public_key).context("invalid public key")?;
              // Point::from_bytes(&response.public_key).context("invalid public key")?
        };

        Ok(secret_key.as_ref().to_be_bytes().to_vec())
    }
}

trait Context<T, E> {
    fn context(self, ctx: &str) -> Result<T, ErrorType>;
}

impl<T, E> Context<T, E> for Result<T, E>
where
    E: core::fmt::Display,
{
    fn context(self, ctx: &str) -> Result<T, ErrorType> {
        self.map_err(|e| ErrorType::new(&alloc::format!("{ctx}: {e}")))
    }
}

fn new_error(ctx: &str) -> ErrorType {
    ErrorType::new(&alloc::format!("{ctx}"))
}

/// Error type to be returned on non-wasm32 arch.
#[derive(Debug)]
pub struct KeyExportError {
    desc: String,
}

impl KeyExportError {
    fn new(s: &str) -> Self {
        KeyExportError {
            desc: alloc::string::ToString::to_string(&s),
        }
    }
}

impl core::fmt::Display for KeyExportError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str(&self.desc)
    }
}
