//! Client code for the key-export functionality.
//!
//! Customers can use the KeyExportContext struct and its methods
//! to build a key-export request, which then can be sent to
//! the Dfns API, and to parse the response and extract the private
//! key of a specified wallet.

#![forbid(missing_docs)]
#![no_std]

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};

use generic_ec::{curves::Secp256k1, Curve, NonZero, Point, Scalar, SecretScalar};

use dfns_key_export_common::{
    KeyCurve, KeyExportRequest, KeyExportResponse, KeyProtocol, KeySharePlaintext, SupportedScheme,
};
use rand_core::{self, RngCore};

const SUPPORTED_SCHEMES: [SupportedScheme; 1] = [SupportedScheme {
    protocol: KeyProtocol::Cggmp21,
    curve: KeyCurve::Secp256k1,
}];

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

// We are using KeyExportContext and the returned ErrorType in `tests/integration.rs` of the
// `dfns-signer-tests` package. As JsError::new() is not suported in non-wasm32 architectures,
// this code is compiled to return a KeyExportError in non-wasm32 architectures
// and a JsError in wasm32 architecture.
#[cfg(target_arch = "wasm32")]
type ErrorType = JsError;
#[cfg(not(target_arch = "wasm32"))]
type ErrorType = KeyExportError;

/// Secret key to be exported
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SecretKey(generic_ec::SecretScalar<Secp256k1>);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SecretKey {
    /// Serializes the secret key in big-endian format.
    pub fn to_bytes_be(secret_key: SecretKey) -> Vec<u8> {
        secret_key.0.as_ref().to_be_bytes().to_vec()
    }
}

/// This class can be used to generate an encryption/decryption key pair,
/// create a key-export request (which needs to be forwarded to the Dfns API),
/// and parse the response of the Dfns API to extract the key of a wallet.
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct KeyExportContext {
    decryption_key: dfns_encryption::DecryptionKey,
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
            decryption_key: dfns_encryption::DecryptionKey::generate(&mut rng),
        })
    }

    /// Returns a request body that needs to be sent to Dfns API in order to
    /// export the key of the wallet with the given `wallet_id`.
    ///
    /// Throws `Error` in case of failure.
    pub fn build_key_export_request(&self, wallet_id: String) -> Result<String, ErrorType> {
        let req = KeyExportRequest {
            wallet_id,
            supported_schemes: Vec::from(SUPPORTED_SCHEMES),
            encryption_key: self.decryption_key.encryption_key().to_bytes().to_vec(),
        };
        serde_json::to_string(&req).context("cannot serialize key-export request")
    }

    /// Parses the response from Dfns API and recovers the private key.
    ///
    /// It returns the private key as a big endian byte array,
    /// or an `Error` (if the private key cannot be recovered,
    /// or is recovered but doesn’t match the public_key).
    pub fn recover_secret_key(&self, response: String) -> Result<SecretKey, ErrorType> {
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

        // Depending on the protocol/curve combination, parse key_shares and public_key,
        // perform the interpolation, and return the private key.
        let secret_key = match (response.protocol, response.curve) {
            (KeyProtocol::Cggmp21, KeyCurve::Secp256k1) => {
                let key_shares = parse_key_shares::<Secp256k1>(&decrypted_key_shares)
                    .context("cannot parse the public key")?;
                let public_key = Point::<Secp256k1>::from_bytes(&response.public_key)
                    .context("cannot parse a decrepted secret-key share")?;
                interpolate_secret_key::<Secp256k1>(&key_shares, &public_key)
                    .context("interpolation failed")?
            }
            (_, _) => {
                return Err(new_error("the combination of protocol and curve for this key is not supported for key export"));
            }
        };
        Ok(SecretKey(secret_key))
    }
}

/// Parse a collection of decrepted shares as a vector of``KeySharePlaintext<E>``.
fn parse_key_shares<E: Curve>(
    key_shares: &[Vec<u8>],
) -> Result<Vec<KeySharePlaintext<E>>, serde_json::Error> {
    key_shares
        .iter()
        .map(|share| serde_json::from_slice(share))
        .collect::<Result<Vec<KeySharePlaintext<E>>, _>>()
}

/// Perform interpolation.
///
/// In the end it verifies the computed key against the provided
/// public key and returns an error if it doesn't match.
pub fn interpolate_secret_key<E: Curve>(
    key_shares: &[KeySharePlaintext<E>],
    public_key: &Point<E>,
) -> Result<SecretScalar<E>, InterpolateKeyError> {
    // Validate input
    let n = key_shares.len();
    if n <= 1 {
        return Err(InterpolateKeyError::NotEnoughShares);
    };

    // Extract evaluation indexes and secret-share values
    let indexes = key_shares
        .iter()
        .map(|s| s.index)
        .collect::<Vec<NonZero<_>>>();
    let secret_shares = key_shares.iter().map(|s| (s.secret_share.clone()));

    // Interpolate
    let mut interpolated_secret_key = {
        let lagrange_coefs = (0..n)
            .map(|j| generic_ec_zkp::polynomial::lagrange_coefficient(Scalar::zero(), j, &indexes));
        lagrange_coefs
            .zip(secret_shares)
            .map(|(lambda_j, share)| Some(lambda_j? * &share))
            .try_fold(Scalar::zero(), |acc, p_i| Some(acc + p_i?))
            .ok_or(InterpolateKeyError::MalformedIndexes)?
    };

    // Compute the public key that corresponds to the interpolated secret key
    // and check whether it matches the given one.
    if Point::generator() * interpolated_secret_key != *public_key {
        return Err(InterpolateKeyError::CannotVerifySecretKey);
    }

    Ok(SecretScalar::new(&mut interpolated_secret_key))
}

/// Structure to describe errors in interpolate_secret_key()
#[derive(Debug)]
pub enum InterpolateKeyError {
    /// Input to interpolate_secret_key() contains not enough shares
    NotEnoughShares,
    /// Internal error. Largange coefficient for zero index
    ZeroIndex,
    /// Internal error. Malformed indexes at secret reconstruction
    MalformedIndexes,
    /// The interpolated secret key cannot be verified against the provided public key
    CannotVerifySecretKey,
}

/// Structure to describe errors in interpolate_secret_key
impl core::fmt::Display for InterpolateKeyError {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        let msg = match self {
            InterpolateKeyError::NotEnoughShares => "not enough shares given as input",
            InterpolateKeyError::ZeroIndex => "index is zero when it's suppposed to be non-zero",
            InterpolateKeyError::MalformedIndexes => "malformed share indexes",
            InterpolateKeyError::CannotVerifySecretKey => "the interpolated secret key cannot be verified against the provided public key (the secret key shares or the public key are invalid",
        };
        f.write_str(msg)
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
    ErrorType::new(ctx)
}

/// Error type to be returned on non-wasm32 arch.
#[derive(Debug)]
pub struct KeyExportError {
    desc: String,
}

impl KeyExportError {
    #[allow(dead_code)]
    fn new(s: &str) -> Self {
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
