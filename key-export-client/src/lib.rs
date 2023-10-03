//! Client code for the key-export functionality.
//!
//! Customers can use the KeyExportContext struct and its methods
//! to build a key-export request, which then can be sent to
//! the Dfns API, and to parse the response and extract the private
//! key of a specified wallet.

#![forbid(missing_docs)]
#![no_std]

// Because JsValue is not suported in non-wasm32 architectures,
// this code is compiled to return a different error type and
// request type in wasm32 and non-wasm32 architectures.
#[cfg_attr(target_arch = "wasm32", path = "types/wasm32.rs")]
#[cfg_attr(not(target_arch = "wasm32"), path = "types/others.rs")]
mod types;

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::*;

extern crate alloc;

use alloc::{
    string::{String, ToString},
    vec::Vec,
};
use base64::{engine::general_purpose, Engine as _};
use rand_core::{self, RngCore};

use dfns_key_export_common::{
    DecryptedShareAndIdentity, EncryptedShareAndIdentity, KeyCurve, KeyExportRequest,
    KeyExportResponse, KeyProtocol, KeySharePlaintext, SupportedScheme,
};
use dfns_trusted_dealer_core::encryption::DecryptionKey;
use generic_ec::{curves::Secp256k1, Curve, NonZero, Point, Scalar, SecretScalar};

const SUPPORTED_SCHEMES: [SupportedScheme; 1] = [SupportedScheme {
    protocol: KeyProtocol::Cggmp21,
    curve: KeyCurve::Secp256k1,
}];

/// Secret key to be exported
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SecretKey(generic_ec::SecretScalar<Secp256k1>);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SecretKey {
    /// Serializes the secret key in big-endian format.
    pub fn to_bytes_be(&self) -> Vec<u8> {
        self.0.as_ref().to_be_bytes().to_vec()
    }
}

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
    pub fn new() -> Result<KeyExportContext, types::Error> {
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
    /// export the key of the wallet with the given `wallet_id`.
    ///
    /// Throws `Error` in case of failure.
    pub fn build_key_export_request(&self) -> Result<types::Request, types::Error> {
        let req = KeyExportRequest {
            supported_schemes: Vec::from(SUPPORTED_SCHEMES),
            encryption_key: self.decryption_key.encryption_key(),
        };
        types::format_request(req)
    }

    /// Parses the response from Dfns API and recovers the private key.
    ///
    /// It returns the private key as a big endian byte array,
    /// or an `Error` (if the private key cannot be recovered,
    /// or is recovered but doesn’t match the public_key).
    pub fn recover_secret_key(&self, response: String) -> Result<SecretKey, types::Error> {
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
        if !(1 <= min_signers && min_signers <= n) {
            return Err(new_error(
                "invalid threshold: min_signers must be at least 1 and at most the number of the given shares",
            ));
        };

        let decrypted_key_shares_and_ids = decrypt_key_shares(
            &self.decryption_key,
            &response.encrypted_shares,
            min_signers,
        )?;

        // Depending on the protocol/curve combination, parse key_shares and public_key,
        // perform the interpolation, and return the private key.
        let secret_key = match (response.protocol, response.curve) {
            (KeyProtocol::Cggmp21, KeyCurve::Secp256k1) => {
                let key_shares =
                    parse_key_shares::<Secp256k1>(&decrypted_key_shares_and_ids, min_signers)?;
                let public_key = parse_public_key(&response.public_key)?;
                interpolate_secret_key::<Secp256k1>(&key_shares, &public_key)
                    .context("interpolation failed")?
            }
            (protocol, curve) => {
                return Err(new_error(&alloc::format!(
                    "protocol {:?} using curve {:?} is not supported for key export",
                    &protocol,
                    &curve
                )));
            }
        };
        Ok(SecretKey(secret_key))
    }
}

/// Decrypt a collection of `EncryptedShareAndIdentity`.
///
/// It requires that `threshold` valid (i.e., successfully decrypted) shares be found,
/// and returns and error otherwise, containg the ids of the signers of invalid shares.
pub fn decrypt_key_shares(
    decryption_key: &DecryptionKey,
    encrypted_shares_and_ids: &[EncryptedShareAndIdentity],
    threshold: u16,
) -> Result<Vec<DecryptedShareAndIdentity>, types::Error> {
    let mut decrypted_shares_and_ids = Vec::new();
    let mut invalid_ids = Vec::new();

    for share in encrypted_shares_and_ids {
        let mut buffer = share.encrypted_key_share.clone();
        match decryption_key.decrypt(&[], &mut buffer) {
            Ok(_) => decrypted_shares_and_ids.push(DecryptedShareAndIdentity {
                signer_identity: share.signer_identity.clone(),
                decrypted_key_share: buffer,
            }),
            Err(_) => invalid_ids.push(&share.signer_identity),
        }
    }

    if decrypted_shares_and_ids.len() >= threshold as usize {
        Ok(decrypted_shares_and_ids)
    } else {
        let error_msg = append_signer_ids_to_error_msg("not enough shares: the signers with the following idenities returned shares that cannot be decrypted:".to_string(), &invalid_ids);
        Err(new_error(&error_msg))
    }
}

/// Parse a collection of `DecryptedShareAndIdentity` as `KeySharePlaintext<E>`.
///
/// It requres that `threshold` valid (i.e., successfully parsed) shares be found,
/// and returns and error otherwise, containg the ids of the signers of invalid shares.
pub fn parse_key_shares<E: Curve>(
    key_shares_and_ids: &[DecryptedShareAndIdentity],
    threshold: u16,
) -> Result<Vec<KeySharePlaintext<E>>, types::Error> {
    let mut parsed_shares = Vec::new();
    let mut invalid_ids = Vec::new();

    for share in key_shares_and_ids {
        match serde_json::from_slice::<KeySharePlaintext<E>>(&share.decrypted_key_share) {
            Ok(parsed_share) => parsed_shares.push(parsed_share),
            Err(_) => invalid_ids.push(&share.signer_identity),
        };
    }

    if parsed_shares.len() >= threshold as usize {
        Ok(parsed_shares)
    } else {
        let error_msg = append_signer_ids_to_error_msg("not enough shares: the signers with the following idenities returned shares that cannot be parsed:".to_string(), &invalid_ids);
        Err(new_error(&error_msg))
    }
}

/// Parse the public key
fn parse_public_key<E: Curve>(public_key_bytes: &Vec<u8>) -> Result<Point<E>, types::Error> {
    Point::<E>::from_bytes(public_key_bytes).context("cannot parse the public key")
}

/// Utility function to encode signer ids as Base64 and append them to a string
fn append_signer_ids_to_error_msg(error_msg: String, invalid_ids: &[&Vec<u8>]) -> String {
    let error_msg = invalid_ids.iter().fold(error_msg, |acc, id| {
        acc + " " + &general_purpose::STANDARD_NO_PAD.encode(id)
    });
    error_msg
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
    if n == 0 {
        return Err(InterpolateKeyError::NoShares);
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
    NoShares,
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
            InterpolateKeyError::NoShares => "not shares given as input to the interpolation algorithm",
            InterpolateKeyError::ZeroIndex => "index is zero when it's suppposed to be non-zero",
            InterpolateKeyError::MalformedIndexes => "malformed share indexes",
            InterpolateKeyError::CannotVerifySecretKey => "the interpolated secret key cannot be verified against the provided public key (the secret key shares or the public key are invalid",
        };
        f.write_str(msg)
    }
}

trait Context<T, E> {
    fn context(self, ctx: &str) -> Result<T, types::Error>;
}

impl<T, E> Context<T, E> for Result<T, E>
where
    E: core::fmt::Display,
{
    fn context(self, ctx: &str) -> Result<T, types::Error> {
        self.map_err(|e| types::Error::new(&alloc::format!("{ctx}: {e}")))
    }
}

fn new_error(ctx: &str) -> types::Error {
    types::Error::new(ctx)
}
