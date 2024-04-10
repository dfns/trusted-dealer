//! Client code for the key-export functionality.
//!
//! Customers can use the KeyExportContext struct and its methods
//! to build a key-export request, which then can be sent to
//! the Dfns API, and to parse the response and extract the private
//! key of a specified wallet.

#![forbid(missing_docs)]
#![cfg_attr(not(test), forbid(unused_crate_dependencies))]
#![no_std]

mod _unused_deps {
    // We don't use getrandom directly, but we need to enable "js" feature
    #[cfg(target_arch = "wasm32")]
    use getrandom as _;
}

extern crate alloc;

use alloc::{format, vec::Vec};
use base64::{engine::general_purpose, Engine as _};
use rand_core::{self, RngCore};

use dfns_key_export_common::{
    DecryptedShareAndIdentity, EncryptedShareAndIdentity, KeyExportRequest, KeyExportResponse,
    KeySharePlaintext, SupportedScheme,
};
use dfns_trusted_dealer_core::{
    encryption::DecryptionKey,
    error::{Context, Error},
    json_value::JsonValue,
    types::{KeyCurve, KeyProtocol},
};
use generic_ec::{curves, Curve, NonZero, Point, Scalar, SecretScalar};

#[cfg(target_arch = "wasm32")]
use dfns_trusted_dealer_core::wasm_bindgen::{self, prelude::wasm_bindgen};

const SUPPORTED_SCHEMES: [SupportedScheme; 1] = [SupportedScheme {
    protocol: KeyProtocol::Cggmp21,
    curve: KeyCurve::Secp256k1,
}];

/// Secret key to be exported
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SecretKey {
    /// Secret key serialized as bytes in big-endian
    be_bytes: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SecretKey {
    /// Serializes the secret key in big-endian format.
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = toBytesBE))]
    pub fn to_bytes_be(&self) -> Vec<u8> {
        (*self.be_bytes).clone()
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
    pub fn new() -> Result<KeyExportContext, Error> {
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
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = buildKeyExportRequest))]
    pub fn build_key_export_request(&self) -> Result<JsonValue, Error> {
        let req = KeyExportRequest {
            supported_schemes: Vec::from(SUPPORTED_SCHEMES),
            encryption_key: self.decryption_key.encryption_key(),
        };
        JsonValue::new(req).context("serialize key export request")
    }

    /// Parses the response from Dfns API and recovers the private key.
    ///
    /// It returns the private key as a big endian byte array,
    /// or an `Error` (if the private key cannot be recovered,
    /// or is recovered but doesn’t match the public_key).
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = recoverSecretKey))]
    pub fn recover_secret_key(&self, response: JsonValue) -> Result<SecretKey, Error> {
        // Parse response
        let response: KeyExportResponse = response.deserialize().context("deserialize response")?;
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
            return Err(Error::new(
                "invalid threshold: min_signers must be at least 2 and at most the number of the given shares",
            ));
        };

        let decrypted_key_shares_and_ids =
            decrypt_key_shares(&self.decryption_key, &response.encrypted_shares)?;

        // Depending on the protocol/curve combination, parse key_shares and public_key,
        // perform the interpolation, and return the private key.
        let secret_key = match (response.protocol, response.curve) {
            (KeyProtocol::Cggmp21, KeyCurve::Secp256k1) => {
                let key_shares =
                    parse_key_shares::<curves::Secp256k1>(&decrypted_key_shares_and_ids)?;
                let public_key = parse_public_key(&response.public_key)?;
                interpolate_secret_key::<curves::Secp256k1>(&key_shares, &public_key)
                    .context("interpolation failed")?
                    .as_ref()
                    .to_be_bytes()
                    .to_vec()
                    .into()
            }
            (KeyProtocol::Cggmp21, KeyCurve::Stark) => {
                let key_shares = parse_key_shares::<curves::Stark>(&decrypted_key_shares_and_ids)?;
                let public_key = parse_public_key(&response.public_key)?;
                interpolate_secret_key::<curves::Stark>(&key_shares, &public_key)
                    .context("interpolation failed")?
                    .as_ref()
                    .to_be_bytes()
                    .to_vec()
                    .into()
            }
            (KeyProtocol::Frost, KeyCurve::Ed25519) => {
                let key_shares =
                    parse_key_shares::<curves::Ed25519>(&decrypted_key_shares_and_ids)?;
                let public_key = parse_public_key(&response.public_key)?;
                interpolate_secret_key::<curves::Ed25519>(&key_shares, &public_key)
                    .context("interpolation failed")?
                    .as_ref()
                    .to_be_bytes()
                    .to_vec()
                    .into()
            }
            (protocol, curve) => {
                return Err(Error::new(&alloc::format!(
                    "protocol {:?} using curve {:?} is not supported for key export",
                    &protocol,
                    &curve
                )));
            }
        };
        Ok(SecretKey {
            be_bytes: secret_key,
        })
    }
}

/// Decrypt a collection of `EncryptedShareAndIdentity`.
///
/// If all ciphertexts are successfully decrypted, it returns
/// a vector of `DecryptedShareAndIdentity`, and an error otherwise,
/// containg the id of the signer with the first invalid share found.
pub fn decrypt_key_shares(
    decryption_key: &DecryptionKey,
    encrypted_shares_and_ids: &[EncryptedShareAndIdentity],
) -> Result<Vec<DecryptedShareAndIdentity>, Error> {
    let decrypted_key_shares = encrypted_shares_and_ids
        .iter()
        .map(|share| {
            let mut buffer = share.encrypted_key_share.clone();
            decryption_key.decrypt(&[], &mut buffer).context(&format!(
                "cannot decrypt a key share from signer with identity {}",
                general_purpose::STANDARD_NO_PAD.encode(&share.signer_id)
            ))?;
            Ok(DecryptedShareAndIdentity {
                signer_identity: share.signer_id.clone(),
                decrypted_key_share: buffer,
            })
        })
        .collect::<Result<Vec<_>, Error>>()?;
    Ok(decrypted_key_shares)
}

/// Parse a collection of `DecryptedShareAndIdentity` as `KeySharePlaintext<E>`.
///
/// If all shares are successfully parsed, it returns
/// a vector of `KeySharePlaintext<E>`, and an error otherwise,
/// containg the id of the signer with the first invalid share found.
pub fn parse_key_shares<E: Curve>(
    key_shares_and_ids: &[DecryptedShareAndIdentity],
) -> Result<Vec<KeySharePlaintext<E>>, Error> {
    let key_shares_plaintext = key_shares_and_ids
        .iter()
        .map(|share| {
            serde_json::from_slice::<KeySharePlaintext<E>>(&share.decrypted_key_share).context(
                &format!(
                    "cannot parse a key share from signer with identity {}",
                    general_purpose::STANDARD_NO_PAD.encode(&share.signer_identity)
                ),
            )
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(key_shares_plaintext)
}

/// Parse the public key
fn parse_public_key<E: Curve>(public_key_bytes: &Vec<u8>) -> Result<Point<E>, Error> {
    Point::<E>::from_bytes(public_key_bytes).context("cannot parse the public key")
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
