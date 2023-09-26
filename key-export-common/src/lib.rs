//! Dfns Key Export SDK
//! Provides a basic functionality for key export.

#![no_std]
#![forbid(missing_docs)]

extern crate alloc;

use alloc::{string::String, vec::Vec};
use serde_with::{base64::Base64, serde_as};

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

/// Format of a decrypted key share
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct KeySharePlaintext<E: Curve> {
    /// The index (evaluation point)
    pub index: NonZero<Scalar<E>>,
    /// The secret share
    pub secret_share: SecretScalar<E>,
}

/// Identity and encrypted share of a signer.
#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct EncryptedShareAndIdentity {
    /// Signer's identity
    #[serde_as(as = "Base64")]
    pub signer_identity: Vec<u8>,
    /// Signers's key share.
    ///
    /// It is an encrypted `dfns_key_export_common::KeySharePlaintext`.
    /// Ciphertext and plaintext are in format defined by `dfns-key-import-common`
    /// library. See [here](https://github.com/dfns-labs/trusted-dealer/).
    #[serde_as(as = "Base64")]
    pub encrypted_key_share: Vec<u8>,
}

/// Key export request that's intended to be sent from the client
/// to Dfns API.
#[serde_as]
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyExportRequest {
    /// The wallet-id whose private key will be extracted
    pub wallet_id: String,
    /// An encryption key, to be used by signers to sign their key share.
    ///
    /// It contains the bytes of a `dfns_key_import_common::encryption::EncryptionKey`,
    /// as defined in `dfns-key-import-common` library:
    /// https://github.com/dfns-labs/trusted-dealer/
    #[serde_as(as = "Base64")]
    pub encryption_key: Vec<u8>,
    /// Key types (protocol and curve) supported by the WASM module
    /// that generated the KeyExportRequest.
    pub supported_schemes: Vec<SupportedScheme>,
}

/// Key export response, sent from Dfns API to the WASM module.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyExportResponse {
    /// The threshold of the specified wallet.
    pub min_signers: u32,
    /// The public key of the specified wallet.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// The protocol the exported scheme can be used for
    pub protocol: KeyProtocol,
    /// The curve the exported scheme can be used for
    pub curve: KeyCurve,
    /// Identities and encrypted shares of wallet's key holders.
    pub encrypted_shares: Vec<EncryptedShareAndIdentity>,
}

/// The protocol and curve for which a key can be used
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SupportedScheme {
    /// protocol
    pub protocol: KeyProtocol,
    /// curve
    pub curve: KeyCurve,
}

/// The protocol for which a key can be used
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum KeyProtocol {
    ///GG18
    Gg18,
    ///Binance EDDSA
    BinanceEcdsa,
    ///CGGMP21
    Cggmp21,
}

/// The curve for which a key can be used
#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub enum KeyCurve {
    /// Secp256k1 curve
    Secp256k1,
    /// Ed25519 curve
    Ed25519,
}

/// Internal function to perform interpolation.
///
/// In the end it verifies the computed key against the provided
/// public key and returns an error if it doesn't match.
/// `key_shares` is a vector of serialized KeySharePlaintext<E>
/// 'public_key` is a serialized Point<E>
pub fn interpolate_secret_key<E: Curve>(
    key_shares_bytes: &[Vec<u8>],
    public_key_bytes: &[u8],
) -> Result<SecretScalar<E>, InterpolateKeyError> {
    // Validate input
    let n = key_shares_bytes.len();
    if n <= 1 {
        return Err(InterpolateKeyError::NotEnoughShares);
    };

    // Parse public key
    let public_key = Point::<E>::from_bytes(public_key_bytes)
        .map_err(|_| InterpolateKeyError::CannotParsePublicKey)?;

    // Parse key_shares
    let key_shares: Vec<KeySharePlaintext<E>> = key_shares_bytes
        .iter()
        .map(|share| serde_json::from_slice(share))
        .collect::<Result<Vec<KeySharePlaintext<E>>, _>>()
        .map_err(|_| InterpolateKeyError::CannotParseShares)?;

    // Extract evaluation indexes and polynomial values
    let indexes = key_shares
        .iter()
        .map(|s| s.index)
        .collect::<Vec<NonZero<_>>>();
    let shares = key_shares
        .iter()
        .map(|s| (s.secret_share.clone()))
        .collect::<Vec<SecretScalar<_>>>();

    let mut interpolated_secret_key = {
        let lagrange_coefs = (0..n)
            .map(|j| generic_ec_zkp::polynomial::lagrange_coefficient(Scalar::zero(), j, &indexes));
        lagrange_coefs
            .zip(shares)
            .map(|(lambda_j, share)| Some(lambda_j? * &share))
            .try_fold(Scalar::zero(), |acc, p_i| Some(acc + p_i?))
            .ok_or(InterpolateKeyError::MalformedIndexes)?
    };

    // Compute the public key that corresponds to the interpolated secret key
    // and check whether it matches the given one.
    if Point::generator() * interpolated_secret_key != public_key {
        return Err(InterpolateKeyError::CannotVerifySecretKey);
    }

    Ok(SecretScalar::new(&mut interpolated_secret_key))
}

/// Structure to describe errors in interpolate_secret_key()
#[derive(Debug)]
pub enum InterpolateKeyError {
    /// Input to interpolate_secret_key() contains not enough shares
    NotEnoughShares,
    /// A secret-key share cannot be parsed
    CannotParseShares,
    /// The public key cannot be parsed
    CannotParsePublicKey,
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
            InterpolateKeyError::CannotParseShares => "cannot parse a decrepted secret-key share",
            InterpolateKeyError::CannotParsePublicKey => "cannot parse the public key",
            InterpolateKeyError::ZeroIndex => "index is zero when it's suppposed to be non-zero",
            InterpolateKeyError::MalformedIndexes => "malformed share indexes",
            InterpolateKeyError::CannotVerifySecretKey => "the interpolated secret key cannot be verified against the provided public key (the secret key shares or the public key are invalid",
        };
        f.write_str(msg)
    }
}
