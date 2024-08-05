//! Dfns Key Import SDK
//!
//! Provides a basic functionality to split the secret key to be imported into key shares
//! at customer side, encrypt them and build a key import request that needs to be sent
//! to Dfns API.

#![forbid(missing_docs)]
#![cfg_attr(not(test), forbid(unused_crate_dependencies))]
#![no_std]

mod _unused_deps {
    // We don't use getrandom directly, but we need to enable "js" feature
    #[cfg(target_arch = "wasm32")]
    use getrandom as _;
}

extern crate alloc;

use alloc::vec::Vec;

use common::{
    error::{Context, Error},
    generic_ec::{self, curves},
    json_value::JsonValue,
    rand_core::{self, CryptoRng, RngCore},
};

#[cfg(target_arch = "wasm32")]
use common::wasm_bindgen::{self, prelude::wasm_bindgen};

pub use common::types::{import as types, KeyCurve, KeyProtocol};

/// Signers info
///
/// Contains information necessary to establish a secure communication channel with
/// the signers who're going to host the imported key
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SignersInfo(types::SignersInfo);

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SignersInfo {
    /// Parses signers info from response obtained from Dfns API
    ///
    /// Throws `Error` if response is malformed
    pub fn new(resp: JsonValue) -> Result<SignersInfo, Error> {
        let info = resp.deserialize().context("couldn't parse the response")?;
        Ok(Self(info))
    }
}

/// Secret key to be imported
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SecretScalar {
    be_bytes: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SecretScalar {
    /// Parses the secret key in big-endian format (the most widely-used format)
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = fromBytesBE))]
    pub fn from_bytes_be(bytes: Vec<u8>) -> SecretScalar {
        Self {
            be_bytes: bytes.into(),
        }
    }
}

impl SecretScalar {
    /// Returns bytes representation of the secret key in big-endian format
    ///
    /// It is not exposed in WASM API
    pub fn to_be_bytes(self) -> zeroize::Zeroizing<Vec<u8>> {
        self.be_bytes
    }
}

/// Builds a request body that needs to be sent to Dfns API in order to import the given key.
///
/// Takes as input the `secret_scalar` to be imported, `signers_info` (contains information
/// about the _n_ key holders, needs to be retrieved from Dfns API)
/// `min_signers` (which will be the threshold and has to satisfy _2 ≤ min_signers ≤ n_),
/// and the `protocol` and `curve` for which the imported key will be used.
///
/// Returns a body of the request that needs to be sent to Dfns API in order to import the given key.
///
/// Requires a global secure randomness generator to be available, that can be either [Web Crypto API]
/// or [Node JS crypto module]. If neither of them is available, throws `Error`.
///
/// [Web Crypto API]: https://www.w3.org/TR/WebCryptoAPI/
/// [Node JS crypto module]: https://nodejs.org/api/crypto.html
///
/// Throws `Error` in case of failure
#[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = buildKeyImportRequest))]
pub fn build_key_import_request(
    secret_scalar: &SecretScalar,
    signers_info: &SignersInfo,
    min_signers: u16,
    protocol: KeyProtocol,
    curve: KeyCurve,
) -> Result<JsonValue, Error> {
    let mut rng = rand_core::OsRng;

    // Sample random 10 bytes to see that CSPRNG is available
    let mut sample = [0u8; 10];
    rng.try_fill_bytes(&mut sample)
        .map_err(|_| Error::new("cryptographic randomness generator is not available"))?;

    let n: u16 = signers_info
        .0
        .signers()
        .len()
        .try_into()
        .context("length of signers_info overflows u16")?;

    if !(2 <= min_signers && min_signers <= n) {
        return Err(Error::new(
            "invalid threshold: min_signers must be at least 2 and at most the length of signers_info",
        ));
    };

    match (protocol, curve) {
        (KeyProtocol::Cggmp21, KeyCurve::Secp256k1) => {
            build_key_import_request_for_curve::<curves::Secp256k1>(
                &mut rng,
                protocol,
                curve,
                secret_scalar,
                signers_info,
                min_signers,
                n,
            )
        }
        (KeyProtocol::Cggmp21, KeyCurve::Stark) => {
            build_key_import_request_for_curve::<curves::Stark>(
                &mut rng,
                protocol,
                curve,
                secret_scalar,
                signers_info,
                min_signers,
                n,
            )
        }
        (KeyProtocol::Frost, KeyCurve::Ed25519) => {
            build_key_import_request_for_curve::<curves::Ed25519>(
                &mut rng,
                protocol,
                curve,
                secret_scalar,
                signers_info,
                min_signers,
                n,
            )
        }
        (p, c) => Err(Error::new(&alloc::format!(
            "protocol {:?} using curve {:?} is not supported for key import",
            &p,
            &c
        ))),
    }
}

/// Converts EdDSA secret key into secret scalar that can be used for key import
pub fn convert_eddsa_secret_key_to_scalar(secret_key: &[u8]) -> Result<SecretScalar, Error> {
    let secret_key: &[u8; 32] = secret_key
        .try_into()
        .map_err(|_| Error::new("EdDSA secret key must be 32 bytes long"))?;

    let h = <sha2::Sha512 as sha2::Digest>::digest(secret_key);
    let mut h: zeroize::Zeroizing<[u8; 64]> = zeroize::Zeroizing::new(h.into());
    let scalar_bytes = &mut h[0..32];

    // The lowest three bits of the first octet are cleared
    scalar_bytes[0] &= 0b1111_1000;
    // the highest bit of the last octet is cleared
    scalar_bytes[31] &= 0b0111_1111;
    // and the second highest bit of the last octet is set
    scalar_bytes[31] |= 0b0100_0000;

    // Interpret `scalar_bytes` as LE integer, and take it modulo curve order
    let scalar = zeroize::Zeroizing::new(
        generic_ec::Scalar::<curves::Ed25519>::from_le_bytes_mod_order(scalar_bytes),
    );

    Ok(SecretScalar::from_bytes_be(scalar.to_be_bytes().to_vec()))
}

fn build_key_import_request_for_curve<E: generic_ec::Curve>(
    rng: &mut (impl RngCore + CryptoRng),
    protocol: KeyProtocol,
    curve: KeyCurve,
    secret_scalar: &SecretScalar,
    signers_info: &SignersInfo,
    min_signers: u16,
    n: u16,
) -> Result<JsonValue, Error> {
    let secret_scalar = generic_ec::SecretScalar::<E>::from_be_bytes(&secret_scalar.be_bytes)
        .context("malformed secret key")?;
    let secret_scalar =
        generic_ec::NonZero::from_secret_scalar(secret_scalar).context("secret key is zero")?;

    // Split the secret key into the shares
    let key_shares = split_secret_scalar(rng, min_signers, n, &secret_scalar)
        .context("failed to split secret key into key shares")?;

    // Serialize each share
    let key_shares = key_shares
        .into_iter()
        .map(|k| serde_json::to_vec(&k))
        .collect::<Result<Vec<_>, _>>()
        .map_err(|_| Error::new("couldn't serialize a key share"))?;

    // Encrypt each share with corresponding signer encryption key
    let encrypted_key_shares = signers_info
        .0
        .signers()
        .iter()
        .zip(key_shares)
        .map(|(recipient, mut key_share)| {
            recipient.encryption_key.encrypt(rng, &[], &mut key_share)?;
            Ok(types::KeyShareCiphertext {
                encrypted_key_share: key_share,
                signer_id: recipient.signer_id.clone(),
            })
        })
        .collect::<Result<Vec<_>, common::encryption::Error>>()
        .map_err(|_| Error::new("couldn't encrypt a key share"))?;

    // Build a request and serialize it
    let req = types::KeyImportRequest {
        min_signers: min_signers.into(),
        protocol,
        curve,
        encrypted_key_shares,
    };

    JsonValue::new(req).context("cannot serialize key-import request")
}

/// Splits secret key into key shares
fn split_secret_scalar<E: generic_ec::Curve, R: RngCore + CryptoRng>(
    rng: &mut R,
    t: u16,
    n: u16,
    secret_scalar: &generic_ec::NonZero<generic_ec::SecretScalar<E>>,
) -> Result<Vec<types::KeySharePlaintext<E>>, Error> {
    if !(n > 1 && 2 <= t && t <= n) {
        return Err(Error::new("invalid parameters t,n"));
    }
    let key_shares_indexes = (1..=n)
        .map(|i| generic_ec::NonZero::from_scalar(generic_ec::Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .ok_or_else(|| Error::new("zero key share preimage"))?;

    let secret_shares = {
        let f = generic_ec_zkp::polynomial::Polynomial::sample_with_const_term(
            rng,
            usize::from(t) - 1,
            secret_scalar.clone(),
        );

        key_shares_indexes
            .iter()
            .map(|i| f.value(i))
            .map(|mut x| {
                generic_ec::NonZero::from_secret_scalar(generic_ec::SecretScalar::new(&mut x))
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(|| Error::new("zero share"))?
    };

    let public_shares = secret_shares
        .iter()
        .map(|x| generic_ec::Point::generator() * x)
        .collect::<Vec<generic_ec::NonZero<generic_ec::Point<E>>>>();

    Ok(secret_shares
        .into_iter()
        .map(|secret_share| types::KeySharePlaintext {
            version: Default::default(),
            secret_share,
            public_shares: public_shares.clone(),
        })
        .collect())
}
