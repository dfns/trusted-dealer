//! Dfns Key Import SDK
//!
//! Provides a basic functionality to split the secret key to be imported into key shares
//! at customer side, encrypt them and build a key import request that needs to be sent
//! to Dfns API.

#![forbid(missing_docs, unused_crate_dependencies)]
#![no_std]

mod _unused_deps {
    // We don't use getrandom directly, but we need to enable "js" feature
    #[cfg(target_arch = "wasm32")]
    use getrandom as _;
}

extern crate alloc;

use alloc::vec::Vec;

use common::{rand_core::CryptoRng, KeyImportRequest};
use dfns_trusted_dealer_core::{
    error::{Context, Error},
    json_value::JsonValue,
    types::{KeyCurve, KeyProtocol},
};

#[cfg(target_arch = "wasm32")]
use dfns_trusted_dealer_core::wasm_bindgen::{self, prelude::wasm_bindgen};

use dfns_key_import_common::{
    self as common,
    generic_ec::{self, curves},
    rand_core::{self, RngCore},
};

/// Signers info
///
/// Contains information necessary to establish a secure communication channel with
/// the signers who're going to host the imported key
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub struct SignersInfo(common::SignersInfo);

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
pub struct SecretKey {
    be_bytes: zeroize::Zeroizing<Vec<u8>>,
}

#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
impl SecretKey {
    /// Parses the secret key in big-endian format (the most widely-used format)
    ///
    /// Throws `Error` if secret key is invalid
    #[cfg_attr(target_arch = "wasm32", wasm_bindgen(js_name = fromBytesBE))]
    pub fn from_bytes_be(bytes: Vec<u8>) -> Result<SecretKey, Error> {
        Ok(Self {
            be_bytes: bytes.into(),
        })
    }
}

/// Builds a request body that needs to be sent to Dfns API in order to import the given key.
///
/// Takes as input the `secret_key` to be imported, `signers_info` (contains information
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
    secret_key: &SecretKey,
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
                secret_key,
                signers_info,
                min_signers,
                n,
            )
        }
        (KeyProtocol::Cggmp21, KeyCurve::Stark) => {
            build_key_import_request_for_curve::<curves::Stark>(
                &mut rng,
                secret_key,
                signers_info,
                min_signers,
                n,
            )
        }
        (KeyProtocol::Frost, KeyCurve::Ed25519) => {
            build_key_import_request_for_curve::<curves::Ed25519>(
                &mut rng,
                secret_key,
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

fn build_key_import_request_for_curve<E: generic_ec::Curve>(
    rng: &mut (impl RngCore + CryptoRng),
    secret_key: &SecretKey,
    signers_info: &SignersInfo,
    min_signers: u16,
    n: u16,
) -> Result<JsonValue, Error> {
    let secret_key = generic_ec::SecretScalar::<E>::from_be_bytes(&secret_key.be_bytes)
        .context("malformed secret key")?;
    let secret_key =
        generic_ec::NonZero::from_secret_scalar(secret_key).context("secret key is zero")?;

    // Split the secret key into the shares
    let key_shares = common::split_secret_key(rng, min_signers, n, &secret_key)
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
            Ok(common::KeyShareCiphertext {
                encrypted_key_share: key_share,
                signer_id: recipient.signer_id.clone(),
            })
        })
        .collect::<Result<Vec<_>, dfns_trusted_dealer_core::encryption::Error>>()
        .map_err(|_| Error::new("couldn't encrypt a key share"))?;

    // Build a request and serialize it
    let req = KeyImportRequest {
        min_signers: 3,
        protocol: KeyProtocol::Cggmp21,
        curve: KeyCurve::Secp256k1,
        encrypted_key_shares,
    };

    JsonValue::new(req).context("cannot serialize key-import request")
}
