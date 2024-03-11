//! Dfns Key Export SDK
//!
//! Provides basic types for key export.

#![no_std]
#![forbid(missing_docs)]

extern crate alloc;

use dfns_trusted_dealer_core::types::{KeyCurve, KeyProtocol};
pub use dfns_trusted_dealer_core::{encryption, types, version};

use alloc::vec::Vec;
use serde_with::{base64::Base64, serde_as};

use generic_ec::{Curve, NonZero, Scalar, SecretScalar};

/// Version number, ensures that server and client
/// use the same key-export-common library
const VERSION: u8 = 1;

/// Format of a decrypted key share
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct KeySharePlaintext<E: Curve> {
    /// Version of library that generated the key share
    pub version: dfns_trusted_dealer_core::version::VersionGuard<VERSION>,
    /// The index (evaluation point)
    pub index: NonZero<Scalar<E>>,
    /// The secret share
    pub secret_share: NonZero<SecretScalar<E>>,
}

/// Key export request that's intended to be sent from the client
/// to Dfns API.
#[serde_as]
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyExportRequest {
    /// An encryption key, to be used by signers to sign their key share.
    ///
    /// It contains the bytes of an `EncryptionKey`, defined in the
    /// `dfns-trusted-dealer-core::encryption` library.
    /// See [here](https://github.com/dfns-labs/trusted-dealer/).
    ///
    pub encryption_key: encryption::EncryptionKey,
    /// Key types (protocol and curve) supported by the WASM module
    /// that generated the KeyExportRequest.
    pub supported_schemes: Vec<SupportedScheme>,
}

/// Key export response, sent from Dfns API to the WASM module.
#[derive(Debug, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct KeyExportResponse {
    /// The threshold of the specified wallet.
    pub min_signers: u32,
    /// The public key of the specified wallet.
    #[serde(with = "hex::serde")]
    pub public_key: Vec<u8>,
    /// The protocol the exported key can be used for
    pub protocol: KeyProtocol,
    /// The curve the exported key can be used for
    pub curve: KeyCurve,
    /// Identities and encrypted shares of wallet's key holders.
    pub encrypted_shares: Vec<EncryptedShareAndIdentity>,
}

/// The protocol and curve for which a key can be used
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct SupportedScheme {
    /// protocol
    pub protocol: KeyProtocol,
    /// curve
    pub curve: KeyCurve,
}

/// Identity and encrypted share of a signer.
#[serde_as]
#[derive(Debug, Clone, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EncryptedShareAndIdentity {
    /// Signer's identity
    #[serde_as(as = "Base64")]
    pub signer_id: Vec<u8>,
    /// Signers's key share.
    ///
    /// It is an encrypted `dfns_key_export_common::KeySharePlaintext`.
    /// Ciphertext and plaintext are in format defined in the
    /// `dfns-trusted-dealer-core::encryption` library.
    /// See [here](https://github.com/dfns-labs/trusted-dealer/).
    #[serde_as(as = "Base64")]
    pub encrypted_key_share: Vec<u8>,
}

/// Struct used to store decrypted key shares
#[derive(Debug, Clone)]
pub struct DecryptedShareAndIdentity {
    /// Signer's identity
    pub signer_identity: Vec<u8>,
    /// Signers's key share.
    /// It is an encrypted `dfns_key_export_common::KeySharePlaintext`.
    pub decrypted_key_share: Vec<u8>,
}

#[cfg(test)]
mod tests {

    use alloc::vec::Vec;
    use dfns_trusted_dealer_core::encryption;

    use crate::{KeyCurve, KeyExportRequest, KeyProtocol, SupportedScheme};

    #[test]
    fn parse_key_share_plaintext() {
        type E = generic_ec::curves::Secp256k1;

        let mut rng = rand_dev::DevRng::new();
        let key_share_plaintext = crate::KeySharePlaintext {
            version: dfns_trusted_dealer_core::version::VersionGuard,
            secret_share: generic_ec::NonZero::<generic_ec::SecretScalar<E>>::random(&mut rng),
            index: generic_ec::NonZero::<generic_ec::Scalar<E>>::random(&mut rng),
        };
        let key_share_plaintext = serde_json::to_string(&key_share_plaintext).unwrap();
        // println!("{:?}", &key_share_plaintext1);
        let _: crate::KeySharePlaintext<E> = serde_json::from_str(&key_share_plaintext).unwrap();
    }

    #[test]
    fn serialize_deserialize_key_export_request() {
        let mut rng = rand_dev::DevRng::new();
        let req = KeyExportRequest {
            encryption_key: encryption::DecryptionKey::generate(&mut rng).encryption_key(),
            supported_schemes: Vec::from([SupportedScheme {
                protocol: KeyProtocol::BinanceEddsa,
                curve: KeyCurve::Secp256k1,
            }]),
        };
        let req_ser = serde_json::to_vec(&req).unwrap();
        let req_deser: KeyExportRequest = serde_json::from_slice(&req_ser).unwrap();
        assert_eq!(req, req_deser);
    }
}
