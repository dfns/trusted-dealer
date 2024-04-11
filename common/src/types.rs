//! Types used in key import and export functionalities

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

/// The protocol for which a key can be used.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub enum KeyProtocol {
    /// GG18
    Gg18,
    /// Binance EDDSA
    BinanceEddsa,
    /// CGGMP21
    Cggmp21,
    /// FROST
    Frost,
}

/// The curve for which a key can be used
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub enum KeyCurve {
    /// Secp256k1 curve
    Secp256k1,
    /// Stark curve
    Stark,
    /// Ed25519 curve
    Ed25519,
}

/// Basic types for key import
#[cfg(feature = "import")]
pub mod import {
    use alloc::vec::Vec;

    use generic_ec::{Curve, NonZero, Point, SecretScalar};
    use serde_with::{base64::Base64, serde_as};

    use super::{KeyCurve, KeyProtocol};

    /// Version number, ensures that server and client
    /// use the same key-import-common library
    const VERSION: u8 = 1;

    /// Format of decrypted key share
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    #[serde(bound = "")]
    pub struct KeySharePlaintext<E: Curve> {
        /// Version of library that generated the key share
        pub version: crate::version::VersionGuard<VERSION>,
        /// The secret share
        pub secret_share: NonZero<SecretScalar<E>>,
        /// `public_shares[j]` is commitment to secret share of j-th party
        pub public_shares: Vec<NonZero<Point<E>>>,
    }

    /// List of signers
    ///
    /// Lists all the signers: their identity and encryption keys. List is sorted by signers identities.
    #[derive(Debug, PartialEq, serde::Serialize)]
    #[serde(transparent, rename_all = "camelCase")]
    pub struct SignersInfo {
        // This list must be sorted by `identity`
        signers: Vec<SignerInfo>,
    }

    impl SignersInfo {
        /// Returns list of signers
        ///
        /// List is sorted by signers identities
        pub fn signers(&self) -> &[SignerInfo] {
            &self.signers
        }
    }

    impl From<Vec<SignerInfo>> for SignersInfo {
        fn from(mut signers: Vec<SignerInfo>) -> Self {
            signers.sort_unstable_by(|s1, s2| s1.signer_id.cmp(&s2.signer_id));
            Self { signers }
        }
    }

    impl<'de> serde::Deserialize<'de> for SignersInfo {
        fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where
            D: serde::Deserializer<'de>,
        {
            let signers = Vec::<SignerInfo>::deserialize(deserializer)?;
            Ok(Self::from(signers))
        }
    }

    /// Signer info
    #[serde_as]
    #[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct SignerInfo {
        /// Signer public encryption key
        pub encryption_key: crate::encryption::EncryptionKey,
        /// Signer identity
        #[serde_as(as = "Base64")]
        pub signer_id: Vec<u8>,
    }

    /// Key import request that's intended to be sent to Dfns API
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct KeyImportRequest {
        /// The threshold of the specified wallet.
        pub min_signers: u32,
        /// The protocol the imported key will be used for
        pub protocol: KeyProtocol,
        /// The curve the imported key will be used for
        pub curve: KeyCurve,
        /// List of encrypted key shares per signer
        pub encrypted_key_shares: Vec<KeyShareCiphertext>,
    }

    /// Encrypted key share
    ///
    /// Contains key share ciphertext and destination signer identity.
    #[serde_as]
    #[derive(Debug, serde::Serialize, serde::Deserialize)]
    #[serde(rename_all = "camelCase")]
    pub struct KeyShareCiphertext {
        /// Key share ciphertext
        #[serde_as(as = "Base64")]
        pub encrypted_key_share: Vec<u8>,
        /// Identity of signer that's supposed to receive that key share
        #[serde_as(as = "Base64")]
        pub signer_id: Vec<u8>,
    }
}

/// Basic types for key export
#[cfg(feature = "export")]
pub mod export {
    use alloc::vec::Vec;

    use generic_ec::{Curve, NonZero, Scalar, SecretScalar};
    use serde_with::{base64::Base64, serde_as};

    use super::{KeyCurve, KeyProtocol};

    /// Version number, ensures that server and client
    /// use the same key-export-common library
    const VERSION: u8 = 1;

    /// Format of a decrypted key share
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    #[serde(bound = "")]
    pub struct KeySharePlaintext<E: Curve> {
        /// Version of library that generated the key share
        pub version: crate::version::VersionGuard<VERSION>,
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
        pub encryption_key: crate::encryption::EncryptionKey,
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
}
