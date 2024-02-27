//! Dfns Key Import SDK: core code
//!
//! This library contains a common code shared between Dfns infrastructure
//! and client library.

#![forbid(missing_docs)]
#![cfg_attr(not(feature = "std"), no_std)]

extern crate alloc;

pub use dfns_trusted_dealer_core::encryption;
pub use {generic_ec, generic_ec::curves::Secp256k1, rand_core};

use alloc::vec::Vec;
use dfns_trusted_dealer_core::types::{KeyCurve, KeyProtocol};
use serde_with::{base64::Base64, serde_as};

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

/// Version number, ensures that server and client
/// use the same key-import-common library
const VERSION: u8 = 1;

/// Format of decrypted key share
#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct KeySharePlaintext<E: Curve> {
    /// Version of library that generated the key share
    pub version: dfns_trusted_dealer_core::version::VersionGuard<VERSION>,
    /// The secret share
    pub secret_share: SecretScalar<E>,
    /// `public_shares[j]` is commitment to secret share of j-th party
    pub public_shares: Vec<Point<E>>,
}

/// Splits secret key into key shares
pub fn split_secret_key<E: Curve, R: RngCore + CryptoRng>(
    rng: &mut R,
    t: u16,
    n: u16,
    secret_key: &NonZero<Scalar<E>>,
) -> Result<Vec<KeySharePlaintext<E>>, Error> {
    if !(n > 1 && 2 <= t && t <= n) {
        return Err(Error(()));
    }
    let key_shares_indexes = (1..=n)
        .map(|i| generic_ec::NonZero::from_scalar(Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .ok_or(Error(()))?;

    let secret_shares = {
        let f = generic_ec_zkp::polynomial::Polynomial::sample_with_const_term(
            rng,
            usize::from(t) - 1,
            *secret_key,
        );
        let shares = key_shares_indexes
            .iter()
            .map(|i| f.value(i))
            .map(|mut x| SecretScalar::new(&mut x))
            .collect::<Vec<_>>();
        shares
    };

    let public_shares = secret_shares
        .iter()
        .map(|x| Point::generator() * x)
        .collect::<Vec<Point<E>>>();

    Ok(secret_shares
        .into_iter()
        .map(|secret_share| KeySharePlaintext {
            version: dfns_trusted_dealer_core::version::VersionGuard,
            secret_share,
            public_shares: public_shares.clone(),
        })
        .collect())
}

/// Splitting key share failed
#[derive(Debug)]
pub struct Error(());

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        f.write_str("splitting secret key into key shares failed")
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

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
    pub encryption_key: encryption::EncryptionKey,
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

#[cfg(test)]
mod tests {
    use alloc::vec::Vec;
    use dfns_trusted_dealer_core::encryption;

    use crate::{SignerInfo, SignersInfo};

    #[test]
    fn serialize_deserialize_signers_info() {
        let mut rng = rand_dev::DevRng::new();

        // SignerInfo
        let signer_info = SignerInfo {
            encryption_key: encryption::DecryptionKey::generate(&mut rng).encryption_key(),
            signer_id: Vec::new(),
        };
        let signer_ser = serde_json::to_vec(&signer_info).unwrap();
        let signer_deser: SignerInfo = serde_json::from_slice(&signer_ser).unwrap();
        assert_eq!(signer_info, signer_deser);

        // SignersInfo
        let signers = SignersInfo {
            signers: Vec::from([signer_info]),
        };
        let signers_ser = serde_json::to_vec(&signers).unwrap();
        let signers_deser: SignersInfo = serde_json::from_slice(&signers_ser).unwrap();
        assert_eq!(signers, signers_deser);
    }
}
