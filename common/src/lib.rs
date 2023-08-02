#![no_std]

extern crate alloc;

pub use {generic_ec, rand_core};

pub mod encryption;
mod utils;

use alloc::vec::Vec;

use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

pub use generic_ec::curves::Secp256k1;

/// Version number, ensures that server and client are compatible
///
/// Version is embedded into all serialized structs (public key, signers info, etc.).
/// Incrementing the version will force clients to update the library.
const VERSION: u8 = 1;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct KeySharePlaintext<E: Curve> {
    /// Version of library that generated the key share
    pub version: utils::VersionGuard,
    /// The secret share
    pub secret_share: SecretScalar<E>,
    /// `public_shares[j]` is commitment to secret share of j-th party
    pub public_shares: Vec<Point<E>>,
}

pub fn split_secret_key<E: Curve, R: RngCore + CryptoRng>(
    rng: &mut R,
    t: u16,
    n: u16,
    secret_key: &SecretScalar<E>,
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
            secret_key.clone(),
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
            version: utils::VersionGuard,
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

#[derive(Debug, serde::Serialize)]
pub struct SignersInfo {
    // This list must be sorted by `identity`
    signers: Vec<SignerInfo>,
}

impl SignersInfo {
    pub fn signers(&self) -> &[SignerInfo] {
        &self.signers
    }
}

impl From<Vec<SignerInfo>> for SignersInfo {
    fn from(mut signers: Vec<SignerInfo>) -> Self {
        signers.sort_unstable_by(|s1, s2| s1.identity.cmp(&s2.identity));
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

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct SignerInfo {
    pub encryption_key: encryption::EncryptionKey,
    #[serde(with = "hex::serde")]
    pub identity: Vec<u8>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyImportRequest {
    pub key_shares_list: Vec<KeyShareCiphertext>,
}

#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct KeyShareCiphertext {
    #[serde(with = "hex::serde")]
    pub encrypted_key_share: Vec<u8>,
    #[serde(with = "hex::serde")]
    pub recipient_identity: Vec<u8>,
}
