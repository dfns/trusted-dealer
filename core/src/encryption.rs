//! Asymmetric encryption scheme
//!
//! This library implements a public-key encryption scheme
//! used in the key-export and key-import functionallities.

use aes_gcm::aead::{AeadCore, AeadInPlace, Buffer, KeyInit};
use base64::{engine::general_purpose, Engine as _};
use rand_core::{CryptoRng, RngCore};

/// We fix our encryption scheme to secp256k1 curve
type Curve = generic_ec::curves::Secp256k1;
type Point = generic_ec::Point<Curve>;
type SecretScalar = generic_ec::SecretScalar<Curve>;

/// HKDF is fixed to HKDF-SHA2-256
type Hkdf = hkdf::Hkdf<sha2::Sha256>;
const HKDF_SALT: &[u8] = b"DFNS_KEY_IMPORT";
const HKDF_KEY_LABEL: &[u8] = b"ENCRYPTION_KEY";

/// Symmetric encryption scheme is fixed to AES256-GCM
type Aes = aes_gcm::Aes256Gcm;
type AesKey = aes_gcm::Key<Aes>;
type AesNonce = aes_gcm::Nonce<<Aes as AeadCore>::NonceSize>;

/// Size of serialized `eph_key`
const EPH_KEY_SIZE: usize = 33;

/// Version number, embedded in serialized encryption and decryption keys,
/// ensures that users of this library use the same key format.
const VERSION: u8 = 1;

/// Public encryption key
#[derive(Debug, PartialEq, Eq)]
pub struct EncryptionKey {
    point: Point,
}
/// Secret decryption key
#[derive(Debug)]
pub struct DecryptionKey {
    scalar: SecretScalar,
}

impl DecryptionKey {
    /// Generates decryption key
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self {
            scalar: SecretScalar::random(rng),
        }
    }

    /// Returns a (public) encryption key corresponding to the decryption key
    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey {
            point: Point::generator() * &self.scalar,
        }
    }

    /// Decrypts a ciphertext
    pub fn decrypt(&self, associated_data: &[u8], buffer: &mut impl Buffer) -> Result<(), Error> {
        // Read `eph_pub`
        let mut eph_pub = [0u8; EPH_KEY_SIZE];
        buffer
            .read_from_back(&mut eph_pub)
            .map_err(|_| Reason::Decrypt)?;
        let eph_pub = Point::from_bytes(eph_pub).map_err(|_| Reason::Decrypt)?;

        // Derive a `aes_key` from `eph_key`
        let mut aes_key = AesKey::default();
        let shared_secret = eph_pub * &self.scalar;
        let kdf = Hkdf::new(Some(HKDF_SALT), &shared_secret.to_bytes(true));
        kdf.expand(HKDF_KEY_LABEL, &mut aes_key)
            .map_err(|_| Reason::Decrypt)?;

        // Decrypt `buffer` using `aes_key`
        let aes = Aes::new(&aes_key);
        // Nonce is zeroes string
        let aes_nonce = AesNonce::default();
        aes.decrypt_in_place(&aes_nonce, associated_data, buffer)
            .map_err(|_| Reason::Decrypt)?;

        Ok(())
    }

    /// Serializes decryption key to bytes
    pub fn to_bytes(&self) -> [u8; 33] {
        let mut output = [0u8; 33];
        output[0] = VERSION;
        output[1..].copy_from_slice(&self.scalar.as_ref().to_be_bytes());
        output
    }

    /// Parses decryption key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Reason::InvalidKey.into());
        }
        if bytes[0] != VERSION {
            return Err(Reason::VersionMismatched(bytes[0]).into());
        }
        let scalar = SecretScalar::from_be_bytes(&bytes[1..]).map_err(|_| Reason::InvalidKey)?;
        Ok(Self { scalar })
    }
}

impl EncryptionKey {
    /// Encrypts a plaintext
    pub fn encrypt(
        &self,
        rng: &mut (impl RngCore + CryptoRng),
        associated_data: &[u8],
        buffer: &mut impl Buffer,
    ) -> Result<(), Error> {
        // Derive an ephemeral key
        let eph_key = SecretScalar::random(rng);
        let eph_pub = (Point::generator() * &eph_key).to_bytes(true);
        debug_assert_eq!(eph_pub.len(), EPH_KEY_SIZE);

        // Derive a `aes_key` from `ehp_key`
        let mut aes_key = AesKey::default();
        let shared_secret = self.point * &eph_key;
        let kdf = Hkdf::new(Some(HKDF_SALT), &shared_secret.to_bytes(true));
        kdf.expand(HKDF_KEY_LABEL, &mut aes_key)
            .map_err(|_| Reason::Encrypt)?;

        // Encrypt `buffer` using `aes_key`
        let aes = Aes::new(&aes_key);
        // Nonce is zeroes string
        let aes_nonce = AesNonce::default();

        aes.encrypt_in_place(&aes_nonce, associated_data, buffer)
            .map_err(|_| Reason::Encrypt)?;

        // Append `eph_pub` to the buffer
        buffer
            .extend_from_slice(&eph_pub)
            .map_err(|_| Reason::Encrypt)?;

        Ok(())
    }

    /// Serialized encryption key to bytes
    pub fn to_bytes(&self) -> [u8; 34] {
        let mut output = [0u8; 34];
        output[0] = VERSION;
        output[1..].copy_from_slice(&self.point.to_bytes(true));
        output
    }

    /// Parses encryption key from bytes
    pub fn from_bytes(bytes: &[u8]) -> Result<Self, Error> {
        if bytes.is_empty() {
            return Err(Reason::InvalidKey.into());
        }
        if bytes[0] != VERSION {
            return Err(Reason::VersionMismatched(bytes[0]).into());
        }
        let point = Point::from_bytes(&bytes[1..]).map_err(|_| Reason::InvalidKey)?;
        Ok(Self { point })
    }
}

impl serde::Serialize for EncryptionKey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        general_purpose::STANDARD
            .encode(self.to_bytes())
            .serialize(serializer)
    }
}

impl<'de> serde::Deserialize<'de> for EncryptionKey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let encoded_ek = alloc::string::String::deserialize(deserializer)?;
        let ek_bytes = general_purpose::STANDARD.decode(encoded_ek).map_err(|e| {
            <D::Error as serde::de::Error>::custom(alloc::format!("malformed hex string: {e}"))
        })?;
        Self::from_bytes(&ek_bytes).map_err(|e| {
            <D::Error as serde::de::Error>::custom(alloc::format!("invalid encryption key: {e}"))
        })
    }
}

/// Describes what went wrong
#[derive(Debug, Clone, Copy)]
pub struct Error(Reason);

#[derive(Debug, Clone, Copy)]
enum Reason {
    VersionMismatched(u8),
    InvalidKey,
    Encrypt,
    Decrypt,
}

impl core::fmt::Display for Error {
    fn fmt(&self, f: &mut core::fmt::Formatter<'_>) -> core::fmt::Result {
        match self {
            Error(Reason::VersionMismatched(v)) => f.write_fmt(core::format_args!("parsing failed: version of data (v{v}) doesn't match version supported by the library (v{VERSION})")),
            Error(Reason::InvalidKey) => f.write_str("invalid key"),
            Error(Reason::Encrypt) => f.write_str("encryption error"),
            Error(Reason::Decrypt) => f.write_str("decryption error"),
        }
    }
}

#[cfg(feature = "std")]
impl std::error::Error for Error {}

impl From<Reason> for Error {
    fn from(err: Reason) -> Self {
        Error(err)
    }
}

trait BufferExt: Buffer {
    /// Copies `buffer[buffer.len() - chunk.len()..]` into the `chunk` and truncates
    /// `chuck.len()` bytes from the buffer.
    fn read_from_back(&mut self, chunk: &mut [u8]) -> Result<(), ()> {
        if self.len() < chunk.len() {
            return Err(());
        }
        chunk.copy_from_slice(&self.as_ref()[self.len() - chunk.len()..]);
        self.truncate(self.len() - chunk.len());
        Ok(())
    }
}
impl<B> BufferExt for B where B: Buffer {}

#[cfg(test)]
mod tests {
    use alloc::vec;
    use rand_core::RngCore;

    use super::{DecryptionKey, EncryptionKey};

    #[test]
    fn keygen_encrypt_decrypt() {
        let mut rng = rand_dev::DevRng::new();

        let dk = DecryptionKey::generate(&mut rng);
        let ek = dk.encryption_key();

        let mut plaintext = vec![0; 70000];
        rng.fill_bytes(&mut plaintext);

        let ciphertext = {
            let mut buffer = plaintext.clone();
            ek.encrypt(&mut rng, &[], &mut buffer).unwrap();
            buffer
        };

        let plaintext_decrypted = {
            let mut buffer = ciphertext;
            dk.decrypt(&[], &mut buffer).unwrap();
            buffer
        };

        assert_eq!(plaintext, plaintext_decrypted);
    }

    #[test]
    fn wrong_ad_lead_to_decryption_error() {
        let mut rng = rand_dev::DevRng::new();

        let dk = DecryptionKey::generate(&mut rng);
        let ek = dk.encryption_key();

        let mut buffer = vec![0u8; 100];
        rng.fill_bytes(&mut buffer);

        ek.encrypt(&mut rng, b"right ad", &mut buffer).unwrap();
        assert!(dk.decrypt(b"wrong ad", &mut buffer).is_err());
    }

    #[test]
    fn decrypting_too_small_ciphertext_returns_error() {
        let mut rng = rand_dev::DevRng::new();

        let dk = DecryptionKey::generate(&mut rng);

        let mut ciphertext = [0u8; 100];
        rng.fill_bytes(&mut ciphertext);

        for i in 0..100 {
            let mut ciphertext = ciphertext[0..i].to_vec();
            assert!(dk.decrypt(&[], &mut ciphertext).is_err());
        }
    }

    #[test]
    fn serialize_deserialize() {
        let mut rng = rand_dev::DevRng::new();

        let dk = DecryptionKey::generate(&mut rng);
        let ek = dk.encryption_key();

        // Serialize and deserialize `dk`
        let dk_bytes = dk.to_bytes();
        let dk_deserialized = DecryptionKey::from_bytes(&dk_bytes).unwrap();
        assert_eq!(dk_deserialized.encryption_key(), ek);

        // Serialize and deserialize `ek`
        let ek_json = serde_json::to_string(&ek).unwrap();
        let ek_deserialized: EncryptionKey = serde_json::from_str(&ek_json).unwrap();
        assert_eq!(ek, ek_deserialized);
    }
}
