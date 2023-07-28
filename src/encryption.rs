use aes_gcm::aead::{AeadCore, AeadInPlace, Buffer, KeyInit};
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

pub struct EncryptionKey(Point);
pub struct DecryptionKey(SecretScalar);

impl DecryptionKey {
    pub fn generate(rng: &mut (impl RngCore + CryptoRng)) -> Self {
        Self(SecretScalar::random(rng))
    }

    pub fn encryption_key(&self) -> EncryptionKey {
        EncryptionKey(Point::generator() * &self.0)
    }

    pub fn decrypt(&self, associated_data: &[u8], buffer: &mut impl Buffer) -> Result<(), Error> {
        // Read `eph_pub`
        let mut eph_pub = [0u8; EPH_KEY_SIZE];
        buffer.read_from_back(&mut eph_pub)?;
        let eph_pub = Point::from_bytes(&eph_pub).map_err(|_| Error)?;

        // Derive a `aes_key` from `eph_key`
        let mut aes_key = AesKey::default();
        let shared_secret = eph_pub * &self.0;
        let kdf = Hkdf::new(Some(HKDF_SALT), &shared_secret.to_bytes(true));
        kdf.expand(HKDF_KEY_LABEL, &mut aes_key)
            .map_err(|_| Error)?;

        // Decrypt `buffer` using `aes_key`
        let aes = Aes::new(&aes_key);
        // Nonce is zeroes string
        let aes_nonce = AesNonce::default();
        aes.decrypt_in_place(&aes_nonce, associated_data, buffer)
            .map_err(|_| Error)?;

        Ok(())
    }
}

impl EncryptionKey {
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
        let shared_secret = self.0 * &eph_key;
        let kdf = Hkdf::new(Some(HKDF_SALT), &shared_secret.to_bytes(true));
        kdf.expand(HKDF_KEY_LABEL, &mut aes_key)
            .map_err(|_| Error)?;

        // Encrypt `buffer` using `aes_key`
        let aes = Aes::new(&aes_key);
        // Nonce is zeroes string
        let aes_nonce = AesNonce::default();

        aes.encrypt_in_place(&aes_nonce, associated_data, buffer)
            .map_err(|_| Error)?;

        // Append `eph_pub` to the buffer
        buffer.extend_from_slice(&eph_pub).map_err(|_| Error)?;

        Ok(())
    }
}

/// Encryption / decryption error
#[derive(Debug, Clone, Copy)]
pub struct Error;

trait BufferExt: Buffer {
    /// Copies `buffer[buffer.len() - chunk.len()..]` into the `chunk` and truncates
    /// `chuck.len()` bytes from the buffer.
    fn read_from_back(&mut self, chunk: &mut [u8]) -> Result<(), Error> {
        if self.len() < chunk.len() {
            return Err(Error);
        }
        chunk.copy_from_slice(&self.as_ref()[self.len() - chunk.len()..]);
        self.truncate(self.len() - chunk.len());
        Ok(())
    }
}
impl<B> BufferExt for B where B: Buffer {}

#[cfg(test)]
mod tests {
    use rand_core::RngCore;

    use super::DecryptionKey;

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
}
