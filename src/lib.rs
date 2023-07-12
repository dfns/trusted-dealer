#[cfg(test)]
mod test;

use std::collections::HashMap;

use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

pub use generic_ec::curves::Secp256k1;

#[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
#[serde(bound = "")]
pub struct Share<E: Curve> {
    // 2 bytes integer representation
    pub i: u16,
    // fixed width representation; usually an integer; size depends on E
    pub shared_public_key: Point<E>,
    // fixed width integer representation; size depends on E
    pub secret_share: SecretScalar<E>,
    // dynamic array of fixed width representations; fixed size depends on E
    pub public_shares: Vec<Point<E>>,
}

impl<E: Curve> Share<E> {
    pub fn to_bytes(&self) -> Vec<u8> {
        let mut buffer = Vec::new();
        let _result = ciborium::into_writer(self, &mut buffer);
        buffer
    }
}

pub fn shard<E: Curve, R: RngCore + CryptoRng>(
    shared_secret_key: &SecretScalar<E>,
    n: u16,
    t: u16,
    rng: &mut R,
) -> Vec<Share<E>> {
    let key_shares_indexes = (1..=n)
        .map(|i| generic_ec::NonZero::from_scalar(Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .unwrap();
    let (shared_public_key, secret_shares) = {
        let f = generic_ec_zkp::polynomial::Polynomial::sample_with_const_term(
            rng,
            usize::from(t) - 1,
            shared_secret_key.clone(),
        );
        let pk = Point::generator() * f.value::<_, Scalar<_>>(&Scalar::zero());
        let shares = key_shares_indexes
            .iter()
            .map(|i| f.value(i))
            .map(|mut x| SecretScalar::new(&mut x))
            .collect::<Vec<_>>();
        (pk, shares)
    };

    let public_shares = secret_shares.iter().map(|x| Point::generator() * x).collect::<Vec<Point<E>>>();

    secret_shares
        .into_iter()
        .zip(0u16..)
        .map(
            |(secret_share, i)| Share {
                i,
                secret_share,
                shared_public_key,
                public_shares: public_shares.clone(),
            },
        )
        .collect()
}

type Identity = Vec<u8>;

#[derive(Clone)]
pub struct Signer {
    pub public_key: Vec<u8>,
    pub identity: Identity,
}

pub trait ApiUser {
    fn get_signers(&mut self) -> std::io::Result<Vec<Signer>>;
    fn send_shards(&mut self, shares: &HashMap<Identity, Vec<u8>>) -> std::io::Result<()>;
}

pub struct EncryptionKey {
    certs: openssl::stack::Stack<openssl::x509::X509>,
}

impl EncryptionKey {
    pub fn open(path: impl AsRef<std::path::Path>) -> std::io::Result<Self> {
        use std::io::Read;
        let mut cert_file = std::fs::File::open(path)?;
        let mut cert_bytes = Vec::new();
        let _ = cert_file.read_exact(&mut cert_bytes)?;
        Self::from_bytes(&cert_bytes)
    }

    pub fn from_bytes(cert_bytes: &[u8]) -> std::io::Result<Self> {
        let cert = openssl::x509::X509::from_pem(&cert_bytes)?;
        let mut certs = openssl::stack::Stack::new()?;
        certs.push(cert)?;

        Ok(Self { certs })
    }

    pub fn encrypt(&self, input: &[u8]) -> std::io::Result<Vec<u8>> {
        let bundle = openssl::pkcs7::Pkcs7::encrypt(
            self.certs.as_ref(),
            input,
            openssl::symm::Cipher::aes_256_cbc(),
            openssl::pkcs7::Pkcs7Flags::empty(),
        )?;
        Ok(bundle.to_pem()?)
    }
}

pub fn send_all<Api: ApiUser>(api: &mut Api, shards: &[Share<Secp256k1>]) -> std::io::Result<()> {
    let mut signers = api.get_signers()?;
    signers.sort_unstable_by(|s1, s2| s1.identity.cmp(&s2.identity));
    let mut dests = HashMap::new();
    for (signer, shard) in signers.into_iter().zip(shards) {
        let key = EncryptionKey::from_bytes(&signer.public_key)?;
        let shard = key.encrypt(&shard.to_bytes())?;
        dests.insert(signer.identity, shard);
    }
    api.send_shards(&dests)
}
