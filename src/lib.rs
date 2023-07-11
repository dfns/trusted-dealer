use ecdsa_mpc::{
    algorithms::zkp::{ZkpPublicSetup, ZkpSetup},
    ecdsa::PaillierKeys,
};
use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

pub struct Share<E: Curve> {
    // 2 bytes integer representation
    pub i: u16,
    // fixed width integer representation; size depends on E
    pub secret_share: SecretScalar<E>,
    // fixed width representation; usually an integer; size depends on E
    pub shared_public_key: Point<E>,
    // two variable-width integers
    pub decryption_key: PaillierKeys,
    // variable length integer
    pub encryption_keys: Vec<curv::BigInt>,
    // 6 variable length integers
    pub range_proof_private: ZkpSetup,
    // 3 + 2*2 + n variable length integers, n also varying in runtime
    pub range_proofs: Vec<ZkpPublicSetup>,
}

#[derive(Debug, serde::Serialize)]
#[serde(bound = "")]
struct SerShare {
    // 2 bytes integer representation
    pub i: u16,
    // integer bytes
    pub secret_share: Vec<u8>,
    // encoded scalar
    pub shared_public_key: Vec<u8>,
    // two variable-width integers
    pub decryption_key: PaillierKeys,
    // variable length integer
    pub encryption_keys: Vec<curv::BigInt>,
    // 6 variable length integers
    pub range_proof_private: ZkpSetup,
    // 3 + 2*2 + n variable length integers, n also varying in runtime
    pub range_proofs: Vec<ZkpPublicSetup>,
}

impl<E: Curve> Share<E> {
    pub fn to_bytes(self) -> Vec<u8> {
        let this = SerShare {
            i: self.i,
            secret_share: self.secret_share.as_ref().to_be_bytes().to_vec(),
            shared_public_key: self.shared_public_key.to_bytes(false).to_vec(),
            decryption_key: self.decryption_key,
            encryption_keys: self.encryption_keys,
            range_proof_private: self.range_proof_private,
            range_proofs: self.range_proofs,
        };
        let mut buffer = Vec::new();
        let _result = ciborium::into_writer(&this, &mut buffer);
        buffer
    }
}

// in gg18 we have:
// key_params - t and n, well-known
// own_party_index - i
// secret_share, public_key
// own_he_keys - get from decryption_key and encryption_keys[i]
// party_he_keys - get from encryption_keys
// party_to_point_map - maps i to i+1
// range_proof_setups - from range_proofs and range_proof_private

pub fn shard<E: Curve, R: RngCore + CryptoRng>(
    shared_secret_key: &SecretScalar<E>,
    n: u16,
    t: u16,
    prime_pool: impl Iterator<Item = round_based_ing::KeygenSetup>,
    rng: &mut R,
) -> Vec<Share<E>> {
    // generate key material

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

    // generate auxiliary data

    let (setups, keys) = prime_pool
        .map(|p| p.into_inner())
        .take(n.into())
        .unzip::<_, _, Vec<_>, Vec<_>>();
    let encryption_keys = keys.iter().map(|k| k.ek.n.clone()).collect::<Vec<_>>();
    let range_proofs = setups
        .iter()
        .map(ZkpPublicSetup::from_private_zkp_setup)
        .collect::<Vec<_>>();

    secret_shares
        .into_iter()
        .zip(setups.into_iter())
        .zip(keys.into_iter())
        .zip(0u16..)
        .map(
            |(((secret_share, range_proof_private), decryption_key), i)| Share {
                i,
                secret_share,
                shared_public_key,
                decryption_key,
                encryption_keys: encryption_keys.clone(),
                range_proof_private,
                range_proofs: range_proofs.clone(),
            },
        )
        .collect()
}

pub fn test_scalar() -> SecretScalar<TheCurve> {
    SecretScalar::random(&mut rand_core::OsRng)
}

pub fn test_rand() -> impl RngCore + CryptoRng {
    rand_core::OsRng
}

pub fn test_pool() -> impl Iterator<Item = round_based_ing::KeygenSetup> {
    std::iter::repeat_with(|| round_based_ing::KeygenSetup::generate())
}

pub type TheCurve = generic_ec::curves::Secp256k1;

#[cfg(test)]
mod test {
    #[test]
    fn test() {
        let r = super::shard(&super::test_scalar(), 5, 3, super::test_pool(), &mut super::test_rand());
        assert_eq!(r.len(), 5);
    }
}
