use generic_ec::{Curve, Point, Scalar, SecretScalar};
use rand_core::{CryptoRng, RngCore};

#[derive(Debug, serde::Serialize)]
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

pub fn test_scalar() -> SecretScalar<TheCurve> {
    SecretScalar::random(&mut rand_core::OsRng)
}

pub type TheCurve = generic_ec::curves::Secp256k1;

#[cfg(test)]
mod test {
    #[test]
    fn test() {
        let shards = super::shard(&super::test_scalar(), 5, 3, &mut rand_core::OsRng);
        assert_eq!(shards.len(), 5);
        for shard in &shards {
            assert_eq!(shard.public_shares.len(), 5);
        }
    }
}
