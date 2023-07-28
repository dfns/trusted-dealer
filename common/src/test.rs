use generic_ec::curves::Secp256k1;

const T: u16 = 3;
const N: u16 = 5;

fn read_share(bytes: &[u8]) -> cggmp21::key_share::IncompleteKeyShare<Secp256k1> {
    let share: super::Share<Secp256k1> = ciborium::from_reader(bytes).unwrap();
    let indexes = (1..=N).map(|i| generic_ec::Scalar::from(i).try_into().unwrap()).collect();
    cggmp21::key_share::DirtyIncompleteKeyShare {
        curve: generic_ec::serde::CurveName::<Secp256k1>::new(),
        i: share.i,
        shared_public_key: share.shared_public_key,
        public_shares: share.public_shares,
        vss_setup: Some(cggmp21::key_share::VssSetup {
            min_signers: T,
            I: indexes,
        }),
        x: share.secret_share,
    }
    .try_into().unwrap()
}

#[test]
fn shard_and_restore() {
    let mut rng = rand_core::OsRng;
    let secret_share = generic_ec::SecretScalar::<Secp256k1>::random(&mut rng);
    let shards = super::shard(&secret_share, N, T, &mut rng);
    let shares = shards.into_iter().map(|x| read_share(&x.to_bytes())).collect::<Vec<_>>();

    let secret = cggmp21::key_share::reconstruct_secret_key(&shares).unwrap();
    assert_eq!(secret_share.as_ref(), secret.as_ref());
}
