#[test]
fn split_and_reconstruct_key() {
    type E = generic_ec::curves::Secp256k1;

    let (t, n) = (3, 5);
    let mut rng = rand_dev::DevRng::new();
    let secret_key = generic_ec::SecretScalar::<E>::random(&mut rng);
    let public_key = generic_ec::Point::generator() * &secret_key;

    let shares = dfns_key_import_common::split_secret_key(&mut rng, t, n, &secret_key).unwrap();

    // Convert shares into cggmp21 shares
    let indexes = (1..=n)
        .map(|i| generic_ec::Scalar::from(i).try_into())
        .collect::<Result<Vec<_>, _>>()
        .unwrap();
    let shares = (0..)
        .zip(shares)
        .map(|(i, s)| {
            cggmp21::key_share::DirtyIncompleteKeyShare {
                curve: Default::default(),
                i,
                shared_public_key: public_key,
                public_shares: s.public_shares,
                vss_setup: Some(cggmp21::key_share::VssSetup {
                    min_signers: t,
                    I: indexes.clone(),
                }),
                x: s.secret_share,
            }
            .try_into()
        })
        .collect::<Result<Vec<cggmp21::IncompleteKeyShare<E>>, _>>()
        .unwrap();

    // Reconstruct a secret key corresponding to the key shares
    let reconstructed_sk = cggmp21::key_share::reconstruct_secret_key(&shares).unwrap();
    assert_eq!(secret_key.as_ref(), reconstructed_sk.as_ref());
}
