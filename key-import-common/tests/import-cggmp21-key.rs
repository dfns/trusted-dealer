use generic_ec::Scalar;
use key_share::Validate as _;

#[test]
fn split_and_reconstruct_key() {
    type E = generic_ec::curves::Secp256k1;

    let (t, n) = (3, 5);
    let mut rng = rand_dev::DevRng::new();
    let secret_key = generic_ec::NonZero::<generic_ec::SecretScalar<E>>::random(&mut rng);
    let public_key = generic_ec::Point::generator() * &secret_key;

    let shares = dfns_key_import_common::split_secret_key(&mut rng, t, n, &secret_key).unwrap();

    // Convert shares into cggmp21 shares
    let indexes = (1..=n)
        .map(|i| generic_ec::NonZero::from_scalar(generic_ec::Scalar::from(i)))
        .collect::<Option<Vec<_>>>()
        .unwrap();
    let shares = (0..)
        .zip(shares)
        .map(|(i, s)| {
            key_share::DirtyCoreKeyShare {
                i,
                key_info: key_share::DirtyKeyInfo {
                    curve: Default::default(),
                    shared_public_key: public_key,
                    public_shares: s.public_shares,
                    vss_setup: Some(key_share::VssSetup {
                        min_signers: t,
                        I: indexes.clone(),
                    }),
                },
                x: s.secret_share,
            }
            .validate()
        })
        .collect::<Result<Vec<key_share::CoreKeyShare<E>>, _>>()
        .unwrap();

    // Reconstruct a secret key corresponding to the key shares
    let reconstructed_sk = key_share::reconstruct_secret_key(&shares).unwrap();
    assert_eq!(
        AsRef::<Scalar<E>>::as_ref(&secret_key),
        reconstructed_sk.as_ref()
    );
}
