use dfns_key_export_client::{interpolate_secret_key, InterpolateKeyError};
use dfns_key_export_common::KeySharePlaintext;
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

fn get_random_keys_and_shares<E: Curve>(
    t: u16,
    n: u16,
) -> (SecretScalar<E>, Point<E>, Vec<KeySharePlaintext<E>>) {
    let mut rng = rand_dev::DevRng::new();

    let secret_key = SecretScalar::<E>::random(&mut rng);
    let public_key = Point::generator() * &secret_key;

    let secret_shares =
        dfns_key_import_common::split_secret_key(&mut rng, t, n, &secret_key).unwrap();

    let shares = (1..n + 1)
        .zip(secret_shares)
        .map(|(i, s)| KeySharePlaintext::<E> {
            index: NonZero::from_scalar(Scalar::from(i)).unwrap(),
            secret_share: s.secret_share.clone(),
        })
        .collect::<Vec<KeySharePlaintext<E>>>();

    (secret_key, public_key, shares)
}

#[test]
fn interpolate_key() {
    type E = generic_ec::curves::Secp256k1;
    let (secret_key, public_key, mut shares) = get_random_keys_and_shares::<E>(3, 5);

    // Interpolate the secret key from all shares.
    let secret_key_interp = interpolate_secret_key(&shares, &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());

    // Interpolate the secret key with 3 shares. Should still work.
    let secret_key_interp = interpolate_secret_key(&shares[..4], &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());

    //Interpolate with 2 shares. This should return an error.
    let res = interpolate_secret_key::<E>(&shares[..2], &public_key);
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        InterpolateKeyError::CannotVerifySecretKey
    ));

    //Interpolate with 1 shares. This should return an error.
    let res = interpolate_secret_key::<E>(&shares[..1], &public_key);
    assert!(res.is_err());
    assert!(matches!(
        res.expect_err(""),
        InterpolateKeyError::NotEnoughShares
    ));

    // Interpolate and compare against a random public key. Should return an error.
    let mut rng = rand_dev::DevRng::new();
    let random_pk =
        generic_ec::Point::generator() * &generic_ec::SecretScalar::<E>::random(&mut rng);

    let res = interpolate_secret_key::<E>(&shares, &random_pk);
    assert!(res.is_err());
    assert!(matches!(
        res.expect_err(""),
        InterpolateKeyError::CannotVerifySecretKey
    ));

    // Change the order of the shares. Nothing should change.
    shares.reverse();

    // Interpolate the secret key from all shares.
    let secret_key_interp = interpolate_secret_key::<E>(&shares, &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());

    // Interpolate the secret key with 3 shares. Should still work.
    let secret_key_interp = interpolate_secret_key::<E>(&shares[..4], &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());
}
