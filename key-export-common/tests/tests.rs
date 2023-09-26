use dfns_key_export_common::{
    parse_and_interpolate_secret_key, InterpolateKeyError, KeySharePlaintext,
};
use dfns_key_import_common::split_secret_key;
use generic_ec::{NonZero, Scalar, SecretScalar};

#[test]
fn interpolate_key() {
    type E = generic_ec::curves::Secp256k1;

    // Split a random secret key
    let (t, n) = (3, 5); // Degree of polynomial is t-1
    let mut rng = rand_dev::DevRng::new();
    let secret_key = generic_ec::SecretScalar::<E>::random(&mut rng);
    let public_key = generic_ec::Point::generator() * &secret_key;
    let public_key = public_key.to_bytes(true).to_vec();

    let shares = split_secret_key(&mut rng, t, n, &secret_key).unwrap();

    let mut shares = (1..n + 1)
        .zip(shares)
        .map(|(i, s)| KeySharePlaintext::<E> {
            index: generic_ec::NonZero::from_scalar(generic_ec::Scalar::from(i)).unwrap(),
            secret_share: s.secret_share.clone(),
        })
        .map(|share_plaintext| serde_json::to_vec(&share_plaintext).unwrap())
        .collect::<Vec<Vec<u8>>>();

    // Interpolate the secret key from all shares.
    let secret_key_interp = parse_and_interpolate_secret_key(&shares, &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());

    // Interpolate the secret key with 3 shares. Should still work.
    let secret_key_interp = parse_and_interpolate_secret_key(&shares[..4], &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());

    //Interpolate with 2 shares. This should return an error.
    let res = parse_and_interpolate_secret_key::<E>(&shares[..2], &public_key);
    assert!(res.is_err());
    assert!(matches!(
        res.unwrap_err(),
        InterpolateKeyError::CannotVerifySecretKey
    ));

    //Interpolate with 1 shares. This should return an error.
    let res = parse_and_interpolate_secret_key::<E>(&shares[..1], &public_key);
    assert!(res.is_err());
    assert!(matches!(
        res.expect_err(""),
        InterpolateKeyError::NotEnoughShares
    ));

    // Interpolate and compare against a random public key. Should return an error.
    let random_pk =
        generic_ec::Point::generator() * &generic_ec::SecretScalar::<E>::random(&mut rng);
    let random_pk = random_pk.to_bytes(true).to_vec();

    let res = parse_and_interpolate_secret_key::<E>(&shares, &random_pk);
    assert!(res.is_err());
    assert!(matches!(
        res.expect_err(""),
        InterpolateKeyError::CannotVerifySecretKey
    ));

    // Change the order of the shares. Nothing should change.
    shares.reverse();

    // Interpolate the secret key from all shares.
    let secret_key_interp = parse_and_interpolate_secret_key::<E>(&shares, &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());

    // Interpolate the secret key with 3 shares. Should still work.
    let secret_key_interp =
        parse_and_interpolate_secret_key::<E>(&shares[..4], &public_key).unwrap();
    assert_eq!(secret_key.as_ref(), secret_key_interp.as_ref());
}

#[test]
fn parse_key_share_plaintext() {
    type E = generic_ec::curves::Secp256k1;

    let mut rng = rand_dev::DevRng::new();
    let key_share_plaintext = KeySharePlaintext {
        secret_share: SecretScalar::<E>::random(&mut rng),
        index: NonZero::<Scalar<E>>::random(&mut rng),
    };
    let key_share_plaintext = serde_json::to_string(&key_share_plaintext).unwrap();
    // println!("{:?}", &key_share_plaintext1);
    let _: KeySharePlaintext<E> = serde_json::from_str(&key_share_plaintext).unwrap();
}
