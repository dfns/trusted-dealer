use dfns_key_export_client::{interpolate_secret_key, InterpolateKeyError, KeyExportContext};
use dfns_key_export_common::{
    EncryptedShareAndIdentity, KeyCurve, KeyExportResponse, KeySharePlaintext,
};
use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};

fn get_random_keys_and_shares<E: Curve>(
    t: u16,
    n: u16,
) -> (SecretScalar<E>, Point<E>, Vec<KeySharePlaintext<E>>) {
    let mut rng = rand_dev::DevRng::new();

    let secret_key = SecretScalar::<E>::random(&mut rng);
    let public_key = Point::generator() * &secret_key;

    let secret_shares = {
        let key_shares_indexes = (1..=n)
            .map(|i| NonZero::from_scalar(Scalar::from(i)))
            .collect::<Option<Vec<_>>>()
            .unwrap();
        let f = generic_ec_zkp::polynomial::Polynomial::sample_with_const_term(
            &mut rng,
            usize::from(t) - 1,
            secret_key.clone(),
        );
        let secret_shares = key_shares_indexes
            .iter()
            .map(|i| f.value(i))
            .map(|mut x| SecretScalar::new(&mut x))
            .collect::<Vec<_>>();
        secret_shares
    };

    let shares = (1..=n)
        .zip(secret_shares)
        .map(|(i, s)| KeySharePlaintext::<E> {
            index: NonZero::from_scalar(Scalar::from(i)).unwrap(),
            secret_share: s,
            version: dfns_trusted_dealer_core::version::VersionGuard,
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

#[test]
fn key_export_context() {
    type E = generic_ec::curves::Secp256k1;
    let mut rng = rand_dev::DevRng::new();
    let (secret_key, public_key, shares) = get_random_keys_and_shares::<E>(3, 5);

    // create a new KeyExportContext and a KeyExportRequest
    let ctx = KeyExportContext::new().map_err(|_| {}).unwrap();
    let req = ctx.build_key_export_request().map_err(|_| {}).unwrap();

    // Create a KeyExportResponse
    let enc_key = req.encryption_key;
    let encrypted_shares_and_ids = shares
        .iter()
        .map(|s| {
            let mut buffer = serde_json::to_vec(s).unwrap();
            enc_key.encrypt(&mut rng, &[], &mut buffer).unwrap();
            EncryptedShareAndIdentity {
                signer_identity: Vec::new(),
                encrypted_key_share: buffer,
            }
        })
        .collect::<Vec<_>>();
    let resp = KeyExportResponse {
        min_signers: 3,
        public_key: public_key.to_bytes(true).to_vec(),
        protocol: dfns_key_export_common::KeyProtocol::Cggmp21,
        curve: KeyCurve::Secp256k1,
        encrypted_shares: encrypted_shares_and_ids.clone(),
    };

    // Call ctx.recover_secret_key(). Should recover the secret key.
    let recovered_secret_key = ctx
        .recover_secret_key(serde_json::to_string(&resp).unwrap())
        .expect("this call should not return error");
    assert_eq!(
        secret_key.as_ref().to_be_bytes().to_vec(),
        recovered_secret_key.to_bytes_be()
    );

    // Try an unsuported protocol. ctx.recover_secret_key() should return an error
    let resp = KeyExportResponse {
        min_signers: 3,
        public_key: public_key.to_bytes(true).to_vec(),
        protocol: dfns_key_export_common::KeyProtocol::Gg18,
        curve: KeyCurve::Secp256k1,
        encrypted_shares: encrypted_shares_and_ids.clone(),
    };
    let recovered_secret_key = ctx.recover_secret_key(serde_json::to_string(&resp).unwrap());
    assert!(recovered_secret_key.is_err());

    // Try with a difference public key.  ctx.recover_secret_key() should return an error
    let (_, public_key, _) = get_random_keys_and_shares::<E>(3, 5);
    let resp = KeyExportResponse {
        min_signers: 3,
        public_key: public_key.to_bytes(true).to_vec(),
        protocol: dfns_key_export_common::KeyProtocol::Cggmp21,
        curve: KeyCurve::Secp256k1,
        encrypted_shares: encrypted_shares_and_ids,
    };
    let recovered_secret_key = ctx.recover_secret_key(serde_json::to_string(&resp).unwrap());
    assert!(recovered_secret_key.is_err());
}
