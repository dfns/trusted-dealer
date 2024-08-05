use core::iter;

use common::{
    generic_ec::{curves, Curve, NonZero, Point, Scalar},
    rand_core::RngCore,
};
use dfns_key_import::{KeyCurve, KeyProtocol};
use key_share::Validate;

#[test_case::case(KeyProtocol::Cggmp21, KeyCurve::Secp256k1, 3, 5; "cggmp21_secp256k1_t3n5")]
#[test_case::case(KeyProtocol::Cggmp21, KeyCurve::Secp256k1, 2, 3; "cggmp21_secp256k1_t2n3")]
#[test_case::case(KeyProtocol::Cggmp21, KeyCurve::Stark, 3, 5; "cggmp21_stark_t3n5")]
#[test_case::case(KeyProtocol::Cggmp21, KeyCurve::Stark, 2, 3; "cggmp21_stark_t2n3")]
#[test_case::case(KeyProtocol::Frost, KeyCurve::Ed25519, 3, 5; "frost_ed25519_t3n5")]
#[test_case::case(KeyProtocol::Frost, KeyCurve::Ed25519, 2, 3; "frost_ed25519_t2n3")]
fn key_import(protocol: KeyProtocol, curve: KeyCurve, t: u16, n: u16) {
    match curve {
        KeyCurve::Secp256k1 => key_import_inner::<curves::Secp256k1>(protocol, curve, t, n),
        KeyCurve::Stark => key_import_inner::<curves::Stark>(protocol, curve, t, n),
        KeyCurve::Ed25519 => key_import_inner::<curves::Ed25519>(protocol, curve, t, n),
    }
}

fn key_import_inner<E: Curve>(protocol: KeyProtocol, curve: KeyCurve, t: u16, n: u16) {
    let mut rng = rand_dev::DevRng::new();
    // Generate signers info
    let decryption_keys =
        iter::repeat_with(|| common::encryption::DecryptionKey::generate(&mut rng))
            .take(n.into())
            .collect::<Vec<_>>();

    let signers_info = (1u8..)
        .zip(&decryption_keys)
        .map(|(i, dk)| dfns_key_import::types::SignerInfo {
            signer_id: vec![i],
            encryption_key: dk.encryption_key(),
        })
        .collect::<Vec<_>>();
    let signers_info = dfns_key_import::types::SignersInfo::from(signers_info);
    let signers_info = common::json_value::JsonValue::new(signers_info).unwrap();
    let signers_info = dfns_key_import::SignersInfo::new(signers_info).unwrap();

    // Generate key to be imported
    let secret_key = NonZero::<Scalar<E>>::random(&mut rng);
    let public_key = Point::generator() * secret_key;

    // Build key import request
    let req = dfns_key_import::build_key_import_request(
        &dfns_key_import::SecretScalar::from_bytes_be(secret_key.to_be_bytes().to_vec()),
        &signers_info,
        t,
        protocol,
        curve,
    )
    .unwrap();
    let req: dfns_key_import::types::KeyImportRequest = req.deserialize().unwrap();

    // Validate the request
    assert_eq!(req.min_signers, u32::from(t));
    assert_eq!(req.protocol, protocol);
    assert_eq!(req.curve, curve);

    // Decrypt key shares
    let key_shares: Vec<dfns_key_import::types::KeySharePlaintext<E>> = (1u8..)
        .zip(&decryption_keys)
        .zip(req.encrypted_key_shares)
        .map(|((i, dk), ciphertext)| {
            assert_eq!(ciphertext.signer_id, [i]);
            let mut key_share = ciphertext.encrypted_key_share;
            dk.decrypt(&[], &mut key_share).unwrap();
            serde_json::from_slice(&key_share).unwrap()
        })
        .collect();

    let key_shares = (0u16..)
        .zip(key_shares)
        .map(|(i, key_share)| {
            key_share::DirtyCoreKeyShare {
                i,
                key_info: key_share::DirtyKeyInfo {
                    curve: Default::default(),
                    shared_public_key: public_key,
                    public_shares: key_share.public_shares,
                    vss_setup: Some(key_share::VssSetup {
                        min_signers: t,
                        I: (1..=n)
                            .map(Scalar::from)
                            .map(|s| NonZero::from_scalar(s).unwrap())
                            .collect(),
                    }),
                },
                x: key_share.secret_share,
            }
            .validate()
            .unwrap()
        })
        .collect::<Vec<_>>();

    // Reconstruct secret key from the key shares
    let reconstructed_sk = key_share::reconstruct_secret_key(&key_shares).unwrap();
    assert_eq!(*reconstructed_sk.as_ref(), secret_key);
}

#[test]
fn eddsa_key_to_scalar() {
    let mut rng = rand_dev::DevRng::new();

    for _ in 0..100 {
        let mut secret_key = [0u8; 32];
        rng.fill_bytes(&mut secret_key);

        // Expected bytes representation of the scalar corresponding to the `secret_key`
        // derived following the EdDSA spec using dalek library. In little-endian format.
        let expected_le = ed25519::hazmat::ExpandedSecretKey::from(&secret_key)
            .scalar
            .to_bytes();
        // Reverse order to big-endian
        let expected_be = {
            let mut bytes = expected_le;
            bytes.reverse();
            bytes
        };

        // Bytes representation of the scalar corresponding to the `secret_key` derived
        // following the EdDSA spec using our library
        let actual_be = dfns_key_import::convert_eddsa_secret_key_to_scalar(&secret_key)
            .unwrap()
            .to_be_bytes();

        assert_eq!(expected_be, **actual_be);
    }
}
