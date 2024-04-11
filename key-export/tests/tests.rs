use common::{
    json_value::JsonValue,
    types::{KeyCurve, KeyProtocol},
};
use dfns_key_export::{
    EncryptedShareAndIdentity, KeyExportContext, KeyExportRequest, KeyExportResponse,
    KeySharePlaintext,
};

use generic_ec::{Curve, NonZero, Point, Scalar, SecretScalar};
use rand::{CryptoRng, RngCore};

fn random_key<E: Curve>(
    rng: &mut (impl RngCore + CryptoRng),
    t: u16,
    n: u16,
) -> (Point<E>, Vec<KeySharePlaintext<E>>) {
    let sk = NonZero::<SecretScalar<E>>::random(rng);

    let key_shares = key_share::trusted_dealer::builder(n)
        .set_threshold(Some(t))
        .set_shared_secret_key(sk.clone())
        .generate_shares(rng)
        .unwrap();
    let public_key = key_shares[0].shared_public_key;
    let key_shares = key_shares
        .into_iter()
        .map(|share| share.into_inner())
        .map(|share| KeySharePlaintext {
            version: Default::default(),
            index: share.share_preimage(share.i).unwrap(),
            secret_share: share.x,
        })
        .collect::<Vec<_>>();

    (*public_key, key_shares)
}

#[test_case::case(KeyProtocol::Cggmp21, KeyCurve::Secp256k1; "cggmp21_secp256k1")]
#[test_case::case(KeyProtocol::Cggmp21, KeyCurve::Stark; "cggmp21_stark")]
#[test_case::case(KeyProtocol::Frost, KeyCurve::Ed25519; "frost_ed25519")]
fn key_export(protocol: KeyProtocol, curve: KeyCurve) {
    match curve {
        KeyCurve::Secp256k1 => key_export_inner::<generic_ec::curves::Secp256k1>(protocol, curve),
        KeyCurve::Stark => key_export_inner::<generic_ec::curves::Stark>(protocol, curve),
        KeyCurve::Ed25519 => key_export_inner::<generic_ec::curves::Ed25519>(protocol, curve),
    }
}

fn key_export_inner<E: Curve>(protocol: KeyProtocol, curve: KeyCurve) {
    let mut rng = rand_dev::DevRng::new();

    let (public_key, key_shares) = random_key::<E>(&mut rng, 3, 5);

    // Create a new KeyExportContext
    let ctx = KeyExportContext::new().unwrap();

    // Build a key export request
    let req = ctx.build_key_export_request().unwrap();
    let req: KeyExportRequest = req.deserialize().unwrap();

    // Construct KeyExportResponse
    let resp =
        build_key_export_response::<E>(&mut rng, &req, protocol, curve, public_key, &key_shares);
    let resp_json = JsonValue::new(resp.clone()).unwrap();

    // Recover secret key
    let recovered_secret_key = ctx
        .recover_secret_key(resp_json)
        .expect("this call should not return error");
    let recovered_secret_key = Scalar::from_be_bytes(recovered_secret_key.to_bytes_be()).unwrap();
    assert_eq!(public_key, Point::generator() * recovered_secret_key);

    // If we change the public key, key recovery fails
    let resp = KeyExportResponse {
        public_key: (public_key + Point::generator()).to_bytes(true).to_vec(),
        ..resp
    };
    let resp = JsonValue::new(resp).unwrap();
    let recovered_secret_key = ctx.recover_secret_key(resp);
    assert!(recovered_secret_key.is_err());
}

#[test]
fn exporting_unsupported_scheme_returns_error() {
    let protocol = KeyProtocol::Cggmp21;
    let curve = KeyCurve::Secp256k1;
    type E = generic_ec::curves::Secp256k1;

    let mut rng = rand_dev::DevRng::new();

    let (public_key, key_shares) = random_key::<E>(&mut rng, 3, 5);

    // Create a new KeyExportContext
    let ctx = KeyExportContext::new().unwrap();

    // Build a key export request
    let req = ctx.build_key_export_request().unwrap();
    let req: KeyExportRequest = req.deserialize().unwrap();

    // Construct KeyExportResponse
    let resp =
        build_key_export_response::<E>(&mut rng, &req, protocol, curve, public_key, &key_shares);

    // Change protocol to Gg18 which is not supported
    let resp = KeyExportResponse {
        protocol: KeyProtocol::Gg18,
        ..resp
    };
    let resp = JsonValue::new(resp).unwrap();
    let recovered_secret_key = ctx.recover_secret_key(resp);
    assert!(recovered_secret_key.is_err());
}

/// Takes a key export request and key to be exported, returns the key export response
fn build_key_export_response<E: Curve>(
    rng: &mut (impl RngCore + CryptoRng),
    req: &KeyExportRequest,
    protocol: KeyProtocol,
    curve: KeyCurve,
    public_key: Point<E>,
    key_shares: &[KeySharePlaintext<E>],
) -> KeyExportResponse {
    assert!(req
        .supported_schemes
        .contains(&dfns_key_export::SupportedScheme { protocol, curve }));
    let enc_key = &req.encryption_key;
    let encrypted_shares_and_ids = key_shares
        .iter()
        .map(|s| {
            let mut buffer = serde_json::to_vec(s).unwrap();
            enc_key.encrypt(rng, &[], &mut buffer).unwrap();
            EncryptedShareAndIdentity {
                signer_id: Vec::new(),
                encrypted_key_share: buffer,
            }
        })
        .collect::<Vec<_>>();
    KeyExportResponse {
        min_signers: 3,
        public_key: public_key.to_bytes(true).to_vec(),
        protocol,
        curve,
        encrypted_shares: encrypted_shares_and_ids.clone(),
    }
}
