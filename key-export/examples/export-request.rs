use common::{
    encryption,
    types::{KeyCurve, KeyProtocol},
};
use generic_ec::{NonZero, Point, Scalar, SecretScalar};

fn main() {
    print_export_request();
    print_export_response();
}

fn print_export_request() {
    let ctx = dfns_key_export::KeyExportContext::new().unwrap();
    let req = ctx.build_key_export_request().unwrap();
    println!("{:?}", req);
}

fn print_export_response() {
    type E = generic_ec::curves::Secp256k1;
    let mut rng = rand_dev::DevRng::new();
    let decryption_key = encryption::DecryptionKey::generate(&mut rng);

    let shares = [dfns_key_export::types::KeySharePlaintext {
        version: common::version::VersionGuard,
        index: NonZero::<Scalar<_>>::random(&mut rng),
        secret_share: NonZero::<SecretScalar<E>>::random(&mut rng),
    }]
    .to_vec();

    let encrypted_shares_and_ids = shares
        .iter()
        .map(|s| {
            let mut buffer = serde_json::to_vec(s).unwrap();
            decryption_key
                .encryption_key()
                .encrypt(&mut rng, &[], &mut buffer)
                .unwrap();
            dfns_key_export::types::EncryptedShareAndIdentity {
                signer_id: b"SignerPK".to_vec(),
                encrypted_key_share: buffer,
            }
        })
        .collect::<Vec<_>>();

    let resp = dfns_key_export::types::KeyExportResponse {
        min_signers: 3,
        public_key: Point::<E>::zero().to_bytes(true).to_vec(),
        protocol: KeyProtocol::Cggmp21,
        curve: KeyCurve::Secp256k1,
        encrypted_shares: encrypted_shares_and_ids,
    };

    print!("{}", serde_json::to_string(&resp).unwrap());
}
