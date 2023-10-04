use dfns_key_export_client::KeyExportContext;
use dfns_key_export_common::{EncryptedShareAndIdentity, KeyExportResponse, KeySharePlaintext};
use dfns_trusted_dealer_core::{
    encryption,
    types::{KeyCurve, KeyProtocol},
};
use generic_ec::{NonZero, Point, SecretScalar};

fn main() {
    print_export_request();
    print_export_response();
}

fn print_export_request() {
    let ctx = KeyExportContext::new().map_err(|_| {}).unwrap();
    let req = ctx.build_key_export_request().map_err(|_| {}).unwrap();
    println!("{:?}", serde_json::to_string(&req).unwrap());
}

fn print_export_response() {
    type E = generic_ec::curves::Secp256k1;
    let mut rng = rand_dev::DevRng::new();
    let decryption_key = encryption::DecryptionKey::generate(&mut rng);

    let shares = [KeySharePlaintext {
        version: dfns_trusted_dealer_core::version::VersionGuard,
        index: NonZero::random(&mut rng),
        secret_share: SecretScalar::<E>::random(&mut rng),
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
            EncryptedShareAndIdentity {
                signer_id: b"SignerPK".to_vec(),
                encrypted_key_share: buffer,
            }
        })
        .collect::<Vec<_>>();

    let resp = KeyExportResponse {
        min_signers: 3,
        public_key: Point::<E>::zero().to_bytes(true).to_vec(),
        protocol: KeyProtocol::Cggmp21,
        curve: KeyCurve::Secp256k1,
        encrypted_shares: encrypted_shares_and_ids,
    };

    print!("{}", serde_json::to_string(&resp).unwrap());
}
