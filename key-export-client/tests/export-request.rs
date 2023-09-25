use dfns_key_export_client::KeyExportContext;

// Not a real test, just prints out the key-export request that is to be sent to Dfns API.
#[test]
fn print_request() {
    let ctx = KeyExportContext::new().map_err(|_| {}).unwrap();
    let req = ctx
        .build_key_export_request(format!("wa-xxx-xxx"))
        .map_err(|_| {})
        .unwrap();
    println!("{:?}", req);
    // let req_parsed: KeyExportRequest = serde_json::from_str(&req).unwrap();
    // println!("{}", hex::encode(req_parsed.encryption_key.to_bytes()));
}
