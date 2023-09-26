use dfns_key_export_client::KeyExportContext;

fn main() {
    print_export_request();
}

fn print_export_request() {
    let ctx = KeyExportContext::new().map_err(|_| {}).unwrap();
    let req = ctx
        .build_key_export_request("wa-xxx-xxx".to_string())
        .map_err(|_| {})
        .unwrap();
    println!("{:?}", req);
}
