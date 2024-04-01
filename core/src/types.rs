//! Types used in key import and export functionalities

/// The protocol for which a key can be used.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub enum KeyProtocol {
    /// GG18
    Gg18,
    /// Binance EDDSA
    BinanceEddsa,
    /// CGGMP21
    Cggmp21,
    /// FROST
    Frost,
}

/// The curve for which a key can be used
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
#[cfg_attr(feature = "wasm", wasm_bindgen::prelude::wasm_bindgen)]
pub enum KeyCurve {
    /// Secp256k1 curve
    Secp256k1,
    /// Stark curve
    Stark,
    /// Ed25519 curve
    Ed25519,
}
