//! Types used in key import and export functionalities

#[cfg(target_arch = "wasm32")]
use wasm_bindgen::prelude::wasm_bindgen;

/// The protocol for which a key can be used.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
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
#[cfg_attr(target_arch = "wasm32", wasm_bindgen)]
pub enum KeyCurve {
    /// Secp256k1 curve
    Secp256k1,
    /// Stark curve
    Stark,
    /// Ed25519 curve
    Ed25519,
}
