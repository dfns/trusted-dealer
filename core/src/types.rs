//! Types used in key import and export functionalities

/// The protocol for which a key can be used.
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum KeyProtocol {
    ///GG18
    Gg18,
    ///Binance EDDSA
    BinanceEddsa,
    ///CGGMP21
    Cggmp21,
}

/// The curve for which a key can be used
#[derive(Debug, PartialEq, serde::Serialize, serde::Deserialize)]
#[serde(rename_all = "camelCase")]
pub enum KeyCurve {
    /// Secp256k1 curve
    Secp256k1,
    /// Ed25519 curve
    Ed25519,
}