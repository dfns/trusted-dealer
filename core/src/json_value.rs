//! JSON Value
//!
//! On wasm target, it's equivalent to `JsValue`. It can be used as a type of
//! input arguments or return value in functions exposed to outside of WASM
//! module.
//!
//! On non-wasm targets, it's represented as `serde_json::Value`. It's done
//! purely for tests purposes, so the library is still usable on non-wasm
//! targets, for instance, to do end-to-end tests.

/// JSON Value
#[cfg(target_arch = "wasm32")]
#[derive(Debug)]
pub struct JsonValue(wasm_bindgen::JsValue);

#[cfg(target_arch = "wasm32")]
impl JsonValue {
    /// Constructs JsonValue
    pub fn new<T: serde::Serialize>(value: T) -> Result<Self, serde_wasm_bindgen::Error> {
        serde_wasm_bindgen::to_value(&value).map(Self)
    }

    /// Deserializes json value into `T`
    pub fn deserialize<T: serde::de::DeserializeOwned>(
        self,
    ) -> Result<T, serde_wasm_bindgen::Error> {
        serde_wasm_bindgen::from_value(self.0)
    }
}

#[cfg(target_arch = "wasm32")]
impl wasm_bindgen::describe::WasmDescribe for JsonValue {
    fn describe() {
        wasm_bindgen::JsValue::describe()
    }
}

#[cfg(target_arch = "wasm32")]
impl wasm_bindgen::convert::IntoWasmAbi for JsonValue {
    type Abi = <wasm_bindgen::JsValue as wasm_bindgen::convert::IntoWasmAbi>::Abi;

    fn into_abi(self) -> Self::Abi {
        self.0.into_abi()
    }
}

#[cfg(target_arch = "wasm32")]
impl wasm_bindgen::convert::FromWasmAbi for JsonValue {
    type Abi = <wasm_bindgen::JsValue as wasm_bindgen::convert::FromWasmAbi>::Abi;

    unsafe fn from_abi(js: Self::Abi) -> Self {
        Self(wasm_bindgen::JsValue::from_abi(js))
    }
}

/// JSON Value
#[cfg(not(target_arch = "wasm32"))]
#[derive(Debug)]
pub struct JsonValue(serde_json::Value);

#[cfg(not(target_arch = "wasm32"))]
impl JsonValue {
    /// Constructs JsonValue
    pub fn new<T: serde::Serialize>(value: T) -> Result<Self, serde_json::Error> {
        serde_json::to_value(value).map(Self)
    }

    /// Deserializes json value into `T`
    pub fn deserialize<T: serde::de::DeserializeOwned>(self) -> Result<T, serde_json::Error> {
        serde_json::from_value(self.0)
    }
}
