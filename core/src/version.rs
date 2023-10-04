//! Versioning util.
//!
//! Version is embedded into all serialized structs (public key, signers info, etc.).
//! Incrementing the version will force clients to update the library.

/// Ensures the serialized version matches the version of the lib
#[derive(Debug, Clone, Copy)]
pub struct VersionGuard<const V: u8>;

impl<const V: u8> serde::Serialize for VersionGuard<V> {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(V)
    }
}

impl<'de, const V: u8> serde::Deserialize<'de> for VersionGuard<V> {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let version = u8::deserialize(deserializer)?;
        if version != V {
            Err(<D::Error as serde::de::Error>::custom(&alloc::format!(
                "you seem to be using old version of the library: version field of serialized \
                data (v{version}) doesn't match version supported by this library (v{V})"
            )))
        } else {
            Ok(Self)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::VersionGuard;

    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct TestStructV1 {
        v: VersionGuard<1>,
        i: u32,
    }
    #[derive(Clone, Debug, serde::Serialize, serde::Deserialize)]
    struct TestStructV2 {
        v: VersionGuard<2>,
        i: u32,
    }

    #[test]
    fn version_guard() {
        let item_v1 = TestStructV1 {
            v: VersionGuard,
            i: 42,
        };
        let item_v2 = TestStructV2 {
            v: VersionGuard,
            i: 42,
        };
        let item_v1_ser = serde_json::to_vec(&item_v1).unwrap();
        let item_v2_ser = serde_json::to_vec(&item_v2).unwrap();

        assert_ne!(item_v1_ser, item_v2_ser);

        assert!(serde_json::from_slice::<TestStructV1>(&item_v1_ser).is_ok());
        assert!(serde_json::from_slice::<TestStructV2>(&item_v1_ser).is_err());
    }
}
