#[derive(Debug, Clone, Copy)]
pub struct VersionGuard;

impl serde::Serialize for VersionGuard {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: serde::Serializer,
    {
        serializer.serialize_u8(crate::VERSION)
    }
}

impl<'de> serde::Deserialize<'de> for VersionGuard {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let version = u8::deserialize(deserializer)?;
        if version != crate::VERSION {
            Err(<D::Error as serde::de::Error>::custom(&alloc::format!(
                "you seem to be using old version of the library: version field of serialized \
                data (v{version}) doesn't match version supported by this library (v{})",
                crate::VERSION
            )))
        } else {
            Ok(Self)
        }
    }
}
