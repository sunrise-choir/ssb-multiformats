//! Implementation of [ssb multihashes](https://spec.scuttlebutt.nz/feed/datatypes.html#multihash).
use std::fmt;
use std::io::{self, Write};

use serde::{
    de::{Deserialize, Deserializer, Error},
    ser::{Serialize, Serializer},
};

use super::{base64, serde, skip_prefix, split_at_byte};

/// A multihash that owns its data.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub enum Multihash {
    /// An ssb [message](https://spec.scuttlebutt.nz/feed/messages.html).
    Message([u8; 32]),
    /// An ssb [blob](TODO).
    Blob([u8; 32]),
}

enum Target {
    Message,
    Blob,
}

impl Multihash {
    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/feed/datatypes.html#multihash-legacy-encoding)
    /// into a `Multihash`.
    pub fn from_legacy(mut s: &[u8]) -> Result<(Multihash, &[u8]), DecodeLegacyError> {
        let target;

        if let Some(tail) = skip_prefix(s, b"%") {
            s = tail;
            target = Target::Message;
        } else {
            let tail = skip_prefix(s, b"&").ok_or(DecodeLegacyError::Sigil)?;

            s = tail;
            target = Target::Blob;
        }

        let (data, suffix) = split_at_byte(s, 0x2E).ok_or(DecodeLegacyError::NoDot)?;

        let tail = skip_prefix(suffix, SHA256_SUFFIX).ok_or(DecodeLegacyError::UnknownSuffix)?;

        if data.len() != SHA256_BASE64_LEN {
            return Err(DecodeLegacyError::Sha256WrongSize);
        }

        if data[SHA256_BASE64_LEN - 2] == b"="[0] {
            return Err(DecodeLegacyError::Sha256WrongSize);
        }

        if data[SHA256_BASE64_LEN - 1] != b"="[0] {
            return Err(DecodeLegacyError::Sha256WrongSize);
        }

        let mut dec_data = [0_u8; 32];
        base64::decode_config_slice(data, base64::STANDARD, &mut dec_data[..])
            .map_err(DecodeLegacyError::InvalidBase64)
            .map(|_| {
                let multihash = match target {
                    Target::Blob => Multihash::Blob(dec_data),
                    Target::Message => Multihash::Message(dec_data),
                };
                (multihash, tail)
            })
    }

    /// Serialize a `Multihash` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/feed/datatypes.html#multihash-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self {
            Multihash::Message(ref bytes) => {
                w.write_all(b"%")?;
                Multihash::write_legacy_hash_and_suffix(bytes, w)
            }
            Multihash::Blob(ref bytes) => {
                w.write_all(b"&")?;
                Multihash::write_legacy_hash_and_suffix(bytes, w)
            }
        }
    }

    fn write_legacy_hash_and_suffix<W: Write>(bytes: &[u8], w: &mut W) -> Result<(), io::Error> {
        let data = base64::encode_config(bytes, base64::STANDARD);
        w.write_all(data.as_bytes())?;

        w.write_all(b".")?;
        w.write_all(SHA256_SUFFIX)
    }

    /// Serialize a `Multihash` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/feed/datatypes.html#multihash-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(SSB_SHA256_ENCODED_LEN);
        self.to_legacy(&mut out).unwrap();
        out
    }

    /// Serialize a `Multihash` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/feed/datatypes.html#multihash-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
    }
}

impl Serialize for Multihash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_legacy_string())
    }
}

impl<'de> Deserialize<'de> for Multihash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Multihash::from_legacy(s.as_bytes())
            .map(|(mh, _)| mh)
            .map_err(|err| D::Error::custom(format!("Invalid multihash: {}", err)))
    }
}

/// Everything that can go wrong when decoding a `Multihash` from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeLegacyError {
    /// Input did not start with the `"@"` sigil.
    Sigil,
    /// Input did not contain a `"."` to separate the data from the suffix.
    NoDot,
    /// The base64 portion of the key was invalid.
    InvalidBase64(base64::DecodeError),
    /// The suffix is not known to this ssb implementation.
    UnknownSuffix,
    /// The suffix declares a sha256 hash, but the data length does not match.
    Sha256WrongSize,
}

impl fmt::Display for DecodeLegacyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            DecodeLegacyError::Sigil => write!(f, "Invalid sigil"),
            DecodeLegacyError::InvalidBase64(ref err) => write!(f, "{}", err),
            DecodeLegacyError::NoDot => write!(f, "No dot"),
            DecodeLegacyError::UnknownSuffix => write!(f, "Unknown suffix"),
            DecodeLegacyError::Sha256WrongSize => write!(f, "Data of wrong length"),
        }
    }
}

impl std::error::Error for DecodeLegacyError {}

/// The legacy suffix indicating the sha256 cryptographic primitive.
const SHA256_SUFFIX: &[u8] = b"sha256";
/// Length of a base64 encoded sha256 hash digest.
const SHA256_BASE64_LEN: usize = 44;
/// Length of a legacy-encoded ssb `Multihash` which uses the sha256 cryptographic primitive.
const SSB_SHA256_ENCODED_LEN: usize = SHA256_BASE64_LEN + 9;

#[test]
fn test_from_legacy() {
    assert!(
        Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.sha256").is_ok()
    );
    assert!(
        Multihash::from_legacy(b"&MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.sha256").is_ok()
    );
    assert!(
        Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rd=.sha256").is_err()
    );
    assert!(
        Multihash::from_legacy(b"@MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.sha256").is_err()
    );
    assert!(
        Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.tha256").is_err()
    );
    assert!(
        Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=sha256").is_err()
    );
    assert!(
        Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc.sha256").is_err()
    );
    assert!(
        Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc==.sha256").is_err()
    );
}
