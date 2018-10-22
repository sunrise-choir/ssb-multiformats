//! Implementation of [ssb multihashes](https://spec.scuttlebutt.nz/datatypes.html#multihash).
use std::fmt;
use std::io::{self, Write};

use base64;

use serde::{
    de::{Deserialize, Deserializer, Error},
    ser::{Serialize, Serializer},
};

use super::*;

/// A multihash that owns its data.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct Multihash(pub Target, _Multihash);

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
/// What does the hash refer to?
pub enum Target {
    /// An ssb [message](https://spec.scuttlebutt.nz/messages.html).
    Message,
    /// An ssb [blob](TODO).
    Blob,
}

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
enum _Multihash {
    // A [sha256](https://en.wikipedia.org/wiki/SHA-2) hash digest.
    Sha256([u8; 32]),
}

impl Multihash {
    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-legacy-encoding)
    /// into a `Multihash`.
    pub fn from_legacy(mut s: &[u8]) -> Result<(Multihash, &[u8]), DecodeLegacyError> {
        let target;

        match skip_prefix(s, b"%") {
            Some(tail) => {
                s = tail;
                target = Target::Message;
            },
            None => match skip_prefix(s, b"&") {
                Some(tail) => {
                    s = tail;
                    target = Target::Blob;
                },
                None => return Err(DecodeLegacyError::Sigil),
            }
        }

        match split_at_byte(s, 0x2E) {
            None => return Err(DecodeLegacyError::NoDot),
            Some((data, suffix)) => {
                match skip_prefix(suffix, SHA256_SUFFIX) {
                    None => return Err(DecodeLegacyError::UnknownSuffix),
                    Some(tail) => {
                        if data.len() != SHA256_BASE64_LEN {
                            return Err(DecodeLegacyError::Sha256WrongSize);
                        }

                        let mut dec_data = [0u8; 32];
                        match base64::decode_config_slice(data, base64::STANDARD, &mut dec_data[..]) {
                            Err(e) => return Err(DecodeLegacyError::InvalidBase64(e)),
                            Ok(_) => return Ok((Multihash(target, _Multihash::Sha256(dec_data)), tail)),
                        }
                    }
                }
            }
        }
    }

    /// Serialize a `Multihash` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self.1 {
            _Multihash::Sha256(ref bytes) => {
                match self.0 {
                    Target::Message => w.write_all(b"%")?,
                    Target::Blob => w.write_all(b"&")?,
                }

                let data = base64::encode_config(bytes, base64::STANDARD);
                w.write_all(data.as_bytes())?;

                w.write_all(b".")?;
                w.write_all(SHA256_SUFFIX)
            }
        }
    }

    /// Serialize a `Multihash` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        match self.1 {
            _Multihash::Sha256(_) => {
                let mut out = Vec::with_capacity(SSB_SHA256_ENCODED_LEN);
                self.to_legacy(&mut out).unwrap();
                out
            }
        }
    }

    /// Serialize a `Multihash` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
    }
}

impl Serialize for Multihash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_legacy_string())
    }
}

impl<'de> Deserialize<'de> for Multihash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        Multihash::from_legacy(&s.as_bytes())
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
            &DecodeLegacyError::Sigil => write!(f, "Invalid sigil"),
            &DecodeLegacyError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeLegacyError::NoDot => write!(f, "No dot"),
            &DecodeLegacyError::UnknownSuffix => {
                write!(f, "Unknown suffix")
            }
            &DecodeLegacyError::Sha256WrongSize => {
                write!(f, "Data of wrong length")
            }
        }

    }
}

impl std::error::Error for DecodeLegacyError {}

/// The legacy suffix indicating the sha256 cryptographic primitive.
const SHA256_SUFFIX: &'static [u8] = b"ed25519";
/// Length of a base64 encoded sha256 hash digest.
const SHA256_BASE64_LEN: usize = 44;
/// Length of a legacy-encoded ssb `Multihash` which uses the sha256 cryptographic primitive.
const SSB_SHA256_ENCODED_LEN: usize = SHA256_BASE64_LEN + 9;
