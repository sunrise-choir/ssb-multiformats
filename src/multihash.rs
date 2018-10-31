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

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord)]
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
    /// Take a sha256 digest and turn it into an opaque `Multihash`.
    pub fn from_sha256(digest: [u8; 32], target: Target) -> Multihash {
        Multihash(target, _Multihash::Sha256(digest))
    }

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

                        if data[SHA256_BASE64_LEN - 2] == b"="[0] {
                            return Err(DecodeLegacyError::Sha256WrongSize);
                        }

                        if data[SHA256_BASE64_LEN - 1] != b"="[0] {
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

    /// Parses a
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-compact-encoding)
    /// into a `Multihash`, also returning the remaining input on success.
    pub fn from_compact(s: &[u8]) -> Result<(Multihash, &[u8]), DecodeCompactError> {
        match ctlv::Ctlv::decode(s) {
            Ok((tlv, tail)) => {
                match tlv.type_ {
                    SHA256_ID_MSG | SHA256_ID_BLOB => {
                        debug_assert!(tlv.value.len() == 32);

                        let mut data = [0u8; 32];
                        for i in 0..32 {
                            data[i] = tlv.value[i];
                        }

                        if tlv.type_ == SHA256_ID_MSG {
                            Ok((Multihash(Target::Message, _Multihash::Sha256(data)), tail))
                        } else {
                            Ok((Multihash(Target::Blob, _Multihash::Sha256(data)), tail))
                        }
                    }
                    _ => Err(DecodeCompactError::UnknownPrimitive(tlv.type_))
                }
            }

            Err((e, _)) => Err(DecodeCompactError::Ctlv(e))
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

    /// Serialize a `Multihash` into a writer, using the
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-compact-encoding).
    pub fn to_compact<W: Write>(&self, w: W) -> Result<usize, io::Error> {
        match (self.0, &self.1) {
            (Target::Message, _Multihash::Sha256(ref bytes)) => {
                let tlv = ctlv::CtlvRef {
                    type_: SHA256_ID_MSG,
                    value: &bytes[..]
                };
                tlv.encode_write(w)
            }

            (Target::Blob, _Multihash::Sha256(ref bytes)) => {
                let tlv = ctlv::CtlvRef {
                    type_: SHA256_ID_BLOB,
                    value: &bytes[..]
                };
                tlv.encode_write(w)
            }
        }
    }

    /// Serialize a `Multihash` into an owned byte vector, using the
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-compact-encoding).
    pub fn to_compact_vec(&self) -> Vec<u8> {
        match (self.0, &self.1) {
            (Target::Message, _Multihash::Sha256(ref bytes)) => {
                let tlv = ctlv::CtlvRef {
                    type_: SHA256_ID_MSG,
                    value: &bytes[..]
                };
                tlv.encode_vec()
            }

            (Target::Blob, _Multihash::Sha256(ref bytes)) => {
                let tlv = ctlv::CtlvRef {
                    type_: SHA256_ID_BLOB,
                    value: &bytes[..]
                };
                tlv.encode_vec()
            }
        }
    }

    /// Serialize a `Multihash` into an owned string, using the
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multihash-compact-encoding).
    pub fn to_compact_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_compact_vec()) }
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

/// Everything that can go wrong when decoding a `Multikey` from the compact encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeCompactError {
    /// The cryptographic primitive is not known to this ssb implementation.
    UnknownPrimitive(u64),
    /// The ctlv encoding was invalid
    Ctlv(ctlv::DecodeError),
}

impl fmt::Display for DecodeCompactError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeCompactError::UnknownPrimitive(prim) => {
                write!(f, "Unknown primitive: {}", prim)
            }
            &DecodeCompactError::Ctlv(e) => e.fmt(f),
        }
    }
}

impl std::error::Error for DecodeCompactError {}

/// The legacy suffix indicating the sha256 cryptographic primitive.
const SHA256_SUFFIX: &'static [u8] = b"sha256";
/// Length of a base64 encoded sha256 hash digest.
const SHA256_BASE64_LEN: usize = 44;
/// Length of a legacy-encoded ssb `Multihash` which uses the sha256 cryptographic primitive.
const SSB_SHA256_ENCODED_LEN: usize = SHA256_BASE64_LEN + 9;

/// Compact format id of the sha256 primitive for messages.
const SHA256_ID_MSG: u64 = 40;
/// Compact format id of the sha256 primitive for blobs.
const SHA256_ID_BLOB: u64 = 41;

#[test]
fn test_from_legacy() {
    assert!(Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.sha256").is_ok());
    assert!(Multihash::from_legacy(b"&MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.sha256").is_ok());
    assert!(Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rd=.sha256").is_err());
    assert!(Multihash::from_legacy(b"@MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.sha256").is_err());
    assert!(Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=.tha256").is_err());
    assert!(Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc=sha256").is_err());
    assert!(Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc.sha256").is_err());
    assert!(Multihash::from_legacy(b"%MwjdLV95P7VqHfrgS49nScXsyIwJfL229e5OSKc+0rc==.sha256").is_err());
}
