//! Implementation of [ssb multiboxes](https://spec.scuttlebutt.nz/datatypes.html#multibox).
use std::fmt;
use std::io::{self, Write};

use base64;

use super::*;

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
/// A multibox that owns its data. This does no decryption, it stores cyphertext.
pub struct Multibox(_Multibox);

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
enum _Multibox {
    // https://ssbc.github.io/scuttlebutt-protocol-guide/#private-messages
    PrivateBox(Vec<u8>),
}

impl Multibox {
    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multibox-legacy-encoding)
    /// into a `Multibox`.
    pub fn from_legacy(s: &[u8]) -> Result<Multibox, DecodeLegacyError> {
        match split_at_byte(s, 0x2E) {
            None => return Err(DecodeLegacyError::NoDot),
            Some((data, suffix)) => {
                match skip_prefix(suffix, b"box") {
                    None => return Err(DecodeLegacyError::UnknownSuffix),
                    Some(tail) => {
                        if tail.len() != 0 {
                            return Err(DecodeLegacyError::UnknownSuffix);
                        }

                        match base64::decode_config(data, base64::STANDARD) {
                            Ok(cypher_raw) => {
                                return Ok(Multibox(_Multibox::PrivateBox(cypher_raw)));
                            }

                            Err(base64_err) => Err(DecodeLegacyError::InvalidBase64(base64_err)),
                        }
                    }
                }
            }
        }
    }

    /// Serialize a `Multibox` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multibox-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self.0 {
            _Multibox::PrivateBox(ref bytes) => {
                let data = base64::encode_config(bytes, base64::STANDARD);
                w.write_all(data.as_bytes())?;

                w.write_all(b".box")
            }
        }
    }

    /// Serialize a `Multibox` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multibox-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        match self.0 {
            _Multibox::PrivateBox(ref cyphertext) => {
                let mut out = Vec::with_capacity(((cyphertext.len() * 4) / 3) + 4);
                self.to_legacy(&mut out).unwrap();
                out
            }
        }
    }

    /// Serialize a `Multibox` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multibox-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
    }
}

/// Everything that can go wrong when decoding a `Multibox` from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeLegacyError {
    /// Input did not contain a `"."` to separate the data from the suffix.
    NoDot,
    /// The base64 portion of the key was invalid.
    InvalidBase64(base64::DecodeError),
    /// The suffix is not known to this ssb implementation.
    UnknownSuffix,
}

impl fmt::Display for DecodeLegacyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeLegacyError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeLegacyError::NoDot => write!(f, "No dot"),
            &DecodeLegacyError::UnknownSuffix => write!(f, "Unknown suffix"),
        }

    }
}

impl std::error::Error for DecodeLegacyError {}
