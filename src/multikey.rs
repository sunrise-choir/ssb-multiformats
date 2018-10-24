//! Implementation of [ssb multikeys](https://spec.scuttlebutt.nz/datatypes.html#multikey).
use std::fmt;
use std::io::{self, Write};

use base64;

use serde::{
    de::{Deserialize, Deserializer, Error},
    ser::{Serialize, Serializer},
};

use super::*;

/// A multikey that owns its data.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct Multikey(_Multikey);

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
enum _Multikey {
    // An [ed25519](http://ed25519.cr.yp.to/) public key.
    Ed25519([u8; 32]),
}

impl Multikey {
    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding)
    /// into a `Multikey`, also returning the remaining input on success.
    pub fn from_legacy(mut s: &[u8]) -> Result<(Multikey, &[u8]), DecodeLegacyError> {
        match skip_prefix(s, b"@") {
            Some(tail) => s = tail,
            None => return Err(DecodeLegacyError::Sigil),
        }

        match split_at_byte(s, 0x2E) {
            None => return Err(DecodeLegacyError::NoDot),
            Some((data, suffix)) => {
                match skip_prefix(suffix, ED25519_SUFFIX) {
                    None => return Err(DecodeLegacyError::UnknownSuffix),
                    Some(tail) => {
                        if data.len() != ED25519_PK_BASE64_LEN {
                            return Err(DecodeLegacyError::Ed25519WrongSize);
                        }

                        if data[ED25519_PK_BASE64_LEN - 2] == b"="[0] {
                            return Err(DecodeLegacyError::Ed25519WrongSize);
                        }

                        // XXX temporary until https://github.com/alicemaz/rust-base64/issues/76 is published
                        if !is_canonical(data) {
                            return Err(DecodeLegacyError::NoDot);
                        }

                        let mut dec_data = [0u8; 32];
                        match base64::decode_config_slice(data, base64::STANDARD, &mut dec_data[..]) {
                            Err(e) => return Err(DecodeLegacyError::InvalidBase64(e)),
                            Ok(_) => return Ok((Multikey(_Multikey::Ed25519(dec_data)), tail)),
                        }
                    }
                }
            }
        }
    }

    /// Serialize a `Multikey` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self.0 {
            _Multikey::Ed25519(ref bytes) => {
                w.write_all(b"@")?;

                let data = base64::encode_config(bytes, base64::STANDARD);
                w.write_all(data.as_bytes())?;

                w.write_all(b".")?;
                w.write_all(ED25519_SUFFIX)
            }
        }
    }

    /// Serialize a `Multikey` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        match self.0 {
            _Multikey::Ed25519(_) => {
                let mut out = Vec::with_capacity(SSB_ED25519_ENCODED_LEN);
                self.to_legacy(&mut out).unwrap();
                out
            }
        }
    }

    /// Serialize a `Multikey` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
    }
}

impl Serialize for Multikey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_legacy_string())
    }
}

impl<'de> Deserialize<'de> for Multikey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        Multikey::from_legacy(&s.as_bytes())
            .map(|(mk, _)| mk)
            .map_err(|err| D::Error::custom(format!("Invalid multikey: {}", err)))
    }
}

/// Everything that can go wrong when decoding a `Multikey` from the legacy encoding.
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
    /// The suffix declares an ed25519 key, but the data length does not match.
    Ed25519WrongSize,
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
            &DecodeLegacyError::Ed25519WrongSize => {
                write!(f, "Data of wrong length")
            }
        }

    }
}

impl std::error::Error for DecodeLegacyError {}

impl Multikey {
    /// Deserialize a legacy signature corrsponding to this key type.
    ///
    /// Returns the raw bytes of the decoded signature.
    pub fn sig_from_legacy<'a>(&self,
                                 s: &'a [u8])
                                 -> Result<(Vec<u8>, &'a [u8]), DecodeSignatureError> {
         match split_at_byte(s, 0x2E) {
             None => return Err(DecodeSignatureError::NoDot),
             Some((data, suffix)) => {
                 match skip_prefix(suffix, b"sig") {
                     None => return Err(DecodeSignatureError::NoDotSig),
                     Some(suffix) => {
                         match self.0 {
                             _Multikey::Ed25519(_) => {
                                 match skip_prefix(suffix, b".ed25519") {
                                     None => return Err(DecodeSignatureError::UnknownSuffix),
                                     Some(tail) => {
                                         if data.len() != ED25519_SIG_BASE64_LEN {
                                             return Err(DecodeSignatureError::Ed25519WrongSize);
                                         }

                                         if data[ED25519_SIG_BASE64_LEN - 2] != b"="[0] {
                                             return Err(DecodeSignatureError::Ed25519WrongSize);
                                         }

                                         // XXX temporary until https://github.com/alicemaz/rust-base64/issues/76 is published
                                         if !is_canonical(data) {
                                             return Err(DecodeSignatureError::NoDot);
                                         }

                                         let mut dec_data = Vec::with_capacity(64);
                                         match base64::decode_config_slice(data, base64::STANDARD, &mut dec_data[..]) {
                                             Err(e) => return Err(DecodeSignatureError::InvalidBase64(e)),
                                             Ok(_) => return Ok((dec_data, tail)),
                                         }
                                     }
                                 }
                             }
                         }
                     }
                 }
             }
         }
    }

    /// Serialize a signature corresponding to this `Multikey` into a writer, in the appropriate
    /// form for a [legacy message](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
    pub fn sig_to_legacy<W: Write>(&self, sig: &[u8], w: &mut W) -> Result<(), io::Error> {
        match self.0 {
            _Multikey::Ed25519(_) => {
                let data = base64::encode_config(sig, base64::STANDARD);
                w.write_all(data.as_bytes())?;
                w.write_all(b".sig.ed25519")
            }
        }
    }

    /// Serialize a signature corresponding to this `Multikey` into an owned byte vector,
    /// in the appropriate form for a
    /// [legacy message](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
    pub fn sig_to_legacy_vec(&self) -> Vec<u8> {
        match self.0 {
            _Multikey::Ed25519(_) => {
                let mut out = Vec::with_capacity(ED25519_SIG_BASE64_LEN);
                self.to_legacy(&mut out).unwrap();
                out
            }
        }
    }

    /// Serialize a signature corresponding to this `Multikey` into an owned string,
    /// in the appropriate form for a
    /// [legacy message](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
    pub fn sig_to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
    }
}

/// Everything that can go wrong when decoding a signature from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeSignatureError {
    /// Input did not contain a `"."` to separate the data from the suffix.
    NoDot,
    /// Input did contain the mandatory ".sig".
    NoDotSig,
    /// The base64 portion of the key was invalid.
    InvalidBase64(base64::DecodeError),
    /// The suffix is not known to this ssb implementation.
    UnknownSuffix,
    /// The suffix declares an ed25519 signature, but the data length does not match.
    Ed25519WrongSize,
}

impl fmt::Display for DecodeSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeSignatureError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeSignatureError::NoDot => write!(f, "No dot"),
            &DecodeSignatureError::NoDotSig => write!(f, "No .sig"),
            &DecodeSignatureError::UnknownSuffix => {
                write!(f, "Unknown suffix")
            }
            &DecodeSignatureError::Ed25519WrongSize => {
                write!(f, "Data of wrong length")
            }
        }

    }
}

impl std::error::Error for DecodeSignatureError {}

/// The legacy suffix indicating the ed25519 cryptographic primitive.
const ED25519_SUFFIX: &'static [u8] = b"ed25519";
/// Length of a base64 encoded ed25519 public key.
const ED25519_PK_BASE64_LEN: usize = 44;
/// Length of a legacy-encoded ssb `Multikey` which uses the ed25519 cryptographic primitive.
const SSB_ED25519_ENCODED_LEN: usize = ED25519_PK_BASE64_LEN + 9;
/// Length of a base64 encoded ed25519 public key.
const ED25519_SIG_BASE64_LEN: usize = 88;
