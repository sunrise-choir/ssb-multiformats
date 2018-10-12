//! Implementation of [ssb multikeys](TODO).
use std::fmt;

use base64;

use ssb_legacy_msg::{
    StringlyTypedError,
    data::{Serialize, Serializer, Deserialize, Deserializer}
};

/// A multihash that owns its data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Multihash(pub Target, _Multihash);

#[derive(Debug, PartialEq, Eq, Clone)]
/// What does the hash refer to?
pub enum Target {
    Message,
    Blob
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum _Multihash {
    // A [sha256](https://en.wikipedia.org/wiki/SHA-2) hash digest.
    Sha256([u8; 32]),
}

impl Multihash {
    /// Parses a [legacy encoding](TODO) into a `Multihash`.
    pub fn from_legacy(mut s: &[u8]) -> Result<Multihash, DecodeLegacyError> {
        let target;
        match s.split_first() {
            // Next character is `%`
            Some((0x25, tail)) => {
                target = Target::Message;
                s = tail;
            },
            // Next character is `&`
            Some((0x26, tail)) => {
                target = Target::Blob;
                s = tail;
            },
            Some((sigil, _)) => return Err(DecodeLegacyError::InvalidSigil(*sigil)),
            None => return Err(DecodeLegacyError::NotEnoughData),
        }

        let mut iter = s.split(|byte| *byte == 0x2e); // split at `.`

        match iter.next() {
            None => return Err(DecodeLegacyError::NotEnoughData),
            Some(data) => {
                match base64::decode_config(data, base64::STANDARD) {
                    Ok(digest_raw) => {
                        match iter.next() {
                            None => return Err(DecodeLegacyError::NoSuffix),
                            Some(&[0x73, 0x68, 0x61, 0x32, 0x35, 0x36]) => {
                                if digest_raw.len() != 32 {
                                    return Err(DecodeLegacyError::Sha256WrongSize(digest_raw));
                                }

                                let mut data = [0u8; 32];
                                data.copy_from_slice(&digest_raw[..]);
                                return Ok(Multihash(target, _Multihash::Sha256(data)));
                            }
                            Some(suffix) => return Err(DecodeLegacyError::UnknownSuffix(suffix.to_vec())),
                        }
                    }

                    Err(base64_err) => Err(DecodeLegacyError::InvalidBase64(base64_err)),
                }
            }
        }
    }

    /// Serialize a `Multihash` into the [legacy encoding](TODO).
    pub fn to_legacy(&self) -> String {
        match self.1 {
            _Multihash::Sha256(ref bytes) => {
                let mut buf = String::with_capacity(SSB_SHA256_ENCODED_LEN);
                match self.0 {
                    Target::Message => buf.push_str("%"),
                    Target::Blob => buf.push_str("&"),
                }

                base64::encode_config_buf(bytes, base64::STANDARD, &mut buf);
                debug_assert!(buf.len() == SHA256_BASE64_LEN + 1);

                buf.push_str(".");
                buf.push_str(SHA256_SUFFIX);
                debug_assert!(buf.len() == SSB_SHA256_ENCODED_LEN);

                buf
            }
        }
    }
}

impl Serialize for Multihash {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_legacy())
    }
}

impl<'de> Deserialize<'de> for Multihash {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
        where D: Deserializer<'de>
    {
        let s = String::deserialize(deserializer)?;
        Multihash::from_legacy(&s.as_bytes())
            .map_err(|err| D::Error::custom(format!("Invalid multihash: {}", err)))
    }
}

/// Everything that can go wrong when decoding a `Multihash` from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeLegacyError {
    /// Input must contain at least four characters (sigil, data, dot, suffix).
    NotEnoughData,
    /// Input did not start with the `"@"` sigil.
    ///
    /// Contains the invalid first byte.
    InvalidSigil(u8),
    /// The base64 portion of the key was invalid.
    InvalidBase64(base64::DecodeError),
    /// No more data after the base64 portion of the encoding.
    NoSuffix,
    /// The suffix is not known to this ssb implementation.
    ///
    /// Contains the suffix.
    UnknownSuffix(Vec<u8>),
    /// The suffix declares a sha256 digest, but the data length does not match.
    ///
    /// Contains the decoded data (of length != 32).
    Sha256WrongSize(Vec<u8>)
}


impl fmt::Display for DecodeLegacyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeLegacyError::NotEnoughData => write!(f, "Not enough input data"),
            &DecodeLegacyError::InvalidSigil(sigil) => write!(f, "Invalid sigil: {}", sigil),
            &DecodeLegacyError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeLegacyError::NoSuffix => write!(f, "No suffix"),
            &DecodeLegacyError::UnknownSuffix(ref suffix) => write!(f, "UnknownSuffix: {:x?}", suffix),
            &DecodeLegacyError::Sha256WrongSize(ref data) => write!(f, "Data of wrong length: {:x?}", data),
        }

    }
}

impl std::error::Error for DecodeLegacyError {}

/// The legacy suffix indicating the sha256 cryptographic primitive.
const SHA256_SUFFIX: &'static str = "ed25519";
/// Length of a base64 encoded sha256 hash digest.
const SHA256_BASE64_LEN: usize = 44;
/// Length of a legacy-encoded ssb `Multihash` which uses the sha256 cryptographic primitive.
const SSB_SHA256_ENCODED_LEN: usize = SHA256_BASE64_LEN + 9;
