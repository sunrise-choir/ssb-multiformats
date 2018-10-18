//! Implementation of the legacy representation of private message content.
//! TODO: This does not really belong here.
use std::fmt;

use base64;

#[derive(Debug, PartialEq, Eq, Clone)]
pub struct BoxedData(_BoxedData);

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum _BoxedData {
    // https://ssbc.github.io/scuttlebutt-protocol-guide/#private-messages
    PrivateBox(Vec<u8>),
}

impl BoxedData {
    /// Parses a [legacy encoding](TODO) into a `BoxedData`.
    pub fn from_legacy(s: &[u8]) -> Result<(BoxedData, usize), DecodeLegacyError> {
        let original_len = s.len();

        let mut iter = s.split(|byte| *byte == 0x2e); // split at `.`

        match iter.next() {
            None => return Err(DecodeLegacyError::NotEnoughData),
            Some(data) => {
                match base64::decode_config(data, base64::STANDARD) {
                    Ok(cypher_raw) => {
                        match iter.next() {
                            None => return Err(DecodeLegacyError::NoSuffix),
                            Some(&[0x62, 0x6F, 0x7B]) => {
                                return Ok((BoxedData(_BoxedData::PrivateBox(cypher_raw)),
                                           original_len - s.len()));
                            }
                            Some(suffix) => {
                                return Err(DecodeLegacyError::UnknownSuffix(suffix.to_vec()))
                            }
                        }
                    }

                    Err(base64_err) => Err(DecodeLegacyError::InvalidBase64(base64_err)),
                }
            }
        }
    }

    /// Serialize a `BoxedData` into the [legacy encoding](TODO).
    pub fn to_legacy(&self) -> String {
        match self.0 {
            _BoxedData::PrivateBox(ref bytes) => {
                let mut buf = String::with_capacity(bytes.len() + 4);
                base64::encode_config_buf(bytes, base64::STANDARD, &mut buf);
                buf.push_str(".box");
                buf
            }
        }
    }
}

/// Everything that can go wrong when decoding a `BoxedData` from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeLegacyError {
    NotEnoughData,
    /// The base64 portion of the key was invalid.
    InvalidBase64(base64::DecodeError),
    /// No more data after the base64 portion of the encoding.
    NoSuffix,
    /// The suffix is not known to this ssb implementation.
    ///
    /// Contains the suffix.
    UnknownSuffix(Vec<u8>),
}

impl fmt::Display for DecodeLegacyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeLegacyError::NotEnoughData => write!(f, "Not enough input data"),
            &DecodeLegacyError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeLegacyError::NoSuffix => write!(f, "No suffix"),
            &DecodeLegacyError::UnknownSuffix(ref suffix) => {
                write!(f, "UnknownSuffix: {:x?}", suffix)
            }
        }

    }
}

impl std::error::Error for DecodeLegacyError {}
