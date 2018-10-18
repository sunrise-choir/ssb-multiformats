//! Implementation of [ssb multikeys](TODO).
use std::fmt;

use base64;

use ssb_legacy_msg_data::{StringlyTypedError, Serialize, Serializer, Deserialize, Deserializer};

/// A multikey that owns its data.
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Multikey(_Multikey);

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum _Multikey {
    // An [ed25519](http://ed25519.cr.yp.to/) public key.
    Ed25519([u8; 32]),
}

impl Multikey {
    /// Parses a [legacy encoding](TODO) into a `Multikey`.
    pub fn from_legacy(mut s: &[u8]) -> Result<(Multikey, usize), DecodeLegacyError> {
        let original_len = s.len();

        match s.split_first() {
            // Next character is `@`
            Some((0x40, tail)) => s = tail,
            Some((sigil, _)) => return Err(DecodeLegacyError::InvalidSigil(*sigil)),
            None => return Err(DecodeLegacyError::NotEnoughData),
        }

        let mut iter = s.split(|byte| *byte == 0x2e); // split at `.`

        match iter.next() {
            None => return Err(DecodeLegacyError::NotEnoughData),
            Some(data) => {
                match base64::decode_config(data, base64::STANDARD) {
                    Ok(key_raw) => {
                        match iter.next() {
                            None => return Err(DecodeLegacyError::NoSuffix),
                            Some(&[0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]) => {
                                if key_raw.len() != 32 {
                                    return Err(DecodeLegacyError::Ed25519WrongSize(key_raw));
                                }

                                let mut data = [0u8; 32];
                                data.copy_from_slice(&key_raw[..]);
                                return Ok((Multikey(_Multikey::Ed25519(data)),
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

    /// Serialize a `Multikey` into the [legacy encoding](TODO).
    pub fn to_legacy(&self) -> String {
        match self.0 {
            _Multikey::Ed25519(ref bytes) => {
                let mut buf = String::with_capacity(SSB_PK_ED25519_ENCODED_LEN);
                buf.push_str("@");

                base64::encode_config_buf(bytes, base64::STANDARD, &mut buf);
                debug_assert!(buf.len() == ED25519_PK_BASE64_LEN + 1);

                buf.push_str(".");
                buf.push_str(ED25519_SUFFIX);
                debug_assert!(buf.len() == SSB_PK_ED25519_ENCODED_LEN);

                buf
            }
        }
    }

    /// Deserialize a legacy signature corrsponding to this key type.
    pub fn deserialize_signature(&self, s: &[u8]) -> Result<Vec<u8>, DecodeSignatureError> {
        let mut iter = s.split(|byte| *byte == 0x2e); // split at `.`

        match iter.next() {
            None => return Err(DecodeSignatureError::NotEnoughData),
            Some(data) => {
                match base64::decode_config(data, base64::STANDARD) {
                    Ok(sig_raw) => {
                        match iter.next() {
                            None => return Err(DecodeSignatureError::NoDotSig),
                            Some(&[0x73, 0x69, 0x67]) => {
                                match self.0 {
                                    _Multikey::Ed25519(_) => {
                                        match iter.next() {
                                            None => return Err(DecodeSignatureError::NoSuffix),
                                            Some(&[0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39]) => {
                                                if sig_raw.len() != 64 {
                                                    return Err(DecodeSignatureError::Ed25519WrongSize(sig_raw));
                                                }
                                                return Ok(sig_raw);
                                            }
                                            Some(suffix) => {
                                                return Err(DecodeSignatureError::UnknownSuffix(suffix.to_vec()))
                                            }
                                        }
                                    }
                                }
                            }
                            Some(other) => {
                                return Err(DecodeSignatureError::NotDotSig(other.to_vec()))
                            }
                        }
                    }

                    Err(base64_err) => Err(DecodeSignatureError::InvalidBase64(base64_err)),
                }
            }
        }
    }
}

impl Serialize for Multikey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
        where S: Serializer
    {
        serializer.serialize_str(&self.to_legacy())
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
    /// The suffix declares an ed25519 key, but the data length does not match.
    ///
    /// Contains the decoded data (of length != 32).
    Ed25519WrongSize(Vec<u8>),
}

impl fmt::Display for DecodeLegacyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeLegacyError::NotEnoughData => write!(f, "Not enough input data"),
            &DecodeLegacyError::InvalidSigil(sigil) => write!(f, "Invalid sigil: {}", sigil),
            &DecodeLegacyError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeLegacyError::NoSuffix => write!(f, "No suffix"),
            &DecodeLegacyError::UnknownSuffix(ref suffix) => {
                write!(f, "UnknownSuffix: {:x?}", suffix)
            }
            &DecodeLegacyError::Ed25519WrongSize(ref data) => {
                write!(f, "Data of wrong length: {:x?}", data)
            }
        }

    }
}

impl std::error::Error for DecodeLegacyError {}

/// Everything that can go wrong when decoding a signature from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeSignatureError {
    NotEnoughData,
    InvalidBase64(base64::DecodeError),
    NoDotSig,
    NotDotSig(Vec<u8>),
    NoSuffix,
    UnknownSuffix(Vec<u8>),
    Ed25519WrongSize(Vec<u8>),
}

impl fmt::Display for DecodeSignatureError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeSignatureError::NotEnoughData => write!(f, "Not enough input data"),
            &DecodeSignatureError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeSignatureError::NoDotSig => write!(f, "No `.sig.`"),
            &DecodeSignatureError::NotDotSig(ref data) => {
                write!(f, "Expected `.sig.`, got {:?}", data)
            }
            &DecodeSignatureError::NoSuffix => write!(f, "No suffix"),
            &DecodeSignatureError::UnknownSuffix(ref suffix) => {
                write!(f, "UnknownSuffix: {:x?}", suffix)
            }
            &DecodeSignatureError::Ed25519WrongSize(ref data) => {
                write!(f, "Data of wrong length: {:x?}", data)
            }
        }

    }
}

impl std::error::Error for DecodeSignatureError {}

/// The legacy suffix indicating the ed25519 cryptographic primitive.
const ED25519_SUFFIX: &'static str = "ed25519";
/// Length of a base64 encoded ed25519 public key.
const ED25519_PK_BASE64_LEN: usize = 44;
/// Length of a legacy-encoded ssb `Multikey` which uses the ed25519 cryptographic primitive.
const SSB_PK_ED25519_ENCODED_LEN: usize = ED25519_PK_BASE64_LEN + 9;

#[test]
fn regression() {
    // let input = "@FCX/tsDLpubCPKKfIrw4gc+SQkHcaD16s7GI6i/ziYW=.ed25519";
    let input = "FCX/tsDLpubCPKKfIrw4gc+SQkHcaD16s7GI6i/ziYW=";
    println!("{:?}", input);
    let dec = base64::decode_config(input, base64::STANDARD).unwrap();
    println!("{:x?}", dec);
    let enc = base64::encode_config(&dec, base64::STANDARD);
    println!("{:?}", enc);
    assert_eq!(enc, input);

    // let dec = Multikey::from_legacy(input.as_bytes()).unwrap();
    // println!("{:?}", dec);
    // match dec.0 {
    //     _Multikey::Ed25519(raw) => println!("{:x?}", raw),
    // }
    //
    // let enc = dec.to_legacy();
    // println!("{:?}", enc);
    //
    // assert_eq!(input, enc)
}
