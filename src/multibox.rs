//! Implementation of [ssb multiboxes](https://spec.scuttlebutt.nz/datatypes.html#multibox).
use std::fmt;
use std::io::{self, Write};

use base64;

use varu64;

use super::*;

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
/// A multibox that owns its data. This does no decryption, it stores cyphertext.
pub struct Multibox(_Multibox);

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
enum _Multibox {
    // https://ssbc.github.io/scuttlebutt-protocol-guide/#private-messages
    PrivateBox(Vec<u8>),
    Other(u64, Vec<u8>),
}

impl Multibox {
    /// Creates a new private box multibox with the given secret text (*not* base64 encoded).
    pub fn new_private_box(secret: Vec<u8>) -> Multibox {
        Multibox(_Multibox::PrivateBox(secret))
    }

    /// Creates a multibox with from the given identifier and the given secret text (*not* base64 encoded).
    pub fn new_multibox(id: u64, secret: Vec<u8>) -> Multibox {
        match id {
            0 => Multibox::new_private_box(secret),
            _ => Multibox(_Multibox::Other(id, secret)),
        }
    }

    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multibox-legacy-encoding)
    /// into a `Multibox`, also returning the remaining input on success.
    pub fn from_legacy(s: &[u8]) -> Result<(Multibox, &[u8]), DecodeLegacyError> {
        match split_at_byte(s, 0x2E) {
            None => return Err(DecodeLegacyError::NoDot),
            Some((data, suffix)) => {
                match base64::decode_config(data, base64::STANDARD) {
                    Ok(cypher_raw) => {
                        if data.len() % 4 != 0 {
                            return Err(DecodeLegacyError::NoncanonicPadding);
                        }

                        match skip_prefix(suffix, b"box") {
                            None => return Err(DecodeLegacyError::InvalidSuffix),
                            Some(tail) => {
                                match decode_base32_id(tail) {
                                    None => return Err(DecodeLegacyError::InvalidSuffix),
                                    Some((0, tail)) => {
                                        return Ok((Multibox(_Multibox::PrivateBox(cypher_raw)), tail));
                                    }
                                    Some((id, tail)) => {
                                        return Ok((Multibox(_Multibox::Other(id, cypher_raw)), tail));
                                    }
                                }
                            }
                        }
                    }

                    Err(base64_err) => {
                        return Err(DecodeLegacyError::InvalidBase64(base64_err));
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

            _Multibox::Other(id, ref bytes) => {
                let data = base64::encode_config(bytes, base64::STANDARD);
                w.write_all(data.as_bytes())?;

                w.write_all(b".box")?;
                w.write_all(&encode_base32_id(id)[..])
            }
        }
    }

    /// Serialize a `Multibox` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multibox-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        let capacity = match self.0 {
            _Multibox::PrivateBox(ref cyphertext) => ((cyphertext.len() * 4) / 3) + 4,
            _Multibox::Other(id, ref cyphertext) => ((cyphertext.len() * 4) / 3) + 4 + id_len_base32(id),
        };

        let mut out = Vec::with_capacity(capacity);
        self.to_legacy(&mut out).unwrap();
        out
    }

    /// Serialize a `Multibox` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multibox-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
    }

    pub fn from_compact(s: &[u8]) -> Result<(Multibox, &[u8]), DecodeCompactError> {
        match varu64::decode(s) {
            Ok((type_, tail)) => {
                match varu64::decode(tail) {
                    Ok((len, tail)) => {
                        if tail.len() < len as usize {
                            return Err(DecodeCompactError::NotEnoughInput);
                        }

                        let mut data = Vec::with_capacity(len as usize);
                        data.extend_from_slice(&tail[..len as usize]);

                        match type_ {
                            0 => return Ok((Multibox(_Multibox::PrivateBox(data)), &tail[len as usize..])),
                            _ => return Ok((Multibox(_Multibox::Other(type_, data)), &tail[len as usize..])),
                        }
                    }

                    Err((e, _)) => Err(DecodeCompactError::InvalidLength(e)),
                }
            }

            Err((e, _)) => return Err(DecodeCompactError::InvalidType(e)),
        }
    }

    pub fn to_compact<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        let (id, bytes) = match self.0 {
            _Multibox::PrivateBox(ref bytes) => (0, bytes),
            _Multibox::Other(id, ref bytes) => (id, bytes),
        };

        varu64::encode_write(id, &mut *w)?;
        varu64::encode_write(bytes.len() as u64, &mut *w)?;
        w.write_all(bytes)
    }

    pub fn to_compact_vec(&self) -> Vec<u8> {
        let (id, bytes) = match self.0 {
            _Multibox::PrivateBox(ref bytes) => (0, bytes),
            _Multibox::Other(id, ref bytes) => (id, bytes),
        };

        let capacity = varu64::encoding_length(id) + varu64::encoding_length(bytes.len() as u64) + bytes.len();
        let mut out = Vec::with_capacity(capacity);
        self.to_compact(&mut out).unwrap();
        out
    }

    pub fn to_compact_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_compact_vec()) }
    }
}

/// Everything that can go wrong when decoding a `Multibox` from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeLegacyError {
    /// Input did not contain a `"."` to separate the data from the suffix.
    NoDot,
    /// The base64 portion of the box was invalid.
    InvalidBase64(base64::DecodeError),
    /// The base64 portion of the box did not use the correct amount of padding.
    NoncanonicPadding,
    /// The suffix is not well-formed.
    InvalidSuffix,
}

impl fmt::Display for DecodeLegacyError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeLegacyError::InvalidBase64(ref err) => write!(f, "{}", err),
            &DecodeLegacyError::NoncanonicPadding => write!(f, "Incorrect number of padding '='s"),
            &DecodeLegacyError::NoDot => write!(f, "No dot"),
            &DecodeLegacyError::InvalidSuffix => write!(f, "Invalid suffix"),
        }
    }
}

impl std::error::Error for DecodeLegacyError {}

/// Everything that can go wrong when decoding a `Multibox` from the compact encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeCompactError {
    /// The type indicator was invalid.
    InvalidType(varu64::DecodeError),
    /// The length indicator was invalid.
    InvalidLength(varu64::DecodeError),
    /// Needed more input to continue decoding.
    NotEnoughInput,
}

impl fmt::Display for DecodeCompactError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            &DecodeCompactError::InvalidType(e) => write!(f, "Invalid type: {}", e),
            &DecodeCompactError::InvalidLength(e) => write!(f, "Invalid length: {}", e),
            &DecodeCompactError::NotEnoughInput => write!(f, "Not enough input"),
        }
    }
}

impl std::error::Error for DecodeCompactError {}

// Decode the legacy format id of a multibox (canonic crockford base32, no leading zeros, at most 2^64 - 1).
// Stops decoding when encounterig end of input, a non-base32 character, or at the maximum identifier length.
// In all these cases, it returns `Some(decoded)`, `None` is only returned if the first input
// character is a zero or if a large identifier has a non-canonical first character.
fn decode_base32_id(s: &[u8]) -> Option<(u64, &[u8])> {
    if s.get(0) == Some(&0x30) {
        return None; // Id may not begin with a zero.
    }

    let mut acc: u64 = 0; // The id is built up in this variable.

    for i in 0..13 { // 13 is the maximum length of an identifier
        match s.get(i) {
            None => return Some((acc, &[][..])), // end of input
            Some(c) => {
                if i == 12 && s[0] > 0x46 {
                    // Noncanonical first character.
                    return None;
                }

                let dec = match c {
                    0x30 => 0,
                    0x31 => 1,
                    0x32 => 2,
                    0x33 => 3,
                    0x34 => 4,
                    0x35 => 5,
                    0x36 => 6,
                    0x37 => 7,
                    0x38 => 8,
                    0x39 => 9,
                    0x41 => 10,
                    0x42 => 11,
                    0x43 => 12,
                    0x44 => 13,
                    0x45 => 14,
                    0x46 => 15,
                    0x47 => 16,
                    0x48 => 17,
                    0x4A => 18,
                    0x4B => 19,
                    0x4D => 20,
                    0x4E => 21,
                    0x50 => 22,
                    0x51 => 23,
                    0x52 => 24,
                    0x53 => 25,
                    0x54 => 26,
                    0x56 => 27,
                    0x57 => 28,
                    0x58 => 29,
                    0x59 => 30,
                    0x5A => 31,
                    _ => return Some((acc, &s[i..])), // non-base32 input byte
                };
                acc <<= 5;
                acc += dec;
            }
        }
    }

    // Reached maximum length of an identifier, return the decoded value and the remainig input.
    return Some((acc, &s[13..]));
}

fn id_len_base32(id: u64) -> usize {
    (68 - id.leading_zeros() as usize) / 5
}

// Produces the canonical base32 encoding used for legacy multibox identifiers.
fn encode_base32_id(id: u64) -> Vec<u8> {
    let len = id_len_base32(id); // how many bytes of output will this create?
    let mut out = Vec::with_capacity(len);

    for i in 0..len {
        let offset = ((len - 1) - i) * 5; // offset to the least-significant bit of the five bits to encode.
        let to_encode = (id >> offset) & 0b11111; // the five bits to encode (and leading zeros)

        // the symbol to write to the output
        let symbol = match to_encode {
            0 => 0x30,
            1 => 0x31,
            2 => 0x32,
            3 => 0x33,
            4 => 0x34,
            5 => 0x35,
            6 => 0x36,
            7 => 0x37,
            8 => 0x38,
            9 => 0x39,
            10 => 0x41,
            11 => 0x42,
            12 => 0x43,
            13 => 0x44,
            14 => 0x45,
            15 => 0x46,
            16 => 0x47,
            17 => 0x48,
            18 => 0x4A,
            19 => 0x4B,
            20 => 0x4D,
            21 => 0x4E,
            22 => 0x50,
            23 => 0x51,
            24 => 0x52,
            25 => 0x53,
            26 => 0x54,
            27 => 0x56,
            28 => 0x57,
            29 => 0x58,
            30 => 0x59,
            31 => 0x5A,
            _ => unreachable!(),
        };

        out.push(symbol);
    }

    return out;
}

#[test]
fn test_from_legacy() {
    assert!(Multibox::from_legacy(b"lB==.box").is_err());
    assert!(Multibox::from_legacy(b"lA==.box0").is_err());
    assert!(Multibox::from_legacy(b"lA==.box01").is_err());
    assert!(Multibox::from_legacy(b"lA==.boxG0123456789AB").is_err());
    assert!(Multibox::from_legacy(b"lA==.boxF0123456789AB").is_ok());

    match (Multibox::from_legacy(b".box").unwrap().0).0 {
        _Multibox::PrivateBox(data) => assert_eq!(data.len(), 0),
        _ => panic!()
    }

    match (Multibox::from_legacy(b"lA==.box").unwrap().0).0 {
        _Multibox::PrivateBox(..) => {},
        _ => panic!()
    }

    match (Multibox::from_legacy(b"lA==.boxa").unwrap().0).0 {
        _Multibox::PrivateBox(..) => {},
        _ => panic!()
    }

    match (Multibox::from_legacy(b"lA==.boxU").unwrap().0).0 {
        _Multibox::PrivateBox(..) => {},
        _ => panic!()
    }

    match (Multibox::from_legacy(b"lA==.box\"").unwrap().0).0 {
        _Multibox::PrivateBox(..) => {},
        _ => panic!()
    }

    match (Multibox::from_legacy(b"lA==.box1").unwrap().0).0 {
        _Multibox::Other(1, _) => {},
        _ => panic!()
    }

    match (Multibox::from_legacy(b"lA==.boxV").unwrap().0).0 {
        _Multibox::Other(27, _) => {},
        _ => panic!()
    }

    match (Multibox::from_legacy(b"lA==.box11").unwrap().0).0 {
        _Multibox::Other(0b00001_00001, _) => {},
        _ => panic!()
    }

    match (Multibox::from_legacy(b".boxNN").unwrap().0).0 {
        _Multibox::Other(0b10101_10101, _) => {},
        _ => panic!()
    }
}

#[test]
fn test_to_legacy() {
    assert_eq!(Multibox::new_private_box(vec![]).to_legacy_vec(), b".box");
    assert_eq!(Multibox::new_multibox(0b10101_10101, vec![]).to_legacy_vec(), b".boxNN");
}
