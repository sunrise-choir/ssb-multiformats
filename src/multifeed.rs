use std::io::{self, Write};

use super::multikey::{self, Multikey};

/// A multifeed that owns its data.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub struct Multifeed(_Multifeed);

#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
enum _Multifeed {
    Multikey(Multikey),
}

impl Multifeed {
    /// Create a new multifeed of kind `multikey`.
    pub fn from_multikey(mk: Multikey) -> Multifeed {
        Multifeed(_Multifeed::Multikey(mk))
    }

    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding)
    /// into a `Multifeed`, also returning the remaining input on success.
    pub fn from_legacy(s: &[u8]) -> Result<(Multifeed, &[u8]), DecodeLegacyError> {
        if s.len() == 0 {
            return Err(DecodeLegacyError::UnknownKind);
        }

        match s[0] {
            0x40 => {
                let (mk, tail) = Multikey::from_legacy(s)?;
                return Ok((Multifeed::from_multikey(mk), tail));
            }
            _ => return Err(DecodeLegacyError::UnknownKind),
        }
    }

    /// Parses a
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-compact-encoding)
    /// into a `Multifeed`, also returning the remaining input on success.
    pub fn from_compact(s: &[u8]) -> Result<(Multifeed, &[u8]), DecodeCompactError> {
        match varu64::decode(s) {
            Err((err, _)) => return Err(DecodeCompactError::Kind(err)),
            Ok((0, tail)) => {
                let (mk, tail) = Multikey::from_compact(tail)?;
                return Ok((Multifeed::from_multikey(mk), tail));
            }
            _ => return Err(DecodeCompactError::UnknownKind),
        }
    }

    /// Serialize a `Multifeed` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self.0 {
            _Multifeed::Multikey(ref mk) => mk.to_legacy(w),
        }
    }

    /// Serialize a `Multifeed` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        match self.0 {
            _Multifeed::Multikey(ref mk) => mk.to_legacy_vec(),
        }
    }

    /// Serialize a `Multifeed` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
    }

    /// Serialize a `Multifeed` into a writer, using the
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-compact-encoding).
    pub fn to_compact<W: Write>(&self, mut w: W) -> Result<usize, io::Error> {
        match self.0 {
            _Multifeed::Multikey(ref mk) => {
                let kind_len = varu64::encode_write(0, &mut w)?;
                Ok(kind_len + mk.to_compact(&mut w)?)
            }
        }
    }

    /// Serialize a `Multifeed` into an owned byte vector, using the
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-compact-encoding).
    pub fn to_compact_vec(&self) -> Vec<u8> {
        match self.0 {
            _Multifeed::Multikey(ref mk) => {
                let kind_len = varu64::encoding_length(0);
                let mk_len = mk.encoding_length();

                let out_len = kind_len + mk_len;
                let mut ret = Vec::with_capacity(out_len);
                ret.resize(out_len, 0);

                varu64::encode(0, &mut ret[..]);
                mk.to_compact(&mut ret[kind_len as usize..]).unwrap();
                return ret;
            }
        }
    }

    /// Serialize a `Multifeed` into an owned string, using the
    /// [compact encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-compact-encoding).
    pub fn to_compact_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_compact_vec()) }
    }
}

/// Everything that can go wrong when decoding a `Multikey` from the legacy encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeLegacyError {
    /// Input did not start with the `"@"` sigil.
    UnknownKind,
    /// Decoding the inner multikey failed.
    Multikey(multikey::DecodeLegacyError),
}

impl From<multikey::DecodeLegacyError> for DecodeLegacyError {
    fn from(err: multikey::DecodeLegacyError) -> DecodeLegacyError {
        DecodeLegacyError::Multikey(err)
    }
}

/// Everything that can go wrong when decoding a `Multikey` from the compact encoding.
#[derive(Debug, PartialEq, Eq, Clone)]
pub enum DecodeCompactError {
    /// The kind varu64 was invalid.
    Kind(varu64::DecodeError),
    /// The kind of the multifeed is not known to this ssb implementation.
    UnknownKind,
    /// Decoding the inner multikey failed.
    Multikey(multikey::DecodeCompactError),
}

impl From<multikey::DecodeCompactError> for DecodeCompactError {
    fn from(err: multikey::DecodeCompactError) -> DecodeCompactError {
        DecodeCompactError::Multikey(err)
    }
}
