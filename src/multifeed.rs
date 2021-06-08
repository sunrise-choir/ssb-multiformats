use std::io::{self, Write};

use super::multikey::{self, Multikey};

/// A multifeed that owns its data.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub enum Multifeed {
    Multikey(Multikey),
}

impl Multifeed {
    /// Create a new multifeed of kind `multikey`.
    pub fn from_multikey(mk: Multikey) -> Multifeed {
        Multifeed::Multikey(mk)
    }

    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding)
    /// into a `Multifeed`, also returning the remaining input on success.
    pub fn from_legacy(s: &[u8]) -> Result<(Multifeed, &[u8]), DecodeLegacyError> {
        if s.is_empty() {
            return Err(DecodeLegacyError::UnknownKind);
        }

        match s[0] {
            0x40 => {
                let (mk, tail) = Multikey::from_legacy(s)?;
                Ok((Multifeed::from_multikey(mk), tail))
            }
            _ => Err(DecodeLegacyError::UnknownKind),
        }
    }

    /// Serialize a `Multifeed` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self {
            Multifeed::Multikey(ref mk) => mk.to_legacy(w),
        }
    }

    /// Serialize a `Multifeed` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        match self {
            Multifeed::Multikey(ref mk) => mk.to_legacy_vec(),
        }
    }

    /// Serialize a `Multifeed` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multifeed-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        unsafe { String::from_utf8_unchecked(self.to_legacy_vec()) }
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
