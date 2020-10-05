//! Implementation of [ssb multikeys](https://spec.scuttlebutt.nz/datatypes.html#multikey).
use std::cmp::{Eq, Ord, Ordering, PartialEq, PartialOrd};
use std::fmt;
use std::io::{self, Cursor, Write};

use base64;
use serde::{
    de::{Deserialize, Deserializer, Error},
    ser::{Serialize, Serializer},
};
use ssb_crypto::{verify_detached, PublicKey, SecretKey, Signature, SECRETKEYBYTES};

use super::*;

/// A multikey that owns its data.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord, Hash)]
pub enum Multikey {
    // An [ed25519](http://ed25519.cr.yp.to/) public key.
    Ed25519(PublicKey),
}

impl Multikey {
    /// Take an ed25519 public key and turn it into an opaque `Multikey`.
    pub fn from_ed25519(pk: &[u8; 32]) -> Multikey {
        Multikey::Ed25519(PublicKey::from_slice(pk).unwrap())
    }

    pub fn from_ed25519_slice(pk: &[u8]) -> Multikey {
        Multikey::Ed25519(PublicKey::from_slice(pk).unwrap())
    }

    pub fn into_ed25519_public_key(self) -> Option<PublicKey>{
        match self {
            Multikey::Ed25519(pk) => Some(pk),
        }
    }

    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding)
    /// into a `Multikey`, also returning the remaining input on success.
    pub fn from_legacy(mut s: &[u8]) -> Result<(Multikey, &[u8]), DecodeLegacyError> {
        s = skip_prefix(s, b"@").ok_or_else(|| DecodeLegacyError::Sigil)?;

        let (data, suffix) = split_at_byte(s, 0x2E).ok_or_else(|| DecodeLegacyError::NoDot)?;

        let tail =
            skip_prefix(suffix, ED25519_SUFFIX).ok_or_else(|| DecodeLegacyError::UnknownSuffix)?;

        if data.len() != ED25519_PK_BASE64_LEN {
            return Err(DecodeLegacyError::Ed25519WrongSize);
        }

        if data[ED25519_PK_BASE64_LEN - 2] == b"="[0] {
            return Err(DecodeLegacyError::Ed25519WrongSize);
        }

        if data[ED25519_PK_BASE64_LEN - 1] != b"="[0] {
            return Err(DecodeLegacyError::Ed25519WrongSize);
        }

        let mut dec_data = [0u8; 32];

        base64::decode_config_slice(data, base64::STANDARD, &mut dec_data)
            .map_err(|e| DecodeLegacyError::InvalidBase64(e))
            .map(|_| (Multikey::from_ed25519(&dec_data), tail))
    }

    /// Serialize a `Multikey` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self {
            Multikey::Ed25519(ref pk) => {
                w.write_all(b"@")?;

                let data = base64::encode_config(&pk[..], base64::STANDARD);
                w.write_all(data.as_bytes())?;

                w.write_all(b".")?;
                w.write_all(ED25519_SUFFIX)
            }
        }
    }

    /// Serialize a `Multikey` into an owned byte vector, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        match self {
            Multikey::Ed25519(_) => {
                let mut out = Vec::with_capacity(SSB_ED25519_ENCODED_LEN);
                self.to_legacy(&mut out).unwrap();
                out
            }
        }
    }

    /// Serialize a `Multikey` into an owned string, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding).
    pub fn to_legacy_string(&self) -> String {
        String::from_utf8(self.to_legacy_vec()).unwrap()
    }

    /// Check whether the given signature of the given text was created by this key.
    pub fn is_signature_correct(&self, data: &[u8], sig: &Multisig) -> bool {
        match (&self, &sig.0) {
            (Multikey::Ed25519(ref pk), _Multisig::Ed25519(ref sig)) => {
                verify_detached(sig, data, pk)
            }
        }
    }
}

impl Serialize for Multikey {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&self.to_legacy_string())
    }
}

impl<'de> Deserialize<'de> for Multikey {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
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
            &DecodeLegacyError::UnknownSuffix => write!(f, "Unknown suffix"),
            &DecodeLegacyError::Ed25519WrongSize => write!(f, "Data of wrong length"),
        }
    }
}

impl std::error::Error for DecodeLegacyError {}

/// The secret counterpart to Multikey
#[derive(Debug, PartialEq, Eq, Clone)]
pub struct Multisecret(SecretKey);

impl Multisecret {
    /// Parses a
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding)
    /// into a `Multisecret`, also returning the remaining input on success.
    pub fn from_legacy(s: &[u8]) -> Result<(Multisecret, &[u8]), DecodeLegacyError> {
        let (data, suffix) = split_at_byte(s, 0x2E).ok_or_else(|| DecodeLegacyError::NoDot)?;

        let tail =
            skip_prefix(suffix, ED25519_SUFFIX).ok_or_else(|| DecodeLegacyError::UnknownSuffix)?;

        if data.len() != SECRETKEYBYTES {
            return Err(DecodeLegacyError::Ed25519WrongSize);
        }

        if data[SECRETKEYBYTES - 2] == b"="[0] {
            return Err(DecodeLegacyError::Ed25519WrongSize);
        }

        if data[SECRETKEYBYTES - 1] != b"="[0] {
            return Err(DecodeLegacyError::Ed25519WrongSize);
        }

        let mut dec_data = [0u8; 32];

        base64::decode_config_slice(data, base64::STANDARD, &mut dec_data)
            .map_err(|e| DecodeLegacyError::InvalidBase64(e))
            .map(|_| (Multisecret(SecretKey::from_slice(&dec_data).unwrap()), tail))
    }

    /// Serialize a `Multisecret` into a writer, using the
    /// [legacy encoding](https://spec.scuttlebutt.nz/datatypes.html#multikey-legacy-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        let data = base64::encode_config(&self.0[..], base64::STANDARD);
        w.write_all(data.as_bytes())?;
        w.write_all(b".")?;
        w.write_all(ED25519_SUFFIX)
    }
}

impl Serialize for Multisecret {
    fn serialize<S>(&self, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut s = [0u8; SSB_ED25519_SECRET_ENCODED_LEN];
        self.to_legacy(&mut Cursor::new(&mut s[..])).unwrap();
        serializer.serialize_str(std::str::from_utf8(&s).unwrap())
    }
}

impl<'de> Deserialize<'de> for Multisecret {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        let s = String::deserialize(deserializer)?;
        Multisecret::from_legacy(&s.as_bytes())
            .map(|(mk, _)| mk)
            .map_err(|err| D::Error::custom(format!("Invalid multikey: {}", err)))
    }
}

/// A signature that owns its data.
#[derive(Debug, PartialEq, Eq, Clone, PartialOrd, Ord)]
pub struct Multisig(_Multisig);

#[derive(Clone)]
enum _Multisig {
    // An [ed25519](http://ed25519.cr.yp.to/) signature.
    Ed25519(Signature),
}

impl fmt::Debug for _Multisig {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            _Multisig::Ed25519(ref data) => write!(f, "Ed25519 signature: {:?}", &data[..]),
        }
    }
}

impl PartialEq for _Multisig {
    fn eq(&self, other: &_Multisig) -> bool {
        match (self, other) {
            (_Multisig::Ed25519(ref a), _Multisig::Ed25519(ref b)) => &a[..] == &b[..],
        }
    }
}

impl Eq for _Multisig {}

impl PartialOrd for _Multisig {
    fn partial_cmp(&self, other: &_Multisig) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for _Multisig {
    fn cmp(&self, other: &_Multisig) -> Ordering {
        match (self, other) {
            (_Multisig::Ed25519(ref a), _Multisig::Ed25519(ref b)) => a.cmp(&b),
        }
    }
}

impl Multikey {
    /// Deserialize a legacy signature corrsponding to this key type.
    pub fn sig_from_legacy<'a>(
        &self,
        s: &'a [u8],
    ) -> Result<(Multisig, &'a [u8]), DecodeSignatureError> {
        let (data, suffix) = split_at_byte(s, 0x2E).ok_or_else(|| DecodeSignatureError::NoDot)?;

        let suffix = skip_prefix(suffix, b"sig").ok_or_else(|| DecodeSignatureError::NoDotSig)?;

        match self {
            Multikey::Ed25519(_) => {
                let tail = skip_prefix(suffix, b".ed25519")
                    .ok_or_else(|| DecodeSignatureError::UnknownSuffix)?;

                if data.len() != ED25519_SIG_BASE64_LEN {
                    return Err(DecodeSignatureError::Ed25519WrongSize);
                }

                if data[ED25519_SIG_BASE64_LEN - 2] != b"="[0] {
                    return Err(DecodeSignatureError::Ed25519WrongSize);
                }

                let mut dec_data = [0u8; 64];

                base64::decode_config_slice(data, base64::STANDARD, &mut dec_data[..])
                    .map_err(|e| DecodeSignatureError::InvalidBase64(e))
                    .map(|_| (Multisig::from_ed25519(&dec_data), tail))
            }
        }
    }
}

impl Multisig {
    /// Take an ed25519 signature and turn it into an opaque `Multisig`.
    pub fn from_ed25519(sig: &[u8; 64]) -> Multisig {
        Multisig(_Multisig::Ed25519(Signature::from_slice(sig).unwrap()))
    }

    /// Serialize a signature into a writer, in the appropriate
    /// form for a [legacy message](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
    pub fn to_legacy<W: Write>(&self, w: &mut W) -> Result<(), io::Error> {
        match self.0 {
            _Multisig::Ed25519(ref sig) => {
                let data = base64::encode_config(&sig[..], base64::STANDARD);
                w.write_all(data.as_bytes())?;
                w.write_all(b".sig.ed25519")
            }
        }
    }

    /// Serialize a signature into an owned byte vector,
    /// in the appropriate form for a
    /// [legacy message](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
    pub fn to_legacy_vec(&self) -> Vec<u8> {
        match self.0 {
            _Multisig::Ed25519(_) => {
                let mut out = Vec::with_capacity(ED25519_SIG_BASE64_LEN);
                self.to_legacy(&mut out).unwrap();
                out
            }
        }
    }

    /// Serialize a signature into an owned string,
    /// in the appropriate form for a
    /// [legacy message](https://spec.scuttlebutt.nz/messages.html#legacy-json-encoding).
    pub fn to_legacy_string(&self) -> String {
        String::from_utf8(self.to_legacy_vec()).unwrap()
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
            &DecodeSignatureError::UnknownSuffix => write!(f, "Unknown suffix"),
            &DecodeSignatureError::Ed25519WrongSize => write!(f, "Data of wrong length"),
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
/// Length of a legacy-encoded ssb ed25519 secret key.
const SSB_ED25519_SECRET_ENCODED_LEN: usize = 96;

#[test]
fn test_from_legacy() {
    assert!(
        Multikey::from_legacy(b"@zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519").is_ok()
    );
    assert!(
        Multikey::from_legacy(b"@zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hB=.ed25519").is_err()
    );
    assert!(
        Multikey::from_legacy(b"&zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.ed25519").is_err()
    );
    assert!(
        Multikey::from_legacy(b"@zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=.dd25519").is_err()
    );
    assert!(
        Multikey::from_legacy(b"@zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA=ed25519").is_err()
    );
    assert!(
        Multikey::from_legacy(b"@zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA.ed25519").is_err()
    );
    assert!(
        Multikey::from_legacy(b"@zurF8X68ArfRM71dF3mKh36W0xDM8QmOnAS5bYOq8hA==.ed25519").is_err()
    );
}
