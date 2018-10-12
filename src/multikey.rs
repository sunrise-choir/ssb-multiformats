//! Implementation of [ssb multikeys](TODO).

use base64;

use ssb_legacy_msg::{
    StringlyTypedError,
    data::{Serialize, Serializer, Deserialize, Deserializer}
};

// Get the next item from the iterator and make sure it is the last one.
// Returns `None` if there was not exactly one remaining item.
fn iter_last<T: Iterator>(t: &mut T) -> Option<T::Item> {
    let item = t.next()?;

    match t.next() {
        None => Some(item),
        _ => None,
    }
}

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
    pub fn from_legacy(mut s: &[u8]) -> Option<Multikey> {
        match s.split_first()? {
            // Next character is `@`
            (0x40, tail) => s = tail,
            _ => return None,
        }

        let mut iter = s.split(|byte| *byte == 0x2e);

        match base64::decode_config(iter.next()?, base64::STANDARD) {
            Ok(key_raw) => {
                match iter_last(&mut iter)? {
                    // ed25519
                    &[0x65, 0x64, 0x32, 0x35, 0x35, 0x31, 0x39] => {
                        println!("internal: {:x?}", key_raw);
                        if key_raw.len() != 32 {
                            return None;
                        }

                        println!("jhkljhkl: {:?}", base64::encode_config(&key_raw, base64::STANDARD));

                        let mut data = [0u8; 32];
                        data.copy_from_slice(&key_raw[..]);
                        return Some(Multikey(_Multikey::Ed25519(data)));
                    }

                    // Unknown suffix:
                    _ => None,

                    // // Unknown suffix
                    // suffix => {
                    //     match std::str::from_utf8(suffix) {
                    //         Ok(tag_str) => {
                    //             return Some(Multikey(_Multikey::UnknownLegacy {
                    //                                      tag: tag_str.to_string(),
                    //                                      data: key_raw,
                    //                                  }))
                    //         }
                    //         _ => return None,
                    //     }
                    // }
                }
            }

            _ => None,
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
        unimplemented!()
        // let s = String::deserialize(deserializer)?;
        // match Multikey::from_legacy(&s.as_bytes()) {
        //     None => Err(D::Error::custom("invalid multikey")),
        //     Some(k) => Ok(k),
        // }
    }
}


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