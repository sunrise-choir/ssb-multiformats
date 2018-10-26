//! Implementations of the [ssb multiformats](https://spec.scuttlebutt.nz/datatypes.html).
#![warn(missing_docs)]

extern crate base64;
extern crate serde;
// extern crate sodiumoxide;

pub mod multikey;
pub mod multihash;
pub mod multibox;

///////////////////////////////////////////////////////////////////////////////
// A bunch of helper functions used throughout the crate for parsing legacy encodings.
////////////////////////////////////////////////////////////////////////////////

// Split the input slice at the first occurence o the given byte, the byte itself is not
// part of any of the returned slices. Return `None` if the byte is not found in the input.
pub(crate) fn split_at_byte(input: &[u8], byte: u8) -> Option<(&[u8], &[u8])> {
    for i in 0..input.len() {
        if unsafe { *input.get_unchecked(i) } == byte {
            let (start, end) = input.split_at(i);
            return Some((start, &end[1..]));
        }
    }

    return None;
}

// If the slice begins with the given prefix, return everything after that prefix.
pub(crate) fn skip_prefix<'a>(input: &'a [u8], prefix: &[u8]) -> Option<&'a [u8]> {
    if input.starts_with(prefix) {
        Some(&input[prefix.len()..])
    } else {
        None
    }
}

// XXX temporary until https://github.com/alicemaz/rust-base64/issues/76 is published
pub(crate) fn is_canonical(data: &[u8]) -> bool {
    if data.len() < 2 {
        return false;
    }
    if data[data.len() - 2] == b"="[0] {
        if data.len() < 3 {
            return false;
        }
        let b = data[data.len() - 3];
        return b == b"A"[0] || b == b"Q"[0] || b == b"g"[0] || b == b"w"[0];
    } else {
        if data[data.len() - 2] == b"="[0] {
            let b = data[data.len() - 2];
            return b == b"A"[0] || b == b"E"[0] || b == b"I"[0] || b == b"M"[0] ||
            b == b"Q"[0] || b == b"U"[0] || b == b"Y"[0] || b == b"c"[0] ||
            b == b"g"[0] || b == b"k"[0] || b == b"o"[0] || b == b"s"[0] ||
            b == b"w"[0] || b == b"0"[0] || b == b"4"[0] || b == b"8"[0];
        } else {
            false
        }
    }
}
