//! Implementations of the [ssb multiformats](https://spec.scuttlebutt.nz/datatypes.html).
#![warn(missing_docs)]

extern crate base64;
extern crate serde;
extern crate ring;
extern crate untrusted;

#[cfg(test)]
#[macro_use] extern crate matches;

pub mod multikey;
pub mod multihash;
pub mod multibox;
pub mod multifeed;

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
