#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssb_multiformats;

use ssb_multiformats::multifeed::Multifeed;

fuzz_target!(|data: &[u8]| {
    // This comment keeps rustfmt from breaking the fuzz macro...
    match Multifeed::from_compact(data) {
        Ok((k, tail)) => {
            if tail.len() != 0 {
                let enc = k.to_compact_string();
                assert_eq!(enc.as_bytes(), &data[..data.len() - tail.len()]);
            }
        }
        Err(_) => {}
    }
});
