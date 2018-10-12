#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssb_multiformats;

use ssb_multiformats::multikey::Multikey;

fuzz_target!(|data: &[u8]| {
    // This comment keeps rustfmt from breaking the fuzz macro...
    match Multikey::from_legacy(data) {
        Some(k) => {
            let enc = k.to_legacy();
            assert_eq!(enc.as_bytes(), data);
        }
        None => {}
    }
});
