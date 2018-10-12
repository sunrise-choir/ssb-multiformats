#![no_main]
#[macro_use]
extern crate libfuzzer_sys;
extern crate ssb_multiformats;

use ssb_multiformats::multihash::Multihash;

fuzz_target!(|data: &[u8]| {
    // This comment keeps rustfmt from breaking the fuzz macro...
    match Multihash::from_legacy(data) {
        Ok(k) => {
            let enc = k.to_legacy();
            assert_eq!(enc.as_bytes(), data);
        }
        Err(_) => {}
    }
});
