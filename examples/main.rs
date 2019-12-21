extern crate ssb_multiformats;

use std::fs::{self, File};
use std::io::{self, prelude::*};
use std::path::{Path, PathBuf};

use ssb_multiformats::{multibox::Multibox, multihash::Multihash, multikey::Multikey};

fn main() {
    handle_nays_key(Path::new("../multiformats-testdata/multikey/nay")).unwrap();
    handle_yays_key(Path::new("../multiformats-testdata/multikey/yay")).unwrap();
    handle_nays_hash(Path::new("../multiformats-testdata/multihash/nay")).unwrap();
    handle_yays_hash(Path::new("../multiformats-testdata/multihash/yay")).unwrap();

    let paths = fs::read_dir("./fuzz/corpus/roundtrip_box").unwrap();

    for dir_path in paths {
        let path = dir_path.unwrap().path();
        let mut file = File::open(path.clone()).unwrap();
        let mut contents = Vec::new();
        file.read_to_end(&mut contents).unwrap();

        match Multibox::from_legacy(&contents) {
            Ok(_) => {
                let (actual, _tail) = split_at_byte(&contents, 0x22).unwrap();

                let mut p = PathBuf::from("../multiformats-testdata/multibox/yay");
                p.push(path.file_name().unwrap());

                let mut file = File::create(&p).unwrap();
                file.write_all(actual).unwrap();
            }

            Err(_) => {
                let mut p = PathBuf::from("../multiformats-testdata/multibox/nay");
                p.push(path.file_name().unwrap());

                let mut file = File::create(&p).unwrap();
                file.write_all(&contents).unwrap();
            }
        }
    }
}

fn handle_nays_key(path: &Path) -> Result<(), io::Error> {
    let paths = fs::read_dir(path)?;

    let mut i = 0;

    for dir_path in paths {
        let path = dir_path.unwrap().path();
        let mut file = File::open(path.clone())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        match Multikey::from_legacy(&contents) {
            Ok(e) => {
                if e.1.len() == 0 {
                    println!("{:?}", path);
                    println!("{:?}", &contents);
                    println!("{:?}", std::str::from_utf8(&contents));
                    println!("{:?}", e);
                    panic!()
                }
            }

            Err(_) => {}
        }

        i += 1;
    }

    println!("handled {} files at {:?}", i, path);
    Ok(())
}

fn handle_yays_key(path: &Path) -> Result<(), io::Error> {
    let paths = fs::read_dir(path)?;

    let mut i = 0;

    for dir_path in paths {
        let path = dir_path.unwrap().path();
        let mut file = File::open(path.clone())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        match Multikey::from_legacy(&contents) {
            Ok(_) => {}

            Err(e) => {
                println!("{:?}", path);
                println!("{:?}", &contents);
                println!("{:?}", std::str::from_utf8(&contents));
                println!("{:?}", e);
                panic!()
            }
        }

        i += 1;
    }

    println!("handled {} files at {:?}", i, path);
    Ok(())
}

fn handle_nays_hash(path: &Path) -> Result<(), io::Error> {
    let paths = fs::read_dir(path)?;

    let mut i = 0;

    for dir_path in paths {
        let path = dir_path.unwrap().path();
        let mut file = File::open(path.clone())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        match Multihash::from_legacy(&contents) {
            Ok(e) => {
                if e.1.len() == 0 {
                    println!("{:?}", path);
                    println!("{:?}", &contents);
                    println!("{:?}", std::str::from_utf8(&contents));
                    println!("{:?}", e);
                    panic!()
                }
            }

            Err(_) => {}
        }

        i += 1;
    }

    println!("handled {} files at {:?}", i, path);
    Ok(())
}

fn handle_yays_hash(path: &Path) -> Result<(), io::Error> {
    let paths = fs::read_dir(path)?;

    let mut i = 0;

    for dir_path in paths {
        let path = dir_path.unwrap().path();
        let mut file = File::open(path.clone())?;
        let mut contents = Vec::new();
        file.read_to_end(&mut contents)?;

        match Multihash::from_legacy(&contents) {
            Ok(_) => {}

            Err(e) => {
                println!("{:?}", path);
                println!("{:?}", &contents);
                println!("{:?}", std::str::from_utf8(&contents));
                println!("{:?}", e);
                panic!()
            }
        }

        i += 1;
    }

    println!("handled {} files at {:?}", i, path);
    Ok(())
}

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
