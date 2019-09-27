///
///
///

use std::{
    fs::File,
    io::prelude::*,
    path::Path,
};

pub fn read_from_file(name: &str) -> Vec<u8> {
    let mut result: Vec<u8> = Vec::new();

    let path = Path::new(name);
    let file = File::open(&path);

    if let Ok(mut f) = file {
        f.read_to_end(&mut result).unwrap_or_else(|_| {
            result.clear();
            0
        });
    }
    result
}
